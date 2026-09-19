package macho

// High level access to low level data structures.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"

	"github.com/ianlancetaylor/demangle"
	"github.com/zdypro888/go-dwarf"

	"github.com/zdypro888/go-macho/internal/saferio"
	"github.com/zdypro888/go-macho/pkg/codesign"
	"github.com/zdypro888/go-macho/pkg/fixupchains"
	"github.com/zdypro888/go-macho/pkg/trie"
	"github.com/zdypro888/go-macho/pkg/xar"
	"github.com/zdypro888/go-macho/types"
)

// A File represents an open Mach-O file.
//
// The read-only parsing methods (GetObjCClasses, GetSwiftTypes,
// GetSwiftProtocolConformances, DyldExports, GetDyldInfo, GetBindInfo,
// GetCStrings, GetFunctions, ...) are safe to call concurrently on one File.
// Every public call that has to read sequentially does so through its own
// cursor (see newReader), and the lazily built caches (ObjC and Swift
// objects, fixups, binds and rebases, export tries, function starts, symbol
// and bind lookup indexes, the Swift context memo) are each guarded by a
// lock. This holds for
// a File opened with Open or NewFile over an io.ReaderAt, and for a
// FileConfig.SectionReader/CacheReader that implements types.ReaderCloner;
// with a reader that cannot be cloned, the parsers fall back to sharing that
// reader and its position, and the File is then only safe for one goroutine
// at a time.
//
// Methods that modify the File are not safe to run concurrently with anything
// else on the same File: Export, CodeSign and SaveBuffer (which rewrite Loads,
// Symtab and the LINKEDIT data), AddLoad and RemoveLoad (Loads), LoadExt,
// SetSharedCacheBaseAddress and the kernel-cache base setters,
// ResetFixupsCache, SetSwiftAutoDemangle, and direct assignments to exported
// fields such as Symtab, Loads or Sections. Call them before handing the File
// to other goroutines, or serialise them with every reader.
//
// Symtab (and Symtab.Syms) may be replaced at any time. Do not edit the
// elements of Symtab.Syms in place after the first symbol lookup: the lookup
// indexes behind FindSymbolAddress and FindAddressSymbols are tied to the
// slice, not to its contents. ResetFixupsCache drops those indexes too.
type File struct {
	FileTOC

	Symtab   *Symtab
	Dysymtab *Dysymtab

	vma                   *types.VMAddrConverter
	customVMAddrConverter bool
	dcf                   *fixupchains.DyldChainedFixups

	// expMu guards exp and exptrieData, the lazily parsed LC_DYLD_EXPORTS_TRIE.
	// Both are immutable once published. Leaf lock.
	expMu       sync.Mutex
	exp         []trie.TrieExport
	exptrieData []byte

	binds       types.Binds
	bindsDone   bool
	rebases     []types.Rebase
	rebasesDone bool

	threadedRebases []types.Rebase

	// fixupsMu protects every lazily-published fixup cache. Cached slices, maps,
	// and chained-fixup objects are immutable after publication; reset replaces
	// them instead of mutating them so callers may safely keep returned values.
	fixupsMu              sync.Mutex
	dyldInfoCacheBuilt    bool
	dyldInfoRebaseTargets map[uint64]uint64
	dyldInfoRebaseValues  map[uint64]struct{}
	dyldInfoBindsByAddr   map[uint64]types.Bind
	bindNameIdx           bindNameIndex // GetBindName's index over binds; guarded by fixupsMu
	lazyLoadMu            sync.Mutex

	// symIndexMu guards symIdx, the lookup indexes of FindSymbolAddress and
	// FindAddressSymbols (see symindex.go). It is a leaf lock.
	symIndexMu sync.Mutex
	symIdx     symbolIndexes

	// functionsMu guards FileTOC.functions, the list GetFunctions and
	// GenerateFunctionStarts cache. Leaf lock.
	functionsMu sync.Mutex

	// swiftCtxMu guards swiftCtx, getContextDesc's per-call memo. Leaf lock.
	swiftCtxMu sync.Mutex
	swiftCtx   swiftContextMemo

	objc map[uint64]any // guarded by mu (PutObjC/GetObjC)

	// swiftMu guards swift, the cache of parsed Swift types and field
	// descriptors keyed by address (see putSwift/getSwift). Leaf lock.
	swiftMu sync.Mutex
	swift   map[uint64]any

	ledata *bytes.Buffer // tmp storage of linkedit data; written by Export/CodeSign only

	objcRuntimeOnce          sync.Once
	objcHasNonFragileRuntime bool
	objcHasFragileRuntime    bool
	objcCacheValueAddOnce    sync.Once
	objcCacheValueAdd        uint64
	objcCacheValueAddKnown   bool
	pointerResolver          PointerResolver

	sharedCacheRelativeSelectorBaseVMAddress uint64 // objc_opt version 16
	objcSelectorBaseUnavailable              bool   // relative method selectors needed the shared cache's selector base
	sharedCacheBase                          uint64 // unslid base for chained pointer formats 13, 15, and 16
	sharedCacheBaseSet                       bool
	kernelCacheBases                         [4]uint64 // runtime basePointers entries for chained pointer formats 8 and 11
	kernelCacheBaseSet                       [4]bool
	kernelCacheLevelZeroSegment              uint64 // inherited lowest unslid LC_SEGMENT for a fileset KC
	kernelCacheLevelZeroSegmentSet           bool
	swiftAutoDemangle                        bool

	mu sync.Mutex
	// sr reads the Mach-O by file offset, cr by file offset or virtual
	// address (the cache reader of a dyld shared cache image). Both are
	// shared by every goroutine, so File methods only use their position-free
	// ReadAt/ReadAtAddr; anything that seeks goes through a per-call cursor
	// from newReader.
	sr     types.MachoReader
	cr     types.MachoReader
	closer io.Closer

	// iunios 扩展字段 - 用于运行时加载
	Entitlements   string           // 代码签名权限
	Entry          uint64           // LC_MAIN 入口点
	ThreadEntry    uint64           // LC_UNIXTHREAD 入口点
	DynamicExports []*DynamicExport // 动态导出符号
	Slide          uint64           // ASLR 滑动偏移 (TEXT 段基址)
	VMSize         uint64           // 虚拟内存总大小
	RelocationBase uint64           // 重定位基址
}

// DynamicExport 动态导出符号
type DynamicExport struct {
	Name   string
	VMAddr uint64
}

/*
 * Mach-O reader
 */

var ErrMachOArchNotSupported = errors.New("MachO arch not supported")
var ErrMachOSectionNotFound = errors.New("MachO missing required section")
var ErrMachODyldInfoNotFound = errors.New("LC_DYLD_INFO(_ONLY) not found")
var ErrMachONoBindInfo = errors.New("MachO does not contain bind information (fixups)")

var ErrCStringNoTerminator = errors.New("cstring has no terminator")
var ErrCStringNotFound = errors.New("cstring not found")

// cstringBufPool reuses 4 KiB read buffers in GetCString to avoid hammering
// the allocator's mcentral lock when many goroutines read C strings concurrently.
var cstringBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0x1000)
		return &b
	},
}

// FormatError is returned by some operations if the data does
// not have the correct format for an object file.
type FormatError struct {
	off int64
	msg string
	val any
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" in record at byte %#x", e.off)
	return msg
}

func loadInSlice(c types.LoadCmd, list []types.LoadCmd) bool {
	for _, b := range list {
		if b == c {
			return true
		}
	}
	return false
}

// PointerResolver resolves an on-disk pointer using the virtual address of the
// pointer slot. Shared-cache slide-info decoders need both values because the
// cache mapping/page containing the slot determines how rawPointer is encoded.
// resolved=false delegates to the Mach-O file's ordinary fixup/conversion path.
type PointerResolver func(slotVMAddr, rawPointer uint64) (target uint64, resolved bool, err error)

// FileConfig is a MachO file config object.
//
// SectionReader (file-offset reads) and CacheReader (virtual-address reads)
// should implement types.ReaderCloner: the File then gives every public
// parsing call a cursor of its own and is safe for concurrent use. A reader
// without Clone is shared, position included, and the File must then be used
// by one goroutine at a time.
type FileConfig struct {
	Offset               int64
	LoadIncluding        []types.LoadCmd
	LoadExcluding        []types.LoadCmd
	VMAddrConverter      types.VMAddrConverter
	SectionReader        types.MachoReader
	CacheReader          types.MachoReader
	PointerResolver      PointerResolver
	RelativeSelectorBase uint64
	SharedCacheBase      uint64 // unslid first mapping address; zero leaves shared-cache chained formats disabled
}

// Open opens the named file using os.Open and prepares it for use as a Mach-O binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

// cloneReader returns a private cursor over r's data when r implements
// types.ReaderCloner, and r itself otherwise.
func cloneReader(r types.MachoReader) types.MachoReader {
	if c, ok := r.(types.ReaderCloner); ok {
		return c.Clone()
	}
	return r
}

// newReader returns the cursor a public parsing call reads sequentially
// through: a clone of the cache reader (types.CustomSectionReader for a File
// opened over an io.ReaderAt, or whatever FileConfig.CacheReader/SectionReader
// supplied) that shares the underlying data and address conversion but has a
// position of its own. It is passed explicitly to every helper of that call,
// so concurrent calls never move each other's position.
//
// When the configured reader does not implement types.ReaderCloner the shared
// reader is returned instead, and the File is not safe for concurrent use.
func (f *File) newReader() types.MachoReader {
	return cloneReader(f.cr)
}

// NewFile creates a new File for accessing a Mach-O binary in an underlying reader.
// The Mach-O binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt, config ...FileConfig) (*File, error) {
	var loadIncluding []types.LoadCmd
	var loadExcluding []types.LoadCmd

	f := new(File)

	f.objc = make(map[uint64]any)
	f.swift = make(map[uint64]any)
	f.swiftAutoDemangle = true

	f.vma = &types.VMAddrConverter{
		Converter:    f.convertToVMAddr,
		VMAddr2Offet: f.getOffset,
		Offet2VMAddr: f.getVMAddress,
	}
	f.sr = types.NewCustomSectionReader(r, f.vma, 0, 1<<63-1)
	f.cr = f.sr
	var headerOffset int64

	if config != nil {
		if config[0].SectionReader != nil {
			f.sr = config[0].SectionReader
			headerOffset = config[0].Offset
			f.cr = f.sr
		}
		if config[0].CacheReader != nil {
			f.cr = config[0].CacheReader
		}
		if config[0].VMAddrConverter.Converter != nil {
			f.vma = &config[0].VMAddrConverter
			f.customVMAddrConverter = true
		}
		loadIncluding = config[0].LoadIncluding
		loadExcluding = config[0].LoadExcluding
		f.pointerResolver = config[0].PointerResolver
		f.sharedCacheRelativeSelectorBaseVMAddress = config[0].RelativeSelectorBase
		if config[0].SharedCacheBase != 0 {
			f.sharedCacheBase = config[0].SharedCacheBase
			f.sharedCacheBaseSet = true
		}
	}

	// Read and decode Mach magic to determine byte order, size.
	// Magic32 and Magic64 differ only in the bottom bit.
	var ident [4]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, fmt.Errorf("failed to parse magic: %v", err)
	}
	be := binary.BigEndian.Uint32(ident[0:])
	le := binary.LittleEndian.Uint32(ident[0:])
	switch types.Magic32.Int() &^ 1 {
	case be &^ 1:
		f.ByteOrder = binary.BigEndian
		f.Magic = types.Magic(be)
	case le &^ 1:
		f.ByteOrder = binary.LittleEndian
		f.Magic = types.Magic(le)
	default:
		return nil, &FormatError{0, "invalid magic number", nil}
	}

	// Read entire file header. A caller-supplied SectionReader may be shared
	// with other Files (GetFileSetFileByName hands the parent's reader to every
	// child), so read through a private cursor when the reader offers one.
	hr := cloneReader(f.sr)
	hr.Seek(headerOffset, io.SeekStart)
	if err := binary.Read(hr, f.ByteOrder, &f.FileHeader); err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	// Then load commands.
	offset := int64(types.FileHeaderSize32)
	if f.Magic == types.Magic64 {
		offset = types.FileHeaderSize64
	}
	dat, err := saferio.ReadDataAt(r, uint64(f.SizeCommands), offset)
	if err != nil {
		return nil, err
	}
	c := saferio.SliceCap[Load](uint64(f.NCommands))
	if c < 0 {
		return nil, &FormatError{offset, "too many load commands", nil}
	}
	f.Loads = make([]Load, 0, c)
	bo := f.ByteOrder
	for i := uint32(0); i < f.NCommands; i++ {
		// Each load command begins with uint32 command and length.
		if len(dat) < 8 {
			return nil, &FormatError{offset, "command block too small", nil}
		}
		cmd, siz := types.LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		if siz < 8 || siz > uint32(len(dat)) {
			return nil, &FormatError{offset, "invalid command block size", nil}
		}

		var cmddat []byte
		cmddat, dat = dat[0:siz], dat[siz:]
		offset += int64(siz)
		var s *Segment

		// skip unwanted load commands
		if len(loadIncluding) > 0 && !loadInSlice(cmd, loadIncluding) {
			continue
		} else if loadInSlice(cmd, loadExcluding) {
			continue
		}

		switch cmd {
		default:
			log.Printf("found NEW load command: %s (please let the author know via https://github.com/zdypro888/go-macho/issues)", cmd)
			f.Loads = append(f.Loads, LoadCmdBytes{types.LoadCmd(cmd), LoadBytes(cmddat)})
		case types.LC_SEGMENT:
			var seg32 types.Segment32
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg32); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEGMENT: %v", err)
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg32.Name[0:])
			s.Addr = uint64(seg32.Addr)
			s.Memsz = uint64(seg32.Memsz)
			s.Offset = uint64(seg32.Offset)
			s.Filesz = uint64(seg32.Filesz)
			s.Maxprot = seg32.Maxprot
			s.Prot = seg32.Prot
			s.Nsect = seg32.Nsect
			s.Flag = seg32.Flag
			s.Firstsect = uint32(len(f.Sections))
			for i := 0; i < int(s.Nsect); i++ {
				var sh32 types.Section32
				if err := binary.Read(b, bo, &sh32); err != nil {
					return nil, fmt.Errorf("failed to read Section32: %v", err)
				}
				sh := new(types.Section)
				sh.Type = 32
				sh.Name = cstring(sh32.Name[0:])
				sh.Seg = cstring(sh32.Seg[0:])
				sh.Addr = uint64(sh32.Addr)
				sh.Size = uint64(sh32.Size)
				sh.Offset = sh32.Offset
				sh.Align = sh32.Align
				sh.Reloff = sh32.Reloff
				sh.Nreloc = sh32.Nreloc
				sh.Flags = sh32.Flags
				sh.Reserved1 = sh32.Reserve1
				sh.Reserved2 = sh32.Reserve2
				sectionReader, err := newSectionReader(f.cr, sh)
				if err != nil {
					return nil, fmt.Errorf("failed to create Section32 reader: %v", err)
				}
				sh.SetReaders(sectionReader, sectionReader)
				if err := f.pushSection(sh, f.cr); err != nil {
					return nil, fmt.Errorf("failed to pushSection32: %v", err)
				}
				s.Sections = append(s.Sections, sh)
			}
			f.Loads = append(f.Loads, s)
		case types.LC_SEGMENT_64:
			var seg64 types.Segment64
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg64); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEGMENT_64: %v", err)
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg64.Name[0:])
			s.Addr = seg64.Addr
			s.Memsz = seg64.Memsz
			s.Offset = seg64.Offset
			s.Filesz = seg64.Filesz
			s.Maxprot = seg64.Maxprot
			s.Prot = seg64.Prot
			s.Nsect = seg64.Nsect
			s.Flag = seg64.Flag
			s.Firstsect = uint32(len(f.Sections))
			for i := 0; i < int(s.Nsect); i++ {
				var sh64 types.Section64
				if err := binary.Read(b, bo, &sh64); err != nil {
					return nil, fmt.Errorf("failed to read Section64: %v", err)
				}
				sh := new(types.Section)
				sh.Type = 64
				sh.Name = cstring(sh64.Name[0:])
				sh.Seg = cstring(sh64.Seg[0:])
				sh.Addr = sh64.Addr
				sh.Size = sh64.Size
				sh.Offset = sh64.Offset
				sh.Align = sh64.Align
				sh.Reloff = sh64.Reloff
				sh.Nreloc = sh64.Nreloc
				sh.Flags = sh64.Flags
				sh.Reserved1 = sh64.Reserve1
				sh.Reserved2 = sh64.Reserve2
				sh.Reserved3 = sh64.Reserve3
				sectionReader, err := newSectionReader(f.cr, sh)
				if err != nil {
					return nil, fmt.Errorf("failed to create Section64 reader: %v", err)
				}
				sh.SetReaders(sectionReader, sectionReader)
				if err := f.pushSection(sh, f.cr); err != nil {
					return nil, fmt.Errorf("failed to pushSection64: %v", err)
				}
				s.Sections = append(s.Sections, sh)
			}
			f.Loads = append(f.Loads, s)
		case types.LC_SYMTAB:
			var hdr types.SymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_SYMTAB: %v", err)
			}
			strtab, err := saferio.ReadDataAt(f.cr, uint64(hdr.Strsize), int64(hdr.Stroff))
			if err != nil {
				return nil, fmt.Errorf("failed to read data at Stroff=%#x; %v", int64(hdr.Stroff), err)
			}
			var symsz int
			if f.Magic == types.Magic64 {
				symsz = 16
			} else {
				symsz = 12
			}
			symdat, err := saferio.ReadDataAt(f.cr, uint64(hdr.Nsyms)*uint64(symsz), int64(hdr.Symoff))
			if err != nil {
				return nil, fmt.Errorf("failed to read data at Symoff=%#x; %v", int64(hdr.Symoff), err)
			}
			st, err := f.parseSymtab(symdat, strtab, cmddat, &hdr, offset)
			if err != nil {
				return nil, fmt.Errorf("failed to read parseSymtab: %v", err)
			}
			st.LoadBytes = cmddat
			st.LoadCmd = cmd
			st.Len = siz
			f.Loads = append(f.Loads, st)
			f.Symtab = st
		case types.LC_SYMSEG:
			var led types.SymsegCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_SYMSEG: %v", err)
			}

			l := new(SymSeg)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_THREAD:
			var t types.ThreadCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &t); err != nil {
				return nil, fmt.Errorf("failed to read LC_THREAD: %v", err)
			}
			l := new(Thread)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.bo = bo
			if f.isArm() || f.isArm64() || f.isArm64e() {
				l.IsArm = true
			}
			for {
				var thread types.ThreadState
				err := binary.Read(b, bo, &thread.Flavor)
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("failed to read LC_THREAD flavor: %v", err)
				}
				if err := binary.Read(b, bo, &thread.Count); err != nil {
					return nil, fmt.Errorf("failed to read LC_THREAD count: %v", err)
				}
				// NOTE: the uint32 multiplication (and its wrap-around) is kept as is;
				// only a size that cannot be satisfied by the load command is rejected early.
				if err := checkReadCount(b, uint64(thread.Count*uint32(binary.Size(uint32(0)))), 1); err != nil {
					return nil, fmt.Errorf("failed to read LC_THREAD state struct data: %v", err)
				}
				thread.Data = make([]byte, thread.Count*uint32(binary.Size(uint32(0))))
				if err := binary.Read(b, bo, &thread.Data); err != nil {
					return nil, fmt.Errorf("failed to read LC_THREAD state struct data: %v", err)
				}
				l.Threads = append(l.Threads, thread)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_UNIXTHREAD:
			var ut types.UnixThreadCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &ut); err != nil {
				return nil, fmt.Errorf("failed to read LC_UNIXTHREAD: %v", err)
			}
			l := new(UnixThread)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.bo = bo
			if f.isArm() || f.isArm64() || f.isArm64e() {
				l.IsArm = true
			}
			for {
				var thread types.ThreadState
				err := binary.Read(b, bo, &thread.Flavor)
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("failed to read LC_UNIXTHREAD flavor: %v", err)
				}
				if err := binary.Read(b, bo, &thread.Count); err != nil {
					return nil, fmt.Errorf("failed to read LC_UNIXTHREAD count: %v", err)
				}
				// NOTE: the uint32 multiplication (and its wrap-around) is kept as is;
				// only a size that cannot be satisfied by the load command is rejected early.
				if err := checkReadCount(b, uint64(thread.Count*uint32(binary.Size(uint32(0)))), 1); err != nil {
					return nil, fmt.Errorf("failed to read LC_UNIXTHREAD state struct data: %v", err)
				}
				thread.Data = make([]byte, thread.Count*uint32(binary.Size(uint32(0))))
				if err := binary.Read(b, bo, &thread.Data); err != nil {
					return nil, fmt.Errorf("failed to read LC_UNIXTHREAD state struct data: %v", err)
				}
				l.Threads = append(l.Threads, thread)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_LOADFVMLIB:
			var hdr types.LoadFvmLibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LOADFVMLIB: %v", err)
			}
			l := new(LoadFvmlib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			l.MinorVersion = hdr.MinorVersion
			l.HeaderAddr = hdr.HeaderAddr
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in LC_LOADFVMLIB command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_IDFVMLIB:
			var hdr types.IDFvmLibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_IDFVMLIB: %v", err)
			}
			l := new(IDFvmlib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			l.MinorVersion = hdr.MinorVersion
			l.HeaderAddr = hdr.HeaderAddr
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in LC_IDFVMLIB command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_IDENT:
			var hdr types.IdentCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_IDENT: %v", err)
			}
			l := new(Ident)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			br := bufio.NewReader(b)
			for {
				o, err := br.ReadString('\x00')
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("failed to read LC_IDENT options: %v", err)
				}
				l.StrTable = append(l.StrTable, o)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_FVMFILE:
			var hdr types.FvmFileCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_FVMFILE: %v", err)
			}
			l := new(FvmFile)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			l.HeaderAddr = hdr.HeaderAddr
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in LC_FVMFILE command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_PREPAGE:
			var hdr types.PrePageCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_PREPAGE: %v", err)
			}
			l := new(Prepage)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			f.Loads = append(f.Loads, l)
		case types.LC_DYSYMTAB:
			var hdr types.DysymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYSYMTAB: %v", err)
			}
			if f.Symtab == nil {
				return nil, &FormatError{offset, "dynamic symbol table seen before any ordinary symbol table", nil}
			} else if hdr.Iundefsym > uint32(len(f.Symtab.Syms)) {
				return nil, &FormatError{offset, fmt.Sprintf(
					"undefined symbols index in dynamic symbol table command is greater than symbol table length (%d > %d)",
					hdr.Iundefsym, len(f.Symtab.Syms)), nil}
			} else if hdr.Iundefsym+hdr.Nundefsym > uint32(len(f.Symtab.Syms)) {
				return nil, &FormatError{offset, fmt.Sprintf(
					"number of undefined symbols after index in dynamic symbol table command is greater than symbol table length (%d > %d)",
					hdr.Iundefsym+hdr.Nundefsym, len(f.Symtab.Syms)), nil}
			}
			dat, err := saferio.ReadDataAt(f.cr, uint64(hdr.Nindirectsyms)*4, int64(hdr.Indirectsymoff))
			if err != nil {
				return nil, fmt.Errorf("failed to read data at Indirectsymoff @ %#x: %w", int64(hdr.Indirectsymoff), err)
			}
			x := make([]uint32, hdr.Nindirectsyms)
			if err := binary.Read(bytes.NewReader(dat), bo, x); err != nil {
				return nil, fmt.Errorf("failed to read Nindirectsyms: %v", err)
			}
			// TODO: parse DylibTableOfContents if Ntoc > 0
			// TODO: parse DylibModule if Nmodtab > 0
			// TODO: parse DylibReference if Nextrefsyms > 0
			st := new(Dysymtab)
			st.LoadBytes = cmddat
			st.LoadCmd = cmd
			st.Len = siz
			st.DysymtabCmd = hdr
			st.IndirectSyms = x
			// 解析 local relocations (InternalRelocs)
			if hdr.Nlocrel > 0 {
				locrelDat, err := saferio.ReadDataAt(f.cr, uint64(hdr.Nlocrel)*8, int64(hdr.Locreloff))
				if err != nil {
					return nil, fmt.Errorf("failed to read local relocations at %#x: %w", hdr.Locreloff, err)
				}
				st.InternalRelocs, err = f.parseRelocations(locrelDat, hdr.Nlocrel, bo)
				if err != nil {
					return nil, fmt.Errorf("failed to parse local relocations: %w", err)
				}
			}
			// 解析 external relocations (ExternalRelocs)
			if hdr.Nextrel > 0 {
				extrelDat, err := saferio.ReadDataAt(f.cr, uint64(hdr.Nextrel)*8, int64(hdr.Extreloff))
				if err != nil {
					return nil, fmt.Errorf("failed to read external relocations at %#x: %w", hdr.Extreloff, err)
				}
				st.ExternalRelocs, err = f.parseRelocations(extrelDat, hdr.Nextrel, bo)
				if err != nil {
					return nil, fmt.Errorf("failed to parse external relocations: %w", err)
				}
			}
			f.Loads = append(f.Loads, st)
			f.Dysymtab = st
		case types.LC_LOAD_DYLIB:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LOAD_DYLIB: %v", err)
			}
			l := new(LoadDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			l.setDylibUseFlags(cmddat, bo)
			f.Loads = append(f.Loads, l)
		case types.LC_ID_DYLIB:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_ID_DYLIB: %v", err)
			}
			l := new(IDDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library ident command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			f.Loads = append(f.Loads, l)
		case types.LC_LOAD_DYLINKER:
			var hdr types.DylinkerCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LOAD_DYLINKER: %v", err)
			}
			l := new(LoadDylinker)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load dylinker command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_ID_DYLINKER:
			var hdr types.IDDylinkerCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_ID_DYLINKER: %v", err)
			}
			l := new(DylinkerID)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load dylinker command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_PREBOUND_DYLIB:
			var hdr types.PreboundDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_PREBOUND_DYLIB: %v", err)
			}
			l := new(PreboundDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in LC_PREBOUND_DYLIB command", hdr.NameOffset}
			}
			l.NumModules = hdr.NumModules
			l.Name = cstring(cmddat[hdr.NameOffset:])
			if hdr.LinkedModulesOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid linked modules in LC_PREBOUND_DYLIB command", hdr.NameOffset}
			}
			l.LinkedModulesBitVector = cstring(cmddat[hdr.LinkedModulesOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_ROUTINES:
			var rt types.RoutinesCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &rt); err != nil {
				return nil, fmt.Errorf("failed to read LC_ROUTINES: %v", err)
			}
			l := new(Routines)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.InitAddress = rt.InitAddress
			l.InitModule = rt.InitModule
			f.Loads = append(f.Loads, l)
		case types.LC_SUB_FRAMEWORK:
			var sf types.SubFrameworkCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sf); err != nil {
				return nil, fmt.Errorf("failed to read LC_SUB_FRAMEWORK: %v", err)
			}
			l := new(SubFramework)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.FrameworkOffset = sf.FrameworkOffset
			if sf.FrameworkOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid framework in sub-framework command", sf.FrameworkOffset}
			}
			l.Framework = cstring(cmddat[sf.FrameworkOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_SUB_UMBRELLA:
			var su types.SubUmbrellaCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &su); err != nil {
				return nil, fmt.Errorf("failed to read LC_SUB_UMBRELLA: %v", err)
			}
			l := new(SubUmbrella)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.UmbrellaOffset = su.UmbrellaOffset
			if su.UmbrellaOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid framework in sub-umbrella command", su.UmbrellaOffset}
			}
			l.Umbrella = cstring(cmddat[su.UmbrellaOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_SUB_CLIENT:
			var sc types.SubClientCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sc); err != nil {
				return nil, fmt.Errorf("failed to read LC_SUB_CLIENT: %v", err)
			}
			l := new(SubClient)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.ClientOffset = sc.ClientOffset
			if sc.ClientOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in sub client command", sc.ClientOffset}
			}
			l.Name = cstring(cmddat[sc.ClientOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_SUB_LIBRARY:
			var s types.SubLibraryCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &s); err != nil {
				return nil, fmt.Errorf("failed to read LC_SUB_LIBRARY: %v", err)
			}
			l := new(SubLibrary)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.LibraryOffset = s.LibraryOffset
			if s.LibraryOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid framework in sub-library command", s.LibraryOffset}
			}
			l.Library = cstring(cmddat[s.LibraryOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_TWOLEVEL_HINTS:
			var t types.TwolevelHintsCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &t); err != nil {
				return nil, fmt.Errorf("failed to read LC_TWOLEVEL_HINTS: %v", err)
			}
			l := new(TwolevelHints)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = t.Offset
			if err := checkReadCount(b, uint64(t.NumHints), uint64(binary.Size(types.TwolevelHint(0)))); err != nil {
				return nil, fmt.Errorf("failed to read hints data: %v", err)
			}
			l.Hints = make([]types.TwolevelHint, t.NumHints)
			if err := binary.Read(b, bo, &l.Hints); err != nil {
				return nil, fmt.Errorf("failed to read hints data: %v", err)
			}
			f.Loads = append(f.Loads, l)

		case types.LC_PREBIND_CKSUM:
			var p types.PrebindCksumCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &p); err != nil {
				return nil, fmt.Errorf("failed to read LC_PREBIND_CKSUM: %v", err)
			}
			l := new(PrebindCheckSum)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.CheckSum = p.CheckSum
			f.Loads = append(f.Loads, l)
		case types.LC_LOAD_WEAK_DYLIB:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LOAD_WEAK_DYLIB: %v", err)
			}
			l := new(WeakDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in weak dynamic library command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			l.setDylibUseFlags(cmddat, bo)
			f.Loads = append(f.Loads, l)
		case types.LC_ROUTINES_64:
			var r64 types.Routines64Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &r64); err != nil {
				return nil, fmt.Errorf("failed to read LC_ROUTINES_64: %v", err)
			}
			l := new(Routines64)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.InitAddress = r64.InitAddress
			l.InitModule = r64.InitModule
			f.Loads = append(f.Loads, l)
		case types.LC_UUID:
			var u types.UUIDCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &u); err != nil {
				return nil, fmt.Errorf("failed to read LC_UUID: %v", err)
			}
			l := new(UUID)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.UUID = u.UUID
			f.Loads = append(f.Loads, l)
		case types.LC_RPATH:
			var hdr types.RpathCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_RPATH: %v", err)
			}
			l := new(Rpath)
			if hdr.PathOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in rpath command", hdr.PathOffset}
			}
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.PathOffset = hdr.PathOffset
			if hdr.PathOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in rpath command", hdr.PathOffset}
			}
			l.Path = cstring(cmddat[hdr.PathOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_CODE_SIGNATURE:
			var hdr types.CodeSignatureCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_CODE_SIGNATURE: %v", err)
			}

			l := new(CodeSignature)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = hdr.Offset
			l.Size = hdr.Size
			csdat, err := readDataAt(f.cr, uint64(hdr.Size), int64(hdr.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read CS data at offset=%#x; %v", int64(hdr.Offset), err)
			}
			cs, err := codesign.ParseCodeSignature(csdat)
			if err != nil {
				return nil, fmt.Errorf("failed to ParseCodeSignature: %v", err)
			}
			l.CodeSignature = *cs
			f.Loads = append(f.Loads, l)
		case types.LC_SEGMENT_SPLIT_INFO:
			var hdr types.SegmentSplitInfoCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO: %v", err)
			}
			l := new(SplitInfo)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = hdr.Offset
			l.Size = hdr.Size
			if l.Size > 0 {
				ldat, err := readDataAt(f.cr, uint64(l.Size), int64(l.Offset))
				if err != nil {
					return nil, fmt.Errorf("failed to read SplitInfo data at offset=%#x; %v", int64(hdr.Offset), err)
				}
				fsr := bytes.NewReader(ldat)
				if err := binary.Read(fsr, bo, &l.Version); err != nil {
					return nil, fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO Version: %v", err)
				}
			}
			f.Loads = append(f.Loads, l)
		case types.LC_REEXPORT_DYLIB:
			var hdr types.ReExportDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_REEXPORT_DYLIB: %v", err)
			}
			l := new(ReExportDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			l.setDylibUseFlags(cmddat, bo)
			f.Loads = append(f.Loads, l)
		case types.LC_LAZY_LOAD_DYLIB:
			var hdr types.LazyLoadDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LAZY_LOAD_DYLIB: %v", err)
			}
			l := new(LazyLoadDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load upwardl dylib command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			f.Loads = append(f.Loads, l)
		case types.LC_ENCRYPTION_INFO:
			var ei types.EncryptionInfoCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &ei); err != nil {
				return nil, fmt.Errorf("failed to read LC_ENCRYPTION_INFO: %v", err)
			}

			l := new(EncryptionInfo)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = ei.Offset
			l.Size = ei.Size
			l.CryptID = ei.CryptID
			f.Loads = append(f.Loads, l)
		case types.LC_DYLD_INFO:
			var info types.DyldInfoCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &info); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLD_INFO: %v", err)
			}
			l := new(DyldInfo)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.RebaseOff = info.RebaseOff
			l.RebaseSize = info.RebaseSize
			l.BindOff = info.BindOff
			l.BindSize = info.BindSize
			l.WeakBindOff = info.WeakBindOff
			l.WeakBindSize = info.WeakBindSize
			l.LazyBindOff = info.LazyBindOff
			l.LazyBindSize = info.LazyBindSize
			l.ExportOff = info.ExportOff
			l.ExportSize = info.ExportSize
			f.Loads = append(f.Loads, l)
		case types.LC_DYLD_INFO_ONLY:
			var info types.DyldInfoOnlyCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &info); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLD_INFO_ONLY: %v", err)
			}
			l := new(DyldInfoOnly)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.RebaseOff = info.RebaseOff
			l.RebaseSize = info.RebaseSize
			l.BindOff = info.BindOff
			l.BindSize = info.BindSize
			l.WeakBindOff = info.WeakBindOff
			l.WeakBindSize = info.WeakBindSize
			l.LazyBindOff = info.LazyBindOff
			l.LazyBindSize = info.LazyBindSize
			l.ExportOff = info.ExportOff
			l.ExportSize = info.ExportSize
			f.Loads = append(f.Loads, l)
		case types.LC_LOAD_UPWARD_DYLIB:
			var hdr types.LoadUpwardDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_LOAD_UPWARD_DYLIB: %v", err)
			}
			l := new(UpwardDylib)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load upward dylib command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			l.Timestamp = hdr.Timestamp
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			l.setDylibUseFlags(cmddat, bo)
			f.Loads = append(f.Loads, l)
		case types.LC_VERSION_MIN_MACOSX:
			var verMin types.VersionMinMacOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, fmt.Errorf("failed to read LC_VERSION_MIN_MACOSX: %v", err)
			}
			l := new(VersionMinMacOSX)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Version = verMin.Version
			l.Sdk = verMin.Sdk
			f.Loads = append(f.Loads, l)
		case types.LC_VERSION_MIN_IPHONEOS:
			var verMin types.VersionMinIPhoneOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, fmt.Errorf("failed to read LC_VERSION_MIN_IPHONEOS: %v", err)
			}
			l := new(VersionMiniPhoneOS)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Version = verMin.Version
			l.Sdk = verMin.Sdk
			f.Loads = append(f.Loads, l)
		case types.LC_FUNCTION_STARTS:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_FUNCTION_STARTS: %v", err)
			}

			l := new(FunctionStarts)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_DYLD_ENVIRONMENT:
			var hdr types.DyldEnvironmentCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLD_ENVIRONMENT: %v", err)
			}
			l := new(DyldEnvironment)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.NameOffset = hdr.NameOffset
			if hdr.NameOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dyld environment command", hdr.NameOffset}
			}
			l.Name = cstring(cmddat[hdr.NameOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_MAIN:
			var hdr types.EntryPointCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_MAIN: %v", err)
			}
			l := new(EntryPoint)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.EntryOffset = hdr.EntryOffset
			l.StackSize = hdr.StackSize
			f.Loads = append(f.Loads, l)
		case types.LC_DATA_IN_CODE:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_DATA_IN_CODE: %v", err)
			}
			l := new(DataInCode)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			ldat, err := readDataAt(f.cr, uint64(l.Size), int64(l.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read DataInCode data at offset=%#x; %v", int64(led.Offset), err)
			}
			l.Entries = make([]types.DataInCodeEntry, len(ldat)/binary.Size(types.DataInCodeEntry{}))
			if err := binary.Read(bytes.NewReader(ldat), bo, &l.Entries); err != nil {
				return nil, fmt.Errorf("failed to read LC_DATA_IN_CODE entries: %v", err)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_SOURCE_VERSION:
			var sv types.SourceVersionCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sv); err != nil {
				return nil, fmt.Errorf("failed to read LC_SOURCE_VERSION: %v", err)
			}
			l := new(SourceVersion)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Version = sv.Version
			f.Loads = append(f.Loads, l)
		case types.LC_DYLIB_CODE_SIGN_DRS:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLIB_CODE_SIGN_DRS: %v", err)
			}

			l := new(DylibCodeSignDrs)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_ENCRYPTION_INFO_64:
			var ei types.EncryptionInfo64Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &ei); err != nil {
				return nil, fmt.Errorf("failed to read LC_ENCRYPTION_INFO_64: %v", err)
			}
			l := new(EncryptionInfo64)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = ei.Offset
			l.Size = ei.Size
			l.CryptID = ei.CryptID
			f.Loads = append(f.Loads, l)
		case types.LC_LINKER_OPTION:
			var lo types.LinkerOptionCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &lo); err != nil {
				return nil, fmt.Errorf("failed to read LC_LINKER_OPTION: %v", err)
			}
			l := new(LinkerOption)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			for i := 0; i < int(lo.Count); i++ {
				o, err := bufio.NewReader(b).ReadString('\x00')
				if err != nil {
					break // FIXME: should this error?
				}
				l.Options = append(l.Options, o)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_LINKER_OPTIMIZATION_HINT:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_LINKER_OPTIMIZATION_HINT: %v", err)
			}

			l := new(LinkerOptimizationHint)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_VERSION_MIN_TVOS:
			var verMin types.VersionMinMacOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, fmt.Errorf("failed to read LC_VERSION_MIN_TVOS: %v", err)
			}
			l := new(VersionMinTvOS)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Version = verMin.Version
			l.Sdk = verMin.Sdk
			f.Loads = append(f.Loads, l)
		case types.LC_VERSION_MIN_WATCHOS:
			var verMin types.VersionMinWatchOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, fmt.Errorf("failed to read LC_VERSION_MIN_WATCHOS: %v", err)
			}
			l := new(VersionMinWatchOS)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Version = verMin.Version
			l.Sdk = verMin.Sdk
			f.Loads = append(f.Loads, l)
		case types.LC_NOTE:
			var n types.NoteCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &n); err != nil {
				return nil, fmt.Errorf("failed to read LC_NOTE: %v", err)
			}
			l := new(Note)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.DataOwner = n.DataOwner
			l.Offset = n.Offset
			l.Size = n.Size
			l.bo = bo
			var err error
			if l.Data, err = readDataAt(f.cr, uint64(l.Size), int64(l.Offset)); err != nil {
				return nil, fmt.Errorf("failed to read Note data at offset=%#x; %v", int64(l.Offset), err)
			}
			f.Loads = append(f.Loads, l)
		case types.LC_BUILD_VERSION:
			var build types.BuildVersionCmd
			var buildTool types.BuildVersionTool
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &build); err != nil {
				return nil, fmt.Errorf("failed to read LC_BUILD_VERSION: %v", err)
			}
			l := new(BuildVersion)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Platform = build.Platform
			l.Minos = build.Minos
			l.Sdk = build.Sdk
			l.NumTools = build.NumTools
			for i := uint32(0); i < build.NumTools; i++ {
				if err := binary.Read(b, bo, &buildTool); err != nil {
					return nil, fmt.Errorf("failed to read LC_BUILD_VERSION buildTool: %v", err)
				}
				l.Tools = append(l.Tools, types.BuildVersionTool{
					Tool:    buildTool.Tool,
					Version: buildTool.Version,
				})
			}
			f.Loads = append(f.Loads, l)
		case types.LC_DYLD_EXPORTS_TRIE:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLD_EXPORTS_TRIE: %v", err)
			}

			l := new(DyldExportsTrie)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_DYLD_CHAINED_FIXUPS:
			var led types.DyldChainedFixupsCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_DYLD_CHAINED_FIXUPS: %v", err)
			}

			l := new(DyldChainedFixups)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_FILESET_ENTRY:
			var hdr types.FilesetEntryCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_FILESET_ENTRY: %v", err)
			}
			l := new(FilesetEntry)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Addr = hdr.Addr
			l.FileOffset = hdr.FileOffset
			l.EntryIdOffset = hdr.EntryIdOffset
			if hdr.EntryIdOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load fileset entry command", hdr.EntryIdOffset}
			}
			l.EntryID = cstring(cmddat[hdr.EntryIdOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_ATOM_INFO:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_ATOM_INFO: %v", err)
			}
			l := new(AtomInfo)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_FUNCTION_VARIANTS:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_FUNCTION_VARIANTS: %v", err)
			}
			l := new(FunctionVariants)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_FUNCTION_VARIANT_FIXUPS:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_FUNCTION_VARIANT_FIXUPS: %v", err)
			}
			l := new(FunctionVariantFixups)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_TARGET_TRIPLE:
			var hdr types.TargetTripleCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, fmt.Errorf("failed to read LC_TARGET_TRIPLE: %v", err)
			}
			l := new(TargetTriple)
			if hdr.TargetOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid target in target triple command", hdr.TargetOffset}
			}
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.TargetOffset = hdr.TargetOffset
			if hdr.TargetOffset >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid target in target triple command", hdr.TargetOffset}
			}
			l.Target = cstring(cmddat[hdr.TargetOffset:])
			f.Loads = append(f.Loads, l)
		case types.LC_LAZY_LOAD_DYLIB_INFO:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_LAZY_LOAD_DYLIB_INFO: %v", err)
			}
			l := new(LazyLoadDylibInfo)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_SEP_CACHE_SLIDE:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEP_CACHE_SLIDE: %v", err)
			}
			l := new(SepCacheSlide)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_SEP_UNKNOWN_2:
			var led types.SepUnknown2Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEP_UNKNOWN_2: %v", err)
			}
			l := new(SepUnknown2)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		case types.LC_SEP_UNKNOWN_3:
			var led types.SepUnknown3Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, fmt.Errorf("failed to read LC_SEP_SYMSEG: %v", err)
			}
			l := new(SepUnknown3)
			l.LoadBytes = cmddat
			l.LoadCmd = cmd
			l.Len = siz
			l.Offset = led.Offset
			l.Size = led.Size
			f.Loads = append(f.Loads, l)
		}
		if s != nil {
			if int64(s.Offset) < 0 {
				return nil, &FormatError{offset, "invalid section offset", s.Offset}
			}
			if int64(s.Filesz) < 0 {
				return nil, &FormatError{offset, "invalid section file size", s.Filesz}
			}
			s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.Filesz))
			s.ReaderAt = s.sr
		}
	}

	return f, nil
}

func (f *File) parseSymtab(symdat, strtab, cmddat []byte, hdr *types.SymtabCmd, offset int64) (*Symtab, error) {
	bo := f.ByteOrder
	c := saferio.SliceCap[Symbol](uint64(hdr.Nsyms))
	if c < 0 {
		return nil, &FormatError{offset, "too many symbols", nil}
	}
	symtab := make([]Symbol, 0, c)
	b := bytes.NewReader(symdat)
	for i := 0; i < int(hdr.Nsyms); i++ {
		var n types.Nlist64
		if f.Magic == types.Magic64 {
			if err := binary.Read(b, bo, &n); err != nil {
				return nil, fmt.Errorf("failed to read Symtab magic: %v", err)
			}
		} else {
			var n32 types.Nlist32
			if err := binary.Read(b, bo, &n32); err != nil {
				return nil, fmt.Errorf("failed to read Symtab nlist32: %v", err)
			}
			n.Name = n32.Name
			n.Type = n32.Type
			n.Sect = n32.Sect
			n.Desc = n32.Desc
			n.Value = uint64(n32.Value)
		}
		var name string
		var indirectName string
		if n.Name < uint32(len(strtab)) {
			// We add "_" to Go symbols. Strip it here. See issue 33808.
			name = cstring(strtab[n.Name:])
			if len(name) > 0 && name[0] == '_' {
				if strings.Contains(name, ".") {
					name = name[1:]
				} else {
					name = demangle.Filter(name[1:])
				}
			}
		}
		if n.Type.IsIndirectSym() && n.Value < uint64(len(strtab)) {
			indirectName = cstring(strtab[n.Value:])
			if strings.Contains(indirectName, ".") && indirectName[0] == '_' {
				indirectName = indirectName[1:]
			}
		}
		symtab = append(symtab, Symbol{
			Name:         name,
			IndirectName: indirectName,
			Type:         n.Type,
			Sect:         n.Sect,
			Desc:         n.Desc,
			Value:        n.Value,
		})
	}
	st := new(Symtab)
	st.LoadBytes = LoadBytes(cmddat)
	st.Symoff = hdr.Symoff
	st.Nsyms = hdr.Nsyms
	st.Stroff = hdr.Stroff
	st.Strsize = hdr.Strsize
	st.Len = hdr.Len
	st.Syms = symtab
	return st, nil
}

func (f *File) pushSection(sh *types.Section, r io.ReaderAt) error {
	f.Sections = append(f.Sections, sh)

	if sh.Nreloc > 0 {
		reldat, err := saferio.ReadDataAt(r, uint64(sh.Nreloc)*8, int64(sh.Reloff))
		if err != nil {
			return fmt.Errorf("failed to read data at Reloff @ %#x: %w", int64(sh.Reloff), err)
		}
		b := bytes.NewReader(reldat)

		bo := f.ByteOrder

		sh.Relocs = make([]types.Reloc, sh.Nreloc)
		for i := range sh.Relocs {
			rel := &sh.Relocs[i]

			var ri types.RelocInfo
			if err := binary.Read(b, bo, &ri); err != nil {
				return fmt.Errorf("failed to read types.RelocInfo: %w", err)
			}

			if ri.Addr&(1<<31) != 0 { // scattered
				rel.Addr = ri.Addr & (1<<24 - 1)
				rel.Type = uint8((ri.Addr >> 24) & (1<<4 - 1))
				rel.Len = uint8((ri.Addr >> 28) & (1<<2 - 1))
				rel.Pcrel = ri.Addr&(1<<30) != 0
				rel.Value = ri.Symnum
				rel.Scattered = true
			} else {
				switch bo {
				case binary.LittleEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum & (1<<24 - 1)
					rel.Pcrel = ri.Symnum&(1<<24) != 0
					rel.Len = uint8((ri.Symnum >> 25) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<27) != 0
					rel.Type = uint8((ri.Symnum >> 28) & (1<<4 - 1))
				case binary.BigEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum >> 8
					rel.Pcrel = ri.Symnum&(1<<7) != 0
					rel.Len = uint8((ri.Symnum >> 5) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<4) != 0
					rel.Type = uint8(ri.Symnum & (1<<4 - 1))
				default:
					panic("unreachable")
				}
			}
		}
	}

	return nil
}

// parseRelocations 解析 relocation 数据 (用于 Dysymtab 的 InternalRelocs/ExternalRelocs)
func (f *File) parseRelocations(data []byte, count uint32, bo binary.ByteOrder) ([]types.Reloc, error) {
	relocs := make([]types.Reloc, count)
	b := bytes.NewReader(data)

	for i := uint32(0); i < count; i++ {
		var ri types.RelocInfo
		if err := binary.Read(b, bo, &ri); err != nil {
			return nil, fmt.Errorf("failed to read RelocInfo: %w", err)
		}

		rel := &relocs[i]
		if ri.Addr&(1<<31) != 0 { // scattered
			rel.Addr = ri.Addr & (1<<24 - 1)
			rel.Type = uint8((ri.Addr >> 24) & (1<<4 - 1))
			rel.Len = uint8((ri.Addr >> 28) & (1<<2 - 1))
			rel.Pcrel = ri.Addr&(1<<30) != 0
			rel.Value = ri.Symnum
			rel.Scattered = true
		} else {
			switch bo {
			case binary.LittleEndian:
				rel.Addr = ri.Addr
				rel.Value = ri.Symnum & (1<<24 - 1)
				rel.Pcrel = ri.Symnum&(1<<24) != 0
				rel.Len = uint8((ri.Symnum >> 25) & (1<<2 - 1))
				rel.Extern = ri.Symnum&(1<<27) != 0
				rel.Type = uint8((ri.Symnum >> 28) & (1<<4 - 1))
			case binary.BigEndian:
				rel.Addr = ri.Addr
				rel.Value = ri.Symnum >> 8
				rel.Pcrel = ri.Symnum&(1<<7) != 0
				rel.Len = uint8((ri.Symnum >> 5) & (1<<2 - 1))
				rel.Extern = ri.Symnum&(1<<4) != 0
				rel.Type = uint8(ri.Symnum & (1<<4 - 1))
			default:
				return nil, fmt.Errorf("unsupported byte order")
			}
		}
	}

	return relocs, nil
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[0:i])
}

func readString(r io.Reader) (string, error) {
	var b byte
	var str string

	for {
		err := binary.Read(r, binary.BigEndian, &b)

		if err != nil {
			return str, err
		}

		if b == '\x00' {
			return str, nil
		}

		str += string(b)
	}
}

func (f *File) is64bit() bool { return f.FileHeader.Magic == types.Magic64 }
func (f *File) isArm() bool   { return f.CPU == types.CPUArm }
func (f *File) isArm64() bool { return f.CPU == types.CPUArm64 || f.CPU == types.CPUArm6432 }
func (f *File) isArm64e() bool {
	return f.isArm64() && (f.SubCPU&types.CpuSubtypeMask) == types.CPUSubtypeArm64E
}

func (f *File) pointerSize() uint64 {
	if f.is64bit() {
		return 8
	}
	return 4
}

func decodePointerValue(data []byte, pointerSize uint64, order binary.ByteOrder) (uint64, error) {
	if order == nil {
		return 0, errors.New("cannot decode pointer without a byte order")
	}

	switch pointerSize {
	case 4:
		if len(data) != 4 {
			return 0, fmt.Errorf("invalid 32-bit pointer size: got %d bytes", len(data))
		}
		return uint64(order.Uint32(data)), nil
	case 8:
		if len(data) != 8 {
			return 0, fmt.Errorf("invalid 64-bit pointer size: got %d bytes", len(data))
		}
		return order.Uint64(data), nil
	default:
		return 0, fmt.Errorf("unsupported pointer size %d", pointerSize)
	}
}

func decodePointerArray(data []byte, pointerSize uint64, order binary.ByteOrder) ([]uint64, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return nil, fmt.Errorf("unsupported pointer size %d", pointerSize)
	}
	if uint64(len(data))%pointerSize != 0 {
		return nil, fmt.Errorf("pointer array size %d is not divisible by pointer size %d", len(data), pointerSize)
	}

	count := uint64(len(data)) / pointerSize
	capacity := saferio.SliceCap[uint64](count)
	if capacity < 0 {
		return nil, fmt.Errorf("pointer array count %d is too large", count)
	}
	pointers := make([]uint64, 0, capacity)
	step := int(pointerSize)
	for offset := 0; offset < len(data); offset += step {
		pointer, err := decodePointerValue(data[offset:offset+step], pointerSize, order)
		if err != nil {
			return nil, err
		}
		pointers = append(pointers, pointer)
	}
	return pointers, nil
}

func (f *File) readPointerAtAddress(address uint64) (uint64, error) {
	size := f.pointerSize()
	data := make([]byte, size)
	if _, err := f.cr.ReadAtAddr(data, address); err != nil {
		return 0, fmt.Errorf("failed to read %d-byte pointer @ %#x: %w", size, address, err)
	}
	return decodePointerValue(data, size, f.ByteOrder)
}

func (f *File) readPointerArrayAtAddress(address, size uint64) ([]uint64, error) {
	pointerSize := f.pointerSize()
	if size%pointerSize != 0 {
		return nil, fmt.Errorf("pointer array @ %#x has size %d, which is not divisible by pointer size %d", address, size, pointerSize)
	}
	if size == 0 {
		return []uint64{}, nil
	}

	data, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: address}, size, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read pointer array @ %#x: %w", address, err)
	}
	return decodePointerArray(data, pointerSize, f.ByteOrder)
}

// pageSize returns the VM page size for the binary's CPU architecture.
func (f *File) pageSize() uint64 {
	if f.has16KPages() {
		return 0x4000
	}
	return 0x1000
}

func (f *File) symbolSize() int {
	if f.is64bit() {
		return binary.Size(types.Nlist64{})
	}
	return binary.Size(types.Nlist32{})
}

func (f *File) has16KPages() bool {
	switch f.CPU {
	case types.CPUArm64, types.CPUArm6432:
		return true
	case types.CPUArm:
		if f.Type != types.MH_KEXT_BUNDLE {
			return false
		}
		return f.SubCPU == types.CPUSubtypeArmV7K
	default:
		return false
	}
}

func (f *File) preferredLoadAddress() uint64 {
	if text := f.Segment("__TEXT"); text != nil {
		return text.Addr
	}
	return 0
}

// addrReaderAt adapts a MachoReader's ReadAtAddr into io.ReaderAt,
// translating offset-based reads into virtual-address-based reads.
// This ensures Section.Data() resolves the correct DSC subcache for
// each read rather than always hitting the LINKEDIT subcache.
type addrReaderAt struct {
	r    types.MachoReader
	addr uint64
}

func (a *addrReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || uint64(off) > math.MaxUint64-a.addr {
		return 0, errors.New("section address read offset out of range")
	}
	return a.r.ReadAtAddr(p, a.addr+uint64(off))
}

// zeroReaderAt models Mach-O sections which occupy virtual memory but have no
// bytes in the file (S_ZEROFILL, S_GB_ZEROFILL, and S_THREAD_LOCAL_ZEROFILL).
// The enclosing SectionReader supplies the section bounds.
type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative zero-fill section offset")
	}
	clear(p)
	return len(p), nil
}

func newSectionReader(r types.MachoReader, section *types.Section) (*io.SectionReader, error) {
	if section.Size > math.MaxInt64 {
		return nil, fmt.Errorf("section %s.%s size %#x exceeds reader limit", section.Seg, section.Name, section.Size)
	}

	size := int64(section.Size)
	switch {
	case section.Flags.IsZerofill(), section.Flags.IsGbZerofill(), section.Flags.IsThreadLocalZerofill():
		return io.NewSectionReader(zeroReaderAt{}, 0, size), nil
	case section.Addr == 0 || section.Seg == "__DWARF":
		// MH_OBJECT sections commonly have address zero, and DWARF data is file
		// metadata rather than mapped runtime memory. In both cases, Offset is
		// the authoritative location and a VM-address read at zero is incorrect.
		return io.NewSectionReader(r, int64(section.Offset), size), nil
	default:
		// VM-address reads are required for mapped shared-cache sections because
		// their bytes can cross subcache file boundaries.
		return io.NewSectionReader(&addrReaderAt{r: r, addr: section.Addr}, 0, size), nil
	}
}

// ReadAt reads data at offset within MachO
func (f *File) ReadAt(p []byte, off int64) (n int, err error) {
	return f.cr.ReadAt(p, off) // TODO: should this be f.cr  or f.sr?
}

func (f *File) ReadAtAddr(p []byte, addr uint64) (n int, err error) {
	return f.cr.ReadAtAddr(p, addr)
}

// GetOffset returns the file offset for a given virtual address
func (f *File) GetOffset(address uint64) (uint64, error) {
	return f.vma.GetOffset(address)
}

func (f *File) getOffset(address uint64) (uint64, error) {
	// Walks Loads directly (same order and result as ranging over Segments())
	// so this hot path does not allocate a segment slice per lookup.
	for _, l := range f.Loads {
		seg, ok := l.(*Segment)
		if !ok {
			continue
		}
		// NOTE: the bound is Memsz on purpose. __PAGEZERO is a segment with
		// addr 0, filesz 0, memsz 4 GiB and file offset 0, so through it any value
		// below 4 GiB maps to the file offset of the same value. Chained-fixup
		// targets are frequently image-relative offsets rather than full
		// addresses, and the ObjC/Swift parsers read through exactly this path.
		// Bounding by Filesz instead (tried) changed 758 ObjC/Swift dump results
		// over a 1,478-binary corpus. The same bound also lets an address in a
		// data segment's zero-fill tail map into the following segment's bytes;
		// that case is left as is because the two cannot be told apart here.
		if seg.Addr <= address && address < seg.Addr+seg.Memsz {
			return (address - seg.Addr) + seg.Offset, nil
		}
	}
	return 0, fmt.Errorf("address %#x not within any segment's adress range", address)
}

// addrResolvable reports whether vmaddr can be read from this file's reader.
//
// In-cache files resolve addresses against the entire shared cache, so
// cross-image references succeed. Standalone files (e.g. a dyld_shared_cache
// extracted dylib) only contain their own segments, so a cross-image reference
// is unresolvable and callers skip it rather than failing.
func (f *File) addrResolvable(vmaddr uint64) bool {
	if vmaddr == 0 || f.cr == nil {
		return false
	}
	// Probe with a real read so segments whose Memsz exceeds Filesz (bss tails)
	// report unresolvable, which a segment-table lookup alone would not catch.
	var buf [1]byte
	n, _ := f.cr.ReadAtAddr(buf[:], vmaddr)
	return n == len(buf)
}

// GetVMAddress returns the virtal address for a given file offset
func (f *File) GetVMAddress(offset uint64) (uint64, error) {
	return f.vma.GetVMAddress(offset)
}

func (f *File) getVMAddress(offset uint64) (uint64, error) {
	for _, l := range f.Loads {
		seg, ok := l.(*Segment)
		if !ok {
			continue
		}
		if seg.Offset <= offset && offset < seg.Offset+seg.Filesz {
			return (offset - seg.Offset) + seg.Addr, nil
		}
	}
	return 0, fmt.Errorf("offset %#x not within any segment's file offset range", offset)
}

// GetBaseAddress returns the MachO's preferred load address
func (f *File) GetBaseAddress() uint64 {
	return f.preferredLoadAddress()
}

func (f *File) resolveChainedFixupAtOffset(offset, raw uint64) (uint64, bool, error) {
	if !f.HasDyldChainedFixups() {
		return 0, false, nil
	}
	dcf, err := f.DyldChainedFixups()
	if err != nil {
		return 0, false, fmt.Errorf("parse chained fixups: %w", err)
	}
	fixup, err := dcf.GetFixupAtOffset(offset)
	if errors.Is(err, fixupchains.ErrNoFixupAtOffset) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("resolve chained fixup at offset %#x: %w", offset, err)
	}

	switch fixup := fixup.(type) {
	case fixupchains.Rebase:
		target, err := dcf.ResolveRebaseVMAddress(fixup, f.GetBaseAddress(), 0)
		if err != nil {
			return 0, false, fmt.Errorf("resolve chained rebase at offset %#x: %w", offset, err)
		}
		return target, true, nil
	case fixupchains.Bind:
		imp, addend, ok := dcf.IsBind(raw)
		if !ok {
			return 0, false, fmt.Errorf("chained fixup at offset %#x reports a bind but raw pointer %#x cannot be decoded", offset, raw)
		}
		if imp.LibOrdinal() == types.BIND_SPECIAL_DYLIB_SELF {
			symAddr, err := f.FindSymbolAddress(fixup.Name())
			if err != nil {
				return 0, false, fmt.Errorf("resolve self bind %q at offset %#x: %w", fixup.Name(), offset, err)
			}
			return uint64(int64(symAddr) + addend), true, nil
		}
		return raw, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported chained fixup type %T at offset %#x", fixup, offset)
	}
}

func (f *File) convertPointerWithoutChainedFixups(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	if resolved, ok := f.decodeDyldInfoPointer(value); ok {
		return resolved
	}
	// A caller-supplied converter may represent a parent fileset/shared-cache
	// address space. Exact chained-fixup membership only excludes this slot from
	// the local chain; it must not bypass that external address conversion.
	if f.customVMAddrConverter {
		return f.vma.Convert(value)
	}
	return value
}

// GetPointer returns pointer at a given offset
func (f *File) GetPointer(offset uint64) (uint64, error) {
	// Thread-safe: Use ReadAt which doesn't modify shared state
	buf := make([]byte, f.pointerSize())
	if _, err := f.cr.ReadAt(buf, int64(offset)); err != nil {
		return 0, fmt.Errorf("failed to read pointer at offset %#x: %w", offset, err)
	}
	ptr, err := decodePointerValue(buf, f.pointerSize(), f.ByteOrder)
	if err != nil {
		return 0, fmt.Errorf("failed to decode pointer at offset %#x: %w", offset, err)
	}
	if address, addrErr := f.vma.GetVMAddress(offset); addrErr == nil {
		if target, resolved, resolveErr := f.resolvePointerAtAddress(address, ptr); resolveErr != nil {
			return 0, resolveErr
		} else if resolved {
			return target, nil
		}
	}
	if f.HasDyldChainedFixups() {
		if target, resolved, resolveErr := f.resolveChainedFixupAtOffset(offset, ptr); resolveErr != nil {
			return 0, resolveErr
		} else if resolved {
			return target, nil
		}
		return f.convertPointerWithoutChainedFixups(ptr), nil
	}
	// CRITICAL: Convert handles pointer sliding/rebasing for relocated pointers
	return f.vma.Convert(ptr), nil
}

// GetPointerAtAddress returns pointer at a given virtual address
func (f *File) GetPointerAtAddress(address uint64) (uint64, error) {
	ptr, err := f.readPointerAtAddress(address)
	if err != nil {
		return 0, err
	}
	if target, resolved, err := f.resolvePointerAtAddress(address, ptr); err != nil {
		return 0, err
	} else if resolved {
		return target, nil
	}
	if offset, offsetErr := f.vma.GetOffset(address); offsetErr == nil && f.HasDyldChainedFixups() {
		if target, resolved, resolveErr := f.resolveChainedFixupAtOffset(offset, ptr); resolveErr != nil {
			return 0, resolveErr
		} else if resolved {
			return target, nil
		}
		if resolved, ok := f.decodeDyldInfoPointerAtAddress(address, ptr); ok {
			return resolved, nil
		}
		return f.convertPointerWithoutChainedFixups(ptr), nil
	}
	// CRITICAL: Convert handles pointer sliding/rebasing for relocated pointers
	return f.vma.Convert(ptr), nil
}

func (f *File) resolvePointerAtAddress(address, raw uint64) (uint64, bool, error) {
	if f.pointerResolver == nil {
		return 0, false, nil
	}
	target, resolved, err := f.pointerResolver(address, raw)
	if err != nil {
		return 0, false, fmt.Errorf("failed to resolve pointer at vmaddr %#x (raw %#x): %w", address, raw, err)
	}
	return target, resolved, nil
}

// ResetFixupsCache clears the cached dyld chained fixups metadata so subsequent
// lookups will reparse the load command payload.
func (f *File) ResetFixupsCache() {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()

	f.dcf = nil
	f.binds = nil
	f.bindsDone = false
	f.rebases = nil
	f.rebasesDone = false
	f.threadedRebases = nil
	f.dyldInfoCacheBuilt = false
	f.dyldInfoRebaseTargets = nil
	f.dyldInfoRebaseValues = nil
	f.dyldInfoBindsByAddr = nil
	f.bindNameIdx = bindNameIndex{}
	f.resetSymbolIndexes()
	if f.vma != nil {
		f.vma.ChainedPointerFormat = 0
	}
}

// SetSharedCacheBaseAddress supplies the unslid first mapping address required
// by shared-cache chained pointer formats. Configure it before publishing the
// File to concurrent readers; an already-parsed local cache is updated too.
func (f *File) SetSharedCacheBaseAddress(address uint64) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	f.sharedCacheBase = address
	f.sharedCacheBaseSet = true
	if f.dcf != nil {
		f.dcf.SetSharedCacheBaseAddress(address)
	}
}

// SharedCacheBaseAddress reports the configured unslid shared-cache base.
func (f *File) SharedCacheBaseAddress() (uint64, bool) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	return f.sharedCacheBase, f.sharedCacheBaseSet
}

// minimumKernelCacheSegmentAddress returns the base used by XNU for a single
// kernel collection: the lowest vmaddr among all LC_SEGMENT commands. This is
// intentionally not GetBaseAddress(), which is the __TEXT vmaddr and may be
// higher than an earlier __HIB segment.
func (f *File) minimumKernelCacheSegmentAddress() (uint64, bool) {
	minimum := ^uint64(0)
	for _, segment := range f.Segments() {
		if segment != nil && segment.Addr < minimum {
			minimum = segment.Addr
		}
	}
	return minimum, minimum != ^uint64(0)
}

func (f *File) effectiveKernelCacheLevelZeroSegmentAddress() (uint64, bool) {
	if f.kernelCacheLevelZeroSegmentSet {
		return f.kernelCacheLevelZeroSegment, true
	}
	return f.minimumKernelCacheSegmentAddress()
}

func (f *File) setKernelCacheLevelZeroSegmentAddress(address uint64) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	f.kernelCacheLevelZeroSegment = address
	f.kernelCacheLevelZeroSegmentSet = true
	if f.dcf != nil {
		f.dcf.SetKernelCacheLevelZeroSegmentAddress(address)
	}
}

// SetKernelCacheBaseAddress configures one runtime basePointers entry for
// chained pointer formats 8 and 11. address must already contain the slide of
// the corresponding primary, pageable, or auxiliary kernel collection.
// Configure it before publishing the File to concurrent readers.
func (f *File) SetKernelCacheBaseAddress(level uint8, address uint64) error {
	if level >= uint8(len(f.kernelCacheBases)) {
		return fmt.Errorf("kernel cache base level %d is outside [0,%d)", level, len(f.kernelCacheBases))
	}
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	f.kernelCacheBases[level] = address
	f.kernelCacheBaseSet[level] = true
	if f.dcf != nil {
		return f.dcf.SetKernelCacheBaseAddress(level, address)
	}
	return nil
}

// KernelCacheBaseAddress reports the effective runtime basePointers entry.
// For an unconfigured level zero, a standalone file defaults to its lowest
// LC_SEGMENT vmaddr (the unslid runtime base). Other levels require explicit
// composition context.
func (f *File) KernelCacheBaseAddress(level uint8) (uint64, bool) {
	if level >= uint8(len(f.kernelCacheBases)) {
		return 0, false
	}
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	if f.kernelCacheBaseSet[level] {
		return f.kernelCacheBases[level], true
	}
	if level == 0 {
		return f.effectiveKernelCacheLevelZeroSegmentAddress()
	}
	return 0, false
}

func (f *File) copyKernelCacheBasesTo(child *File) error {
	if child == nil {
		return errors.New("nil kernel collection child")
	}
	f.fixupsMu.Lock()
	bases := f.kernelCacheBases
	baseSet := f.kernelCacheBaseSet
	levelZeroSegment, levelZeroSegmentSet := f.effectiveKernelCacheLevelZeroSegmentAddress()
	f.fixupsMu.Unlock()
	for level := range bases {
		if baseSet[level] {
			if err := child.SetKernelCacheBaseAddress(uint8(level), bases[level]); err != nil {
				return err
			}
		}
	}
	if !baseSet[0] && levelZeroSegmentSet {
		child.setKernelCacheLevelZeroSegmentAddress(levelZeroSegment)
	}
	return nil
}

// GetSlidPointerAtAddress reads the raw pointer at the given virtual address and, if it is a
// chained rebase pointer, returns the rebased (slid) target using the fast fixup lookup. When the
// pointer is not part of a chained rebase, the result falls back to SlidePointer behaviour.
func (f *File) GetSlidPointerAtAddress(address uint64) (uint64, error) {
	offset, offErr := f.vma.GetOffset(address)
	var rawBuf [8]byte
	var raw uint64
	var rawRead bool

	if offErr == nil && f.HasDyldChainedFixups() {
		dcf, err := f.DyldChainedFixups()
		if err == nil && dcf != nil {
			if format, fmtErr := dcf.PointerFormatForOffset(offset); fmtErr == nil {
				size := fixupchains.PointerSize(format)
				if size == 4 || size == 8 {
					n, readErr := f.cr.ReadAt(rawBuf[:size], int64(offset))
					if readErr == nil && n == size {
						if size == 4 {
							raw = uint64(f.ByteOrder.Uint32(rawBuf[:4]))
						} else {
							raw = f.ByteOrder.Uint64(rawBuf[:8])
						}
						rawRead = true
					}
				}
			}
		}
	}

	if !rawRead {
		var err error
		raw, err = f.readPointerAtAddress(address)
		if err != nil {
			return 0, err
		}
	}

	if target, resolved, err := f.resolvePointerAtAddress(address, raw); err != nil {
		return 0, err
	} else if resolved {
		return target, nil
	}

	if offErr == nil && f.HasDyldChainedFixups() {
		if target, resolved, resolveErr := f.resolveChainedFixupAtOffset(offset, raw); resolveErr != nil {
			return 0, resolveErr
		} else if resolved {
			return target, nil
		}
		if resolved, ok := f.decodeDyldInfoPointerAtAddress(address, raw); ok {
			return resolved, nil
		}
		return f.convertPointerWithoutChainedFixups(raw), nil
	}

	if resolved, ok := f.decodeDyldInfoPointerAtAddress(address, raw); ok {
		return resolved, nil
	}

	return f.SlidePointer(raw), nil
}

func (f *File) decodeChainedPointer(value uint64) (uint64, bool) {
	if value == 0 || !f.HasDyldChainedFixups() {
		return 0, false
	}

	dcf, err := f.DyldChainedFixups()
	if err != nil || dcf == nil {
		return 0, false
	}

	if target, err := dcf.ResolveRawRebaseVMAddress(value, f.GetBaseAddress(), 0); err == nil {
		return target, true
	}

	bind, addend, ok := dcf.IsBind(value)
	if !ok {
		return 0, false
	}

	if bind.LibOrdinal() == types.BIND_SPECIAL_DYLIB_SELF {
		symAddr, err := f.FindSymbolAddress(bind.Name)
		if err != nil {
			return 0, false
		}
		return uint64(int64(symAddr) + addend), true
	}

	return value, true
}

func (f *File) buildDyldInfoFixupsCache() error {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	return f.buildDyldInfoFixupsCacheLocked()
}

func (f *File) buildDyldInfoFixupsCacheLocked() error {
	if f.dyldInfoCacheBuilt {
		return nil
	}

	// Build into locals and publish only after every parser succeeds. This keeps
	// a failed first parse from exposing a partial cache or duplicating entries
	// when the caller retries.
	rebaseTargets := make(map[uint64]uint64)
	rebaseValues := make(map[uint64]struct{})
	bindsByAddr := make(map[uint64]types.Bind)

	rebases, err := f.getRebaseInfoLocked()
	if err != nil && !errors.Is(err, ErrMachODyldInfoNotFound) {
		return err
	}
	for _, rebase := range rebases {
		addr := rebase.Start + rebase.Offset
		rebaseTargets[addr] = f.normalizeDyldInfoPointer(rebase.Value)
		rebaseValues[rebase.Value] = struct{}{}
	}

	binds, err := f.getBindInfoLocked()
	if err != nil && !errors.Is(err, ErrMachODyldInfoNotFound) {
		return err
	}
	for _, bind := range binds {
		addr := bind.Start + bind.SegOffset
		if _, exists := bindsByAddr[addr]; exists {
			continue
		}
		bindsByAddr[addr] = bind
	}

	f.dyldInfoRebaseTargets = rebaseTargets
	f.dyldInfoRebaseValues = rebaseValues
	f.dyldInfoBindsByAddr = bindsByAddr
	f.dyldInfoCacheBuilt = true
	return nil
}

func (f *File) dyldInfoFixupsSnapshot() (map[uint64]uint64, map[uint64]struct{}, map[uint64]types.Bind, error) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	if err := f.buildDyldInfoFixupsCacheLocked(); err != nil {
		return nil, nil, nil, err
	}
	return f.dyldInfoRebaseTargets, f.dyldInfoRebaseValues, f.dyldInfoBindsByAddr, nil
}

func (f *File) normalizeDyldInfoPointer(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	if f.FindSegmentForVMAddr(value) != nil {
		return value
	}

	base := f.GetBaseAddress()
	if value >= base {
		return value
	}

	candidate := value + base
	if f.FindSegmentForVMAddr(candidate) != nil {
		return candidate
	}

	return value
}

func (f *File) usesDyldInfoFixups() bool {
	return (f.HasDyldInfo() || f.HasDyldInfoOnly()) && !f.HasDyldChainedFixups()
}

func (f *File) decodeDyldInfoPointer(value uint64) (uint64, bool) {
	if value == 0 || !f.usesDyldInfoFixups() {
		return 0, false
	}

	_, rebaseValues, _, err := f.dyldInfoFixupsSnapshot()
	if err != nil {
		return 0, false
	}
	if _, ok := rebaseValues[value]; !ok {
		return 0, false
	}
	return f.normalizeDyldInfoPointer(value), true
}

func (f *File) decodeDyldInfoPointerAtAddress(address, raw uint64) (uint64, bool) {
	if !f.usesDyldInfoFixups() {
		return 0, false
	}

	rebaseTargets, _, bindsByAddr, err := f.dyldInfoFixupsSnapshot()
	if err != nil {
		return 0, false
	}

	if resolved, ok := rebaseTargets[address]; ok {
		return resolved, true
	}

	if bind, ok := bindsByAddr[address]; ok {
		if bind.Dylib == f.LibraryOrdinalName(types.BIND_SPECIAL_DYLIB_SELF) {
			symAddr, err := f.FindSymbolAddress(bind.Name)
			if err != nil {
				return 0, false
			}
			return uint64(int64(symAddr) + bind.Addend), true
		}
		return raw, true
	}

	return 0, false
}

// SlidePointer returns slid or un-chained pointer
func (f *File) SlidePointer(ptr uint64) uint64 {
	if resolved, ok := f.decodeChainedPointer(ptr); ok {
		return resolved
	}
	if resolved, ok := f.decodeDyldInfoPointer(ptr); ok {
		return resolved
	}
	return f.vma.Convert(ptr)
}

func (f *File) convertToVMAddr(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	if resolved, ok := f.decodeChainedPointer(value); ok {
		return resolved
	}
	if resolved, ok := f.decodeDyldInfoPointer(value); ok {
		return resolved
	} else if f.isArm64e() {
		// TODO: fix this dumb hack for SUPPORT_OLD_ARM64E_FORMAT
		dcf := fixupchains.DyldChainedFixups{
			PointerFormat: fixupchains.DYLD_CHAINED_PTR_ARM64E,
		}
		if target, ok := dcf.IsRebase(value, f.GetBaseAddress()); ok {
			return target + f.preferredLoadAddress()
		} else if bind, addend, ok := dcf.IsBind(value); ok {
			if bind.LibOrdinal() == types.BIND_SPECIAL_DYLIB_SELF {
				symAddr, err := f.FindSymbolAddress(bind.Name)
				if err != nil {
					return 0
				}
				return uint64(int64(symAddr) + addend)
			}
		}
	}
	return value
}

// GetBindName returns the import name for a given dyld chained pointer
func (f *File) GetBindName(pointer uint64) (string, error) {
	if f.HasFixups() {
		if f.HasDyldChainedFixups() {
			dcf, err := f.DyldChainedFixups()
			if err != nil {
				return "", fmt.Errorf("failed to parse dyld chained fixups: %v", err)
			}
			if len(dcf.Imports) > 0 {
				if bind, _, ok := dcf.IsBind(pointer); ok {
					return bind.Name, nil
				}
				return "", fmt.Errorf("pointer %#x is not a bind", pointer)
			}
			return "", fmt.Errorf("MachO does not contain dyld chained fixups importts")
		} else if f.HasDyldInfo() || f.HasDyldInfoOnly() {
			// first bind at that slot address, in bind-stream order
			f.fixupsMu.Lock()
			binds, err := f.getBindInfoLocked()
			var (
				name  string
				found bool
			)
			if err == nil {
				name, found = f.bindAtLocked(binds, pointer)
			}
			f.fixupsMu.Unlock()
			if err != nil {
				return "", fmt.Errorf("failed to parse classic dyld bind info: %v", err)
			}
			if found {
				return name, nil
			}
			return "", fmt.Errorf("pointer %#x is not a bind", pointer)
		}
	}
	return "", ErrMachONoBindInfo
}

// getBindNameAtAddress resolves the import attached to a pointer slot. Classic
// dyld info identifies binds by slot address, while chained fixups encode the
// import ordinal in the raw pointer bits stored at that slot.
func (f *File) getBindNameAtAddress(address uint64) (string, error) {
	if !f.HasDyldChainedFixups() {
		return f.GetBindName(address)
	}

	dcf, err := f.DyldChainedFixups()
	if err != nil {
		return "", fmt.Errorf("failed to parse dyld chained fixups: %w", err)
	}
	offset, err := f.vma.GetOffset(address)
	if err != nil {
		return "", fmt.Errorf("failed to convert bind slot address %#x: %w", address, err)
	}
	fixup, err := dcf.GetFixupAtOffset(offset)
	if err != nil {
		return "", fmt.Errorf("pointer slot %#x is not a chained bind: %w", address, err)
	}
	if bind, ok := fixup.(fixupchains.Bind); ok {
		return bind.Name(), nil
	}
	return "", fmt.Errorf("pointer slot %#x is not a bind", address)
}

// GetCString returns a c-string at a given virtual address in the MachO
func (f *File) GetCString(addr uint64) (string, error) {
	const maxLength = 1 << 20 // 1 MiB safety cap

	bp := cstringBufPool.Get().(*[]byte)
	buf := *bp
	defer cstringBufPool.Put(bp)

	var out []byte
	current := addr

	for len(out) < maxLength {
		n, err := f.cr.ReadAtAddr(buf, current)
		if n > 0 {
			nullIdx := bytes.IndexByte(buf[:n], 0)
			if nullIdx >= 0 {
				out = append(out, buf[:nullIdx]...)
				if len(out) == 0 {
					return "", nil
				}
				return string(out), nil
			}
			out = append(out, buf[:n]...)
			current += uint64(n)
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("%w at address %#x", ErrCStringNoTerminator, addr)
			}
			continue
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(out) == 0 {
					return "", fmt.Errorf("%w at address %#x", ErrCStringNotFound, addr)
				}
				return "", fmt.Errorf("%w at address %#x", ErrCStringNoTerminator, addr)
			}
			return "", fmt.Errorf("failed to read at address %#x: %w", current, err)
		}

		// No bytes read and no error, avoid infinite loop
		break
	}

	if len(out) == 0 {
		return "", fmt.Errorf("%w at address %#x", ErrCStringNotFound, addr)
	}
	return "", fmt.Errorf("%w at address %#x", ErrCStringNoTerminator, addr)
}

// getUTF16String reads a UTF-16LE encoded string at a given virtual address.
// charCount is the number of UTF-16 code units (not bytes).
func (f *File) getUTF16String(addr, charCount uint64) (string, error) {
	if charCount == 0 {
		return "", nil
	}
	const maxCharCount = 1 << 20 // 1M code units safety cap
	if charCount > maxCharCount {
		return "", fmt.Errorf("implausible UTF-16 char count %d at address %#x", charCount, addr)
	}
	buf := make([]byte, charCount*2)
	if _, err := f.cr.ReadAtAddr(buf, addr); err != nil {
		return "", fmt.Errorf("failed to read UTF-16 string at address %#x: %w", addr, err)
	}
	codes := make([]uint16, charCount)
	for i := range codes {
		codes[i] = f.ByteOrder.Uint16(buf[i*2:])
	}
	return string(utf16.Decode(codes)), nil
}

func (f *File) GetCStrings() (map[string]map[string]uint64, error) {
	strs := make(map[string]map[string]uint64)

	for _, sec := range f.Sections {
		if sec.Flags.IsCstringLiterals() || sec.Name == "__os_log" {
			// Thread-safe: Use ReadAtAddr which doesn't modify shared state
			dat, err := readDataAtAddr(f.cr, sec.Size, sec.Addr)
			if err != nil {
				return nil, fmt.Errorf("failed to read cstring data in %s.%s: %w", sec.Seg, sec.Name, err)
			}

			section := fmt.Sprintf("%s.%s", sec.Seg, sec.Name)
			strs[section] = make(map[string]uint64)

			csr := bytes.NewBuffer(dat)

			for {
				pos := sec.Addr + uint64(csr.Cap()-csr.Len())

				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					return nil, fmt.Errorf("failed to read string: %v", err)
				}

				s = strings.Trim(s, "\x00")

				if len(s) > 0 {
					// Check if string contains printable characters (including Unicode like emojis)
					isPrintable := true
					for _, r := range s {
						if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
							isPrintable = false
							break
						}
					}
					if isPrintable {
						strs[section][s] = pos
					}
				}
			}
		}
	}

	return strs, nil
}

// GetCStringAtOffset returns a c-string at a given offset into the MachO
func (f *File) GetCStringAtOffset(strOffset int64) (string, error) {
	const (
		chunkSize = 0x1000  // 4 KiB per read attempt
		maxLength = 1 << 20 // 1 MiB safety cap
	)

	buf := make([]byte, chunkSize)
	var out []byte
	current := strOffset

	for len(out) < maxLength {
		n, err := f.cr.ReadAt(buf, current)
		if n > 0 {
			nullIdx := bytes.IndexByte(buf[:n], 0)
			if nullIdx >= 0 {
				out = append(out, buf[:nullIdx]...)
				if len(out) == 0 {
					return "", nil
				}
				return string(out), nil
			}
			out = append(out, buf[:n]...)
			current += int64(n)
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("%w at offset %#x", ErrCStringNoTerminator, strOffset)
			}
			continue
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(out) == 0 {
					return "", fmt.Errorf("%w at offset %#x", ErrCStringNotFound, strOffset)
				}
				return "", fmt.Errorf("%w at offset %#x", ErrCStringNoTerminator, strOffset)
			}
			return "", fmt.Errorf("failed to read at offset %#x: %w", current, err)
		}

		break
	}

	if len(out) == 0 {
		return "", fmt.Errorf("%w at offset %#x", ErrCStringNotFound, strOffset)
	}
	return "", fmt.Errorf("%w at offset %#x", ErrCStringNoTerminator, strOffset)
}

// IsCString returns cstring at given virtual address if is in a CstringLiterals section
func (f *File) IsCString(addr uint64) (string, bool) {
	for _, sec := range f.Sections {
		if sec.Flags.IsCstringLiterals() {
			if sec.Addr <= addr && addr < sec.Addr+sec.Size {
				str, err := f.GetCString(addr)
				if err != nil {
					return "", false
				}
				return str, true
			}
		}
	}
	return "", false
}

func (f *File) GetLoadsByName(name string) []Load {
	var loads []Load
	for _, l := range f.Loads {
		if l.Command().Command().String() == name {
			loads = append(loads, l)
		}
	}
	return loads
}

// Segment returns the first Segment with the given name, or nil if no such segment exists.
func (f *File) Segment(name string) *Segment {
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok && s.Name == name {
			return s
		}
	}
	return nil
}

// Segments returns all Segments.
func (f *File) Segments() Segments {
	var segs Segments
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok {
			segs = append(segs, s)
		}
	}
	// sort.Sort(segs)
	return segs
}

// GetSectionsForSegment returns all the segment's sections or nil if it doesn't have any
func (f *File) GetSectionsForSegment(name string) []*types.Section {
	var secs []*types.Section
	if seg := f.Segment(name); seg != nil {
		if seg.Nsect > 0 {
			for i := uint32(0); i < seg.Nsect; i++ {
				if int(i+seg.Firstsect) < len(f.Sections) {
					secs = append(secs, f.Sections[i+seg.Firstsect])
				}
			}
			return secs
		}
	}
	return nil
}

// Section returns the section with the given name in the given segment,
// or nil if no such section exists.
func (f *File) Section(segment, section string) *types.Section {
	for _, sec := range f.Sections {
		if sec.Seg == segment && sec.Name == section {
			return sec
		}
	}
	return nil
}

// FindSegmentForVMAddr returns the segment containing a given virtual memory ddress.
func (f *File) FindSegmentForVMAddr(vmAddr uint64) *Segment {
	if f.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fs := range f.FileSets() {
			if mfe, err := f.GetFileSetFileByName(fs.EntryID); err == nil {
				if seg := mfe.FindSegmentForVMAddr(vmAddr); seg != nil {
					seg.Name = fmt.Sprintf("%s.%s", fs.EntryID, seg.Name)
					return seg
				}
			}
		}
	}
	for _, seg := range f.Segments() {
		if seg.Addr <= vmAddr && vmAddr < seg.Addr+seg.Memsz {
			return seg
		}
	}
	return nil
}

// FindSectionForVMAddr returns the section containing a given virtual memory ddress.
func (f *File) FindSectionForVMAddr(vmAddr uint64) *types.Section {
	if f.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fs := range f.FileSets() {
			if mfe, err := f.GetFileSetFileByName(fs.EntryID); err == nil {
				if sec := mfe.FindSectionForVMAddr(vmAddr); sec != nil {
					sec.Name = fmt.Sprintf("%s.%s", fs.EntryID, sec.Name)
					return sec
				}
			}
		}
	}
	for _, sec := range f.Sections {
		if sec.Addr <= vmAddr && vmAddr < sec.Addr+sec.Size {
			return sec
		}
	}
	return nil
}

// UUID returns the UUID load command, or nil if no UUID exists.
func (f *File) UUID() *UUID {
	for _, l := range f.Loads {
		if u, ok := l.(*UUID); ok {
			return u
		}
	}
	return nil
}

// DylibID returns the dylib ID load command, or nil if no dylib ID exists.
func (f *File) DylibID() *IDDylib {
	for _, l := range f.Loads {
		if s, ok := l.(*IDDylib); ok {
			return s
		}
	}
	return nil
}

// DyldInfo returns the dyld info load command, or nil if no dyld info exists.
func (f *File) DyldInfo() *DyldInfo {
	for _, l := range f.Loads {
		if s, ok := l.(*DyldInfo); ok {
			return s
		}
	}
	return nil
}

// DyldInfoOnly returns the dyld info only load command, or nil if no dyld info only exists.
func (f *File) DyldInfoOnly() *DyldInfoOnly {
	for _, l := range f.Loads {
		if s, ok := l.(*DyldInfoOnly); ok {
			return s
		}
	}
	return nil
}

// SourceVersion returns the source version load command, or nil if no source version exists.
func (f *File) SourceVersion() *SourceVersion {
	for _, l := range f.Loads {
		if s, ok := l.(*SourceVersion); ok {
			return s
		}
	}
	return nil
}

// BuildVersions returns the build version load commands as an array.
func (f *File) BuildVersions() []*BuildVersion {
	var builds []*BuildVersion
	for _, l := range f.Loads {
		if s, ok := l.(*BuildVersion); ok {
			builds = append(builds, s)
		}
	}
	return builds
}

// VersionMin returns the minimum-version load command, or nil if no minimum-version exists.
func (f *File) VersionMin() *VersionMin {
	for _, l := range f.Loads {
		switch s := l.(type) {
		case *VersionMinMacOSX:
			return &s.VersionMin
		case *VersionMinTvOS:
			return &s.VersionMin
		case *VersionMinWatchOS:
			return &s.VersionMin
		case *VersionMiniPhoneOS:
			return &s.VersionMin
		}
	}
	return nil
}

// FileSets returns an array of Fileset entries.
func (f *File) FileSets() []*FilesetEntry {
	var fsets []*FilesetEntry
	for _, l := range f.Loads {
		if fs, ok := l.(*FilesetEntry); ok {
			fsets = append(fsets, fs)
		}
	}
	return fsets
}

// GetFileSetFileByName returns the Fileset MachO for a given name.
func (f *File) GetFileSetFileByName(name string) (*File, error) {
	for _, l := range f.Loads {
		if fs, ok := l.(*FilesetEntry); ok {
			if strings.EqualFold(fs.EntryID, name) || strings.HasSuffix(strings.ToLower(fs.EntryID), strings.ToLower(name)) {
				child, err := NewFile(io.NewSectionReader(f.sr, int64(fs.FileOffset), 1<<63-1), FileConfig{
					Offset:        int64(fs.FileOffset),
					SectionReader: f.sr,
					CacheReader:   f.cr,
					VMAddrConverter: types.VMAddrConverter{
						Converter:    f.convertToVMAddr,
						VMAddr2Offet: f.GetOffset,
						Offet2VMAddr: f.GetVMAddress,
					},
				})
				if err != nil {
					return nil, err
				}
				if err := f.copyKernelCacheBasesTo(child); err != nil {
					_ = child.Close()
					return nil, err
				}
				return child, nil
			}
		}
	}
	return nil, fmt.Errorf("fileset does NOT contain %s", name)
}

// DataInCode returns the LC_DATA_IN_CODE, or nil if none exists.
func (f *File) DataInCode() *DataInCode {
	for _, l := range f.Loads {
		if s, ok := l.(*DataInCode); ok {
			return s
		}
	}
	return nil
}

// FunctionStarts returns the function starts array, or nil if none exists.
func (f *File) FunctionStarts() *FunctionStarts {
	for _, l := range f.Loads {
		if s, ok := l.(*FunctionStarts); ok {
			return s
		}
	}
	return nil
}

// FunctionVariants returns the LC_FUNCTION_VARIANTS load command, or nil if none exists.
func (f *File) FunctionVariants() *FunctionVariants {
	for _, l := range f.Loads {
		if fv, ok := l.(*FunctionVariants); ok {
			return fv
		}
	}
	return nil
}

// FunctionVariantFixups returns the LC_FUNCTION_VARIANT_FIXUPS load command, or nil if none exists.
func (f *File) FunctionVariantFixups() *FunctionVariantFixups {
	for _, l := range f.Loads {
		if fv, ok := l.(*FunctionVariantFixups); ok {
			return fv
		}
	}
	return nil
}

// GetFunctionVariants parses and returns the function variants data.
func (f *File) GetFunctionVariants() (*types.FuncVarData, error) {
	fv := f.FunctionVariants()
	if fv == nil {
		return nil, fmt.Errorf("LC_FUNCTION_VARIANTS not found")
	}

	// Return cached data if already parsed
	if fv.Data != nil {
		f.resolveFunctionVariantSymbolsIfParsed(fv)
		return fv.Data, nil
	}

	// Size comes from an untrusted load command. Read incrementally so a tiny
	// malformed file cannot force a multi-gigabyte allocation before the short
	// read is detected.
	data, err := saferio.ReadDataAt(f.cr, uint64(fv.Size), int64(fv.Offset))
	if err != nil {
		return nil, fmt.Errorf("failed to read function variants data: %v", err)
	}

	// Parse the data
	parsed, err := ParseFunctionVariants(data, f.ByteOrder)
	if err != nil {
		return nil, err
	}

	// Cache the parsed data
	fv.Data = parsed

	f.resolveFunctionVariantSymbolsIfParsed(fv)

	return parsed, nil
}

// GetFunctionVariantFixups parses and returns the function variant fixups data.
func (f *File) GetFunctionVariantFixups() (*types.FuncVarFixupsData, error) {
	fv := f.FunctionVariantFixups()
	if fv == nil {
		return nil, fmt.Errorf("LC_FUNCTION_VARIANT_FIXUPS not found")
	}

	// Return cached data if already parsed
	if fv.Data != nil {
		return fv.Data, nil
	}

	// Size comes from an untrusted load command; see GetFunctionVariants.
	data, err := saferio.ReadDataAt(f.cr, uint64(fv.Size), int64(fv.Offset))
	if err != nil {
		return nil, fmt.Errorf("failed to read function variant fixups data: %v", err)
	}

	// Parse the data
	parsed, err := ParseFunctionVariantFixups(data, f.ByteOrder)
	if err != nil {
		return nil, err
	}

	// Cache the parsed data
	fv.Data = parsed

	return parsed, nil
}

// LazyLoadDylibInfos returns all LC_LAZY_LOAD_DYLIB_INFO load commands.
// A single binary may carry many of these, so this returns a slice (nil if none).
func (f *File) LazyLoadDylibInfos() []*LazyLoadDylibInfo {
	var lazies []*LazyLoadDylibInfo
	for _, l := range f.Loads {
		if ll, ok := l.(*LazyLoadDylibInfo); ok {
			lazies = append(lazies, ll)
		}
	}
	return lazies
}

// GetLazyLoadedDylibs decodes the payloads of all LC_LAZY_LOAD_DYLIB_INFO load
// commands, caching the result on each command's Data field. It returns the
// successfully decoded payloads in load-command order; a malformed payload is
// skipped and its error joined into the returned error so valid siblings still
// decode. It returns (nil, nil) when the binary has no such commands.
func (f *File) GetLazyLoadedDylibs() ([]*LazyLoadedDylib, error) {
	f.lazyLoadMu.Lock()
	defer f.lazyLoadMu.Unlock()

	infos := f.LazyLoadDylibInfos()
	if len(infos) == 0 {
		return nil, nil
	}

	dylibs := make([]*LazyLoadedDylib, 0, len(infos))
	var errs []error
	for _, ll := range infos {
		// Return cached data if already parsed
		if ll.Data != nil {
			dylibs = append(dylibs, ll.Data)
			continue
		}

		// Read the payload data
		data, err := saferio.ReadDataAt(f.cr, uint64(ll.Size), int64(ll.Offset))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read lazy load dylib info data at offset %#x: %v", ll.Offset, err))
			continue
		}

		// Parse the data
		parsed, err := ParseLazyLoadDylibInfo(data, f.ByteOrder)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := f.validateLazyLoadImageOffsets(parsed); err != nil {
			errs = append(errs, err)
			continue
		}

		// Walk the fixup chain before publishing the cache. A partially decoded
		// object must not turn a failed first call into a successful cached call.
		if err := f.walkLazyLoadChain(parsed); err != nil {
			errs = append(errs, err)
			continue
		}

		// Cache the parsed data
		ll.Data = parsed
		dylibs = append(dylibs, parsed)
	}

	if len(errs) > 0 {
		return dylibs, errors.Join(errs...)
	}
	return dylibs, nil
}

// lazyLoadMaxVMOffset mirrors dyld's image-relative validation range for
// LazyLoadDylibLinkEdit. __LINKEDIT does not hold the flag or fixup chain, and
// __PAGEZERO-style segments below the preferred load address have no unsigned
// runtime offset in this image.
func (f *File) lazyLoadMaxVMOffset() (uint64, error) {
	base := f.GetBaseAddress()
	maxVMOffset := uint64(0x4000)
	for _, segment := range f.Segments() {
		if segment == nil || segment.Name == "__LINKEDIT" || segment.Addr < base {
			continue
		}
		runtimeOffset := segment.Addr - base
		if segment.Memsz > math.MaxUint64-runtimeOffset {
			return 0, fmt.Errorf("lazy load segment %s runtime range %#x+%#x overflows", segment.Name, runtimeOffset, segment.Memsz)
		}
		if end := runtimeOffset + segment.Memsz; end > maxVMOffset {
			maxVMOffset = end
		}
	}
	return maxVMOffset, nil
}

func (f *File) validateLazyLoadImageOffsets(lld *LazyLoadedDylib) error {
	if lld == nil {
		return errors.New("nil lazy load dylib info")
	}
	maxVMOffset, err := f.lazyLoadMaxVMOffset()
	if err != nil {
		return err
	}
	if uint64(lld.FlagImageOffset) > maxVMOffset {
		return fmt.Errorf("lazy load dylib %q: flag image offset %#x exceeds max VM offset %#x", lld.LoadPath, lld.FlagImageOffset, maxVMOffset)
	}
	if uint64(lld.ChainStartImageOffset) > maxVMOffset {
		return fmt.Errorf("lazy load dylib %q: chain start image offset %#x exceeds max VM offset %#x", lld.LoadPath, lld.ChainStartImageOffset, maxVMOffset)
	}
	return nil
}

// walkLazyLoadChain follows the chained-pointer fixup chain at
// lld.ChainStartImageOffset, appending each bound slot to lld.Fixups and
// resolving its ordinal to lld.Symbols. The chain lives in the image (not the
// __LINKEDIT blob) and is encoded per lld.PointerFormat.
func (f *File) walkLazyLoadChain(lld *LazyLoadedDylib) error {
	if lld.ChainStartImageOffset == 0 {
		return nil
	}
	step, ok := fixupchains.Stride(lld.PointerFormat)
	if !ok {
		return fmt.Errorf("lazy load dylib %q: unsupported pointer format %s", lld.LoadPath, lld.PointerFormat)
	}

	base := f.GetBaseAddress()
	imgOff := uint64(lld.ChainStartImageOffset)
	maxVMOffset, err := f.lazyLoadMaxVMOffset()
	if err != nil {
		return err
	}
	var buf [8]byte
	const maxChain = 1 << 20 // guard against a malformed/cyclic chain
	for i := 0; i < maxChain; i++ {
		if imgOff > maxVMOffset {
			return fmt.Errorf("lazy load dylib %q: chain offset %#x exceeds max VM offset %#x", lld.LoadPath, imgOff, maxVMOffset)
		}
		if base > math.MaxUint64-imgOff {
			return fmt.Errorf("lazy load dylib %q: base %#x plus chain offset %#x overflows", lld.LoadPath, base, imgOff)
		}
		vmaddr := base + imgOff
		fileOff, err := f.GetOffset(vmaddr)
		if err != nil {
			return fmt.Errorf("lazy load dylib %q: map chain offset %#x: %v", lld.LoadPath, imgOff, err)
		}
		n, readErr := f.cr.ReadAtAddr(buf[:], vmaddr)
		if n != len(buf) {
			if readErr == nil {
				readErr = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("lazy load dylib %q: read chain at vmaddr %#x (file offset %#x): %v", lld.LoadPath, vmaddr, fileOff, readErr)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("lazy load dylib %q: read chain at vmaddr %#x (file offset %#x): %v", lld.LoadPath, vmaddr, fileOff, readErr)
		}
		raw := f.ByteOrder.Uint64(buf[:])

		fixup, next, err := decodeLazyLoadFixup(lld.PointerFormat, raw, vmaddr, fileOff, lld.Symbols)
		if err != nil {
			return fmt.Errorf("lazy load dylib %q: %v", lld.LoadPath, err)
		}
		if fixup != nil {
			lld.Fixups = append(lld.Fixups, *fixup)
		}
		if next == 0 {
			return nil
		}
		advance := next * step
		if imgOff > math.MaxUint64-advance {
			return fmt.Errorf("lazy load dylib %q: chain offset %#x plus advance %#x overflows", lld.LoadPath, imgOff, advance)
		}
		imgOff += advance
	}
	return fmt.Errorf("lazy load dylib %q: fixup chain exceeded %d entries (malformed?)", lld.LoadPath, maxChain)
}

// decodeLazyLoadFixup decodes a single chained-pointer slot. It returns the
// decoded bind (nil for a rebase slot, which carries no symbol), the chain's
// raw next delta, and an error for unsupported formats.
func decodeLazyLoadFixup(format fixupchains.DCPtrKind, raw, vmaddr, fileOff uint64, symbols []string) (*LazyLoadFixup, uint64, error) {
	resolve := func(ordinal uint64) (string, error) {
		if ordinal >= uint64(len(symbols)) {
			return "", fmt.Errorf("lazy bind ordinal %d exceeds symbol count %d", ordinal, len(symbols))
		}
		return symbols[ordinal], nil
	}

	switch format {
	case fixupchains.DYLD_CHAINED_PTR_ARM64E,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_KERNEL,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		next := fixupchains.DcpArm64eNext(raw)
		if !fixupchains.DcpArm64eIsBind(raw) {
			return nil, next, nil // rebase slot, not a symbol bind
		}
		is24 := format == fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24
		fixup := &LazyLoadFixup{Address: vmaddr, Offset: fileOff}
		switch {
		case fixupchains.DcpArm64eIsAuth(raw) && is24:
			b := fixupchains.DyldChainedPtrArm64eAuthBind24{Pointer: raw}
			fixup.Ordinal = uint32(b.Ordinal())
			fixup.Auth, fixup.Key, fixup.AddrDiv, fixup.Diversity = true, uint8(b.Key()), b.AddrDiv() != 0, uint16(b.Diversity())
		case fixupchains.DcpArm64eIsAuth(raw):
			b := fixupchains.DyldChainedPtrArm64eAuthBind{Pointer: raw}
			fixup.Ordinal = uint32(b.Ordinal())
			fixup.Auth, fixup.Key, fixup.AddrDiv, fixup.Diversity = true, uint8(b.Key()), b.AddrDiv() != 0, uint16(b.Diversity())
		case is24:
			fixup.Ordinal = uint32(fixupchains.DyldChainedPtrArm64eBind24{Pointer: raw}.Ordinal())
		default:
			fixup.Ordinal = uint32(fixupchains.DyldChainedPtrArm64eBind{Pointer: raw}.Ordinal())
		}
		var err error
		fixup.Symbol, err = resolve(uint64(fixup.Ordinal))
		if err != nil {
			return nil, 0, err
		}
		return fixup, next, nil
	case fixupchains.DYLD_CHAINED_PTR_64,
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET:
		next := fixupchains.Generic64Next(raw)
		if !fixupchains.Generic64IsBind(raw) {
			return nil, next, nil
		}
		b := fixupchains.DyldChainedPtr64Bind{Pointer: raw}
		symbol, err := resolve(b.Ordinal())
		if err != nil {
			return nil, 0, err
		}
		return &LazyLoadFixup{Address: vmaddr, Offset: fileOff, Ordinal: uint32(b.Ordinal()), Symbol: symbol}, next, nil
	default:
		return nil, 0, fmt.Errorf("unsupported pointer format %s for lazy load fixup chain", format)
	}
}

// Enrich pre-parses optional data to add detail to load command stringers/JSON.
// It is best-effort; any encountered errors are returned as a joined error.
func (f *File) Enrich() error {
	var errs []error

	if f.DyldExportsTrie() != nil {
		if _, err := f.DyldExports(); err != nil {
			errs = append(errs, err)
		}
	}

	if f.FunctionVariants() != nil {
		if _, err := f.GetFunctionVariants(); err != nil {
			errs = append(errs, err)
		}
	}

	if f.FunctionVariantFixups() != nil {
		if _, err := f.GetFunctionVariantFixups(); err != nil {
			errs = append(errs, err)
		}
	}

	if _, err := f.GetLazyLoadedDylibs(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (f *File) resolveFunctionVariantSymbolsIfParsed(fv *FunctionVariants) {
	if fv == nil || fv.Data == nil || len(fv.Data.Tables) == 0 {
		return
	}
	parsedExports := f.parsedDyldExports()
	if f.Symtab == nil && parsedExports == nil {
		return
	}

	addrToName := make(map[uint64]string)
	if f.Symtab != nil {
		addrToName = make(map[uint64]string, len(f.Symtab.Syms))
		for _, sym := range f.Symtab.Syms {
			if _, ok := addrToName[sym.Value]; !ok {
				addrToName[sym.Value] = sym.Name
			}
		}
	}
	if parsedExports != nil {
		for _, exp := range parsedExports {
			if _, ok := addrToName[exp.Address]; !ok {
				addrToName[exp.Address] = exp.Name
			}
		}
	}

	if len(addrToName) == 0 {
		return
	}
	for i := range fv.Data.Tables {
		for j := range fv.Data.Tables[i].Entries {
			entry := &fv.Data.Tables[i].Entries[j]
			if entry.IsTableIndex() || entry.Symbol != "" {
				continue
			}
			implOffset := uint64(entry.ImplValue())
			base := f.preferredLoadAddress()
			if implOffset > ^uint64(0)-base {
				continue
			}
			if name, ok := addrToName[base+implOffset]; ok {
				entry.Symbol = name
			}
		}
	}
}

// cachedFunctions returns the function list GetFunctions or
// GenerateFunctionStarts published, if any.
func (f *File) cachedFunctions() []types.Function {
	f.functionsMu.Lock()
	defer f.functionsMu.Unlock()
	return f.functions
}

// publishFunctions caches funcs unless another call published a list first,
// and returns the list every caller now sees.
func (f *File) publishFunctions(funcs []types.Function) []types.Function {
	f.functionsMu.Lock()
	defer f.functionsMu.Unlock()
	if len(f.functions) == 0 {
		f.functions = funcs
	}
	return f.functions
}

func (f *File) GenerateFunctionStarts() ([]types.Function, error) {
	if funcs := f.cachedFunctions(); len(funcs) > 0 {
		return funcs, nil
	}

	if !f.isArm64e() {
		return nil, ErrMachOArchNotSupported
	}

	var funcs []types.Function

	text := f.Section("__TEXT", "__text")
	if text == nil {
		text = f.Section("__TEXT_EXEC", "__text")
		if text == nil {
			return nil, ErrMachOSectionNotFound
		}
	}
	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __text section data: %v", err)
	}

	instructions := make([]uint32, len(data)/binary.Size(uint32(0)))
	if err := binary.Read(bytes.NewReader(data), f.ByteOrder, &instructions); err != nil {
		return nil, fmt.Errorf("failed to read __text section data: %v", err)
	}

	// find function starts by looking for the instruction 0xe320f000
	for idx, instr := range instructions {
		if instr == 0xd503237f {
			funcs = append(funcs, types.Function{
				StartAddr: text.Addr + uint64(idx*4),
			})
		}
	}
	if len(funcs) == 0 {
		return nil, fmt.Errorf("failed to find any function starts by searching for 'pacibsp' prologues")
	}
	// set end addresses
	for i := 0; i < len(funcs)-1; i++ {
		funcs[i].EndAddr = funcs[i+1].StartAddr
	}
	funcs[len(funcs)-1].EndAddr = Align(text.Addr+text.Size, uint64(text.Align))

	return f.publishFunctions(funcs), nil
}

// GetFunctions returns the function array, or nil if none exists.
func (f *File) GetFunctions(data ...byte) []types.Function {

	if funcs := f.cachedFunctions(); len(funcs) > 0 {
		return funcs
	}

	var funcs []types.Function

	fs := f.FunctionStarts()
	if fs == nil {
		if fs, err := f.GenerateFunctionStarts(); err == nil {
			return fs
		}
		return nil
	}

	var fsr *bytes.Reader
	if len(data) > 0 {
		fsr = bytes.NewReader(data)
	} else {
		ldat, err := readDataAt(f.cr, uint64(fs.Size), int64(fs.Offset))
		if err != nil {
			return nil
		}
		fsr = bytes.NewReader(ldat)
	}

	offset, err := trie.ReadUleb128(fsr)
	if err != nil {
		return nil
	}

	startVMA := offset + f.GetBaseAddress()

	for {
		offset, err = trie.ReadUleb128(fsr)
		if err == io.EOF {
			break
		}
		if offset == 0 {
			break
		}
		if err != nil {
			return nil
		}

		funcs = append(funcs, types.Function{
			StartAddr: startVMA,
			EndAddr:   startVMA + offset,
		})

		startVMA += offset
	}

	// get last function
	if s := f.FindSectionForVMAddr(startVMA); s != nil {
		funcs = append(funcs, types.Function{
			StartAddr: startVMA,
			EndAddr:   s.Addr + s.Size,
		})
	}

	// cache parsed functions
	return f.publishFunctions(funcs)
}

// GetFunctionForVMAddr returns the function containing a given virual address
func (f *File) GetFunctionForVMAddr(addr uint64) (types.Function, error) {
	for _, fn := range f.GetFunctions() {
		if addr >= fn.StartAddr && addr < fn.EndAddr {
			return fn, nil
		}
	}
	return types.Function{}, fmt.Errorf("address %#016x not in any function", addr)
}

// GetFunctionsForRange returns the functions contained in a given virual address range
func (f *File) GetFunctionsForRange(start, end uint64) ([]types.Function, error) {
	var funcs []types.Function
	for _, fn := range f.GetFunctions() {
		if start >= fn.StartAddr && fn.StartAddr < end {
			funcs = append(funcs, fn)
		}
	}
	return funcs, nil
}

func (f *File) GetFunctionData(fn types.Function) ([]byte, error) {
	if fn.EndAddr <= fn.StartAddr {
		return nil, fmt.Errorf("invalid function range %#x - %#x", fn.StartAddr, fn.EndAddr)
	}
	data := make([]byte, fn.EndAddr-fn.StartAddr)
	if _, err := f.cr.ReadAtAddr(data, fn.StartAddr); err != nil {
		return nil, fmt.Errorf("failed to read data at address %#x: %v", fn.StartAddr, err)
	}
	return data, nil
}

// CodeSignature returns the code signature, or nil if none exists.
func (f *File) CodeSignature() *CodeSignature {
	for _, l := range f.Loads {
		if s, ok := l.(*CodeSignature); ok {
			return s
		}
	}
	return nil
}

// DyldExportsTrie returns the dyld export trie load command, or nil if no dyld info exists.
func (f *File) DyldExportsTrie() *DyldExportsTrie {
	for _, l := range f.Loads {
		if s, ok := l.(*DyldExportsTrie); ok {
			return s
		}
	}
	return nil
}

// DyldExports returns the dyld export trie symbols
func (f *File) GetDyldExport(symbol string) (*trie.TrieExport, error) {
	if dxt := f.DyldExportsTrie(); dxt == nil {
		return nil, fmt.Errorf("macho does not contain LC_DYLD_EXPORTS_TRIE")
	} else {
		var err error
		var r *bytes.Reader
		f.expMu.Lock()
		data := f.exptrieData
		f.expMu.Unlock()
		if data != nil {
			r = bytes.NewReader(data)
		} else {
			data, err := saferio.ReadDataAt(f.cr, uint64(dxt.Size), int64(dxt.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s data at offset=%#x; %v", types.LC_DYLD_EXPORTS_TRIE, int64(dxt.Offset), err)
			}
			f.expMu.Lock()
			f.exptrieData = data
			f.expMu.Unlock()
			r = bytes.NewReader(data)
		}
		if _, err = trie.WalkTrie(r, symbol); err != nil {
			return nil, err
		}
		return trie.ReadExport(r, symbol, f.preferredLoadAddress())
	}
}

// parsedDyldExports returns the LC_DYLD_EXPORTS_TRIE parse DyldExports has
// published, if any.
func (f *File) parsedDyldExports() []trie.TrieExport {
	f.expMu.Lock()
	defer f.expMu.Unlock()
	return f.exp
}

// DyldExports returns the dyld export trie symbols
func (f *File) DyldExports() ([]trie.TrieExport, error) {
	if exp := f.parsedDyldExports(); exp != nil {
		return exp, nil
	}
	if dxt := f.DyldExportsTrie(); dxt != nil {
		if dxt.Size == 0 {
			return []trie.TrieExport{}, nil
		}
		data, err := saferio.ReadDataAt(f.cr, uint64(dxt.Size), int64(dxt.Offset))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s data at offset=%#x; %v", types.LC_DYLD_EXPORTS_TRIE, int64(dxt.Offset), err)
		}
		exp, err := trie.ParseTrieExports(bytes.NewReader(data), f.GetBaseAddress())
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %v", types.LC_DYLD_EXPORTS_TRIE, err)
		}
		// Two concurrent first calls parse the same bytes; keep the first
		// published slice so that everybody (and the export lookup indexes,
		// which are keyed by slice identity) sees one value.
		f.expMu.Lock()
		if f.exp == nil {
			f.exp = exp
		}
		exp = f.exp
		f.expMu.Unlock()
		return exp, nil
	}

	return nil, fmt.Errorf("macho does not contain LC_DYLD_EXPORTS_TRIE")
}

// HasFixups reports whether the Mach-O contains chained or classic dyld fixup metadata.
func (f *File) HasFixups() bool {
	return f.HasDyldChainedFixups() || f.HasDyldInfo() || f.HasDyldInfoOnly()
}

func (f *File) HasDyldChainedFixups() bool {
	for _, l := range f.Loads {
		if _, ok := l.(*DyldChainedFixups); ok {
			return true
		}
	}
	return false
}

// HasDyldInfo reports whether the Mach-O contains an LC_DYLD_INFO load command.
func (f *File) HasDyldInfo() bool {
	return f.DyldInfo() != nil
}

// HasDyldInfoOnly reports whether the Mach-O contains an LC_DYLD_INFO_ONLY load command.
func (f *File) HasDyldInfoOnly() bool {
	return f.DyldInfoOnly() != nil
}

// DyldChainedFixups returns the dyld chained fixups.
func (f *File) DyldChainedFixups() (*fixupchains.DyldChainedFixups, error) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	return f.dyldChainedFixupsLocked()
}

func (f *File) dyldChainedFixupsLocked() (*fixupchains.DyldChainedFixups, error) {
	if f.dcf != nil { // is cached
		return f.dcf, nil
	}

	for _, l := range f.Loads {
		if dcfLC, ok := l.(*DyldChainedFixups); ok {
			data, err := saferio.ReadDataAt(f.cr, uint64(dcfLC.Size), int64(dcfLC.Offset))
			if err != nil {
				return nil, fmt.Errorf("failed to read DyldChainedFixups data at offset=%#x; %v", int64(dcfLC.Offset), err)
			}
			dcf := fixupchains.NewChainedFixups(bytes.NewReader(data), &f.cr, f.ByteOrder)
			if f.sharedCacheBaseSet {
				dcf.SetSharedCacheBaseAddress(f.sharedCacheBase)
			}
			if err := dcf.ParseStarts(); err != nil {
				return nil, fmt.Errorf("failed to parse dyld chained fixup starts: %v", err)
			}
			segs := f.Segments()
			if len(dcf.Starts) > len(segs) {
				return nil, fmt.Errorf("dyld chained fixups segment count %d exceeds Mach-O segment count %d", len(dcf.Starts), len(segs))
			}
			if len(dcf.Starts) != len(segs) {
				// Post-link tools such as ctf_insert may insert one or more zero-VM-size
				// segments immediately before __LINKEDIT without rebuilding the starts
				// table. Apple validates the structural zero-size condition, not a
				// particular segment name.
				linkeditIndex := -1
				for idx, segment := range segs {
					if segment != nil && segment.Name == "__LINKEDIT" {
						linkeditIndex = idx
						break
					}
				}
				missing := len(segs) - len(dcf.Starts)
				validInsertion := linkeditIndex >= missing
				for idx := linkeditIndex - 1; validInsertion && idx >= linkeditIndex-missing; idx-- {
					validInsertion = segs[idx] != nil && segs[idx].Memsz == 0
				}
				if !validInsertion {
					return nil, fmt.Errorf("dyld chained fixups segment count %d does not match Mach-O segment count %d", len(dcf.Starts), len(segs))
				}
			}
			for idx := range dcf.Starts {
				start := &dcf.Starts[idx]
				if start.PageStarts == nil {
					continue
				}
				if got, want := fixupchains.PointerSize(start.PointerFormat), int(f.pointerSize()); got != want {
					return nil, fmt.Errorf("dyld chained fixups segment %d pointer format %s uses %d-byte pointers in a %d-byte Mach-O", idx, start.PointerFormat, got, want)
				}
			}
			var maxValidPointer uint32
			for idx := range dcf.Starts {
				if value := dcf.Starts[idx].MaxValidPointer; value != 0 {
					maxValidPointer = value
					break
				}
			}
			if maxValidPointer != 0 {
				lastDataIndex := len(segs) - 1
				if lastDataIndex >= 0 && segs[lastDataIndex] != nil && segs[lastDataIndex].Name == "__LINKEDIT" {
					lastDataIndex--
				}
				if lastDataIndex < 0 || segs[lastDataIndex] == nil {
					return nil, errors.New("dyld chained fixups max_valid_pointer has no data segment to validate")
				}
				lastData := segs[lastDataIndex]
				if lastData.Addr > math.MaxUint64-lastData.Memsz {
					return nil, fmt.Errorf("segment %s VM range %#x+%#x overflows", lastData.Name, lastData.Addr, lastData.Memsz)
				}
				lastVMAddress := lastData.Addr + lastData.Memsz
				if uint64(maxValidPointer) < lastVMAddress {
					return nil, fmt.Errorf("dyld chained fixups max_valid_pointer %#x is below last data VM address %#x", maxValidPointer, lastVMAddress)
				}
			}
			for level := range f.kernelCacheBases {
				if f.kernelCacheBaseSet[level] {
					if err := dcf.SetKernelCacheBaseAddress(uint8(level), f.kernelCacheBases[level]); err != nil {
						return nil, err
					}
				}
			}
			if !f.kernelCacheBaseSet[0] {
				if base, ok := f.effectiveKernelCacheLevelZeroSegmentAddress(); ok {
					dcf.SetKernelCacheLevelZeroSegmentAddress(base)
				}
			}
			preferredLoadAddress := f.GetBaseAddress()
			for idx, start := range dcf.Starts {
				segment := segs[idx]
				if segment.Addr >= preferredLoadAddress {
					dcf.Starts[idx].SegmentVMOffset = segment.Addr - preferredLoadAddress
				} else {
					// __PAGEZERO precedes the preferred load address and has no
					// representable unsigned runtime offset or fixup targets.
					dcf.Starts[idx].SegmentVMOffset = 0
				}
				if start.PageStarts != nil {
					// Replacing SegmentOffset(vmaddr) with FileOffset
					// (for static analysis of binaries with split segs
					// since we aren't actually loading the MachO
					// ref: void Adjustor<P>::adjustChainedFixups() in
					// dyld-750.6/dyld3/shared-cache/AdjustDylibSegments.cpp
					dcf.Starts[idx].SegmentOffset = segment.Offset
				}
			}
			dcf.ResetSegmentIndex()
			// Complete the chain walk before publishing dcf. Its public lookup
			// methods can then read immutable maps/slices after the File lock is
			// released.
			if _, err := dcf.Parse(); err != nil {
				return nil, fmt.Errorf("failed to parse dyld chained fixups: %v", err)
			}
			// The first Mach-O segment commonly has no starts record. ParseStarts
			// records the first actual pointer format rather than assuming Starts[0]
			// is populated.
			f.vma.ChainedPointerFormat = uint16(dcf.PointerFormat)

			f.dcf = dcf // cache

			return dcf, nil
		}
	}
	return nil, fmt.Errorf("macho does not contain LC_DYLD_CHAINED_FIXUPS")
}

func (f *File) ForEachV2SplitSegReference(handler func(fromSectionIndex, fromSectionOffset, toSectionIndex, toSectionOffset uint64, kind types.SplitInfoKind)) error {
	for _, l := range f.Loads {
		if si, ok := l.(*SplitInfo); ok {
			if si.Size == 0 {
				return nil
			}
			data := make([]byte, si.Size)
			if _, err := f.cr.ReadAt(data, int64(si.Offset)); err != nil {
				return fmt.Errorf("failed to read %s data at offset=%#x; %v", types.LC_SEGMENT_SPLIT_INFO, int64(si.Offset), err)
			}

			r := bytes.NewReader(data)

			var version uint8
			if err := binary.Read(r, f.ByteOrder, &version); err != nil {
				return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO Version: %v", err)
			}
			if version != types.DYLD_CACHE_ADJ_V2_FORMAT {
				return nil
			}

			sectionCount, err := trie.ReadUleb128(r)
			if err != nil {
				return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO SectionCount: %v", err)
			}

			for i := uint64(0); i < sectionCount; i++ {
				fromSectionIndex, err := trie.ReadUleb128(r)
				if err != nil {
					return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO fromSectionIndex: %v", err)
				}
				toSectionIndex, err := trie.ReadUleb128(r)
				if err != nil {
					return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO toSectionIndex: %v", err)
				}
				toOffsetCount, err := trie.ReadUleb128(r)
				if err != nil {
					return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO toOffsetCount: %v", err)
				}

				var toSectionOffset uint64
				for j := uint64(0); j < toOffsetCount; j++ {
					toSectionDelta, err := trie.ReadUleb128(r)
					if err != nil {
						return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO toSectionDelta: %v", err)
					}
					fromOffsetCount, err := trie.ReadUleb128(r)
					if err != nil {
						return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO fromOffsetCount: %v", err)
					}

					toSectionOffset += toSectionDelta
					for k := uint64(0); k < fromOffsetCount; k++ {
						kind, err := trie.ReadUleb128(r)
						if err != nil {
							return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO kind: %v", err)
						}
						if kind > 13 {
							return fmt.Errorf("invalid LC_SEGMENT_SPLIT_INFO kind: %d", kind)
						}

						fromSectDeltaCount, err := trie.ReadUleb128(r)
						if err != nil {
							return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO fromSectDeltaCount: %v", err)
						}

						var fromSectionOffset uint64
						for l := uint64(0); l < fromSectDeltaCount; l++ {
							delta, err := trie.ReadUleb128(r)
							if err != nil {
								return fmt.Errorf("failed to read LC_SEGMENT_SPLIT_INFO delta: %v", err)
							}

							fromSectionOffset += delta

							handler(fromSectionIndex, fromSectionOffset, toSectionIndex, toSectionOffset, types.SplitInfoKind(kind))
						}
					}
				}
			}
		}
	}
	return nil
}

func (f *File) GetEmbeddedInfoPlist() ([]byte, error) {
	infoSec := f.Section("__TEXT", "__info_plist")
	if infoSec == nil {
		return nil, fmt.Errorf("no __TEXT.__info_plist section")
	}
	data, err := infoSec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __TEXT.__info_plist section data: %v", err)
	}
	return data, nil
}

const (
	BitcodeWrapperMagic = 0x0b17c0de
	RawBitcodeMagic     = 0xdec04342 // 'BC' 0xc0de
)

type BitstreamWrapperHeader struct {
	Magic   uint32
	Version uint32
	Offset  uint32
	Size    uint32
	CPUType uint32
}

func (f *File) GetEmbeddedLLVMBitcode() (*xar.Reader, error) {
	llvmBundle := f.Section("__LLVM", "__bundle")
	if llvmBundle == nil {
		return nil, fmt.Errorf("no %s.%s section", "__LLVM", "__bundle")
	}
	data, err := llvmBundle.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read %s.%s section data: %v", llvmBundle.Seg, llvmBundle.Name, err)
	}
	return xar.NewReader(bytes.NewReader(data), int64(len(data)))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create xar reader: %v", err)
	// }

	// if xr.HasSignature() {
	// 	fmt.Println(xr.Certificates)
	// }

	// for _, xf := range xr.File {
	// 	fmt.Printf("name: %s, type: %v, info: %v, valid_checksum: %t\n", xf.Name, xf.Type, xf.Info, xf.VerifyChecksum())
	// 	f, err := xf.Open()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to open xar file: %v", err)
	// 	}
	// 	data, err := io.ReadAll(f)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read xar file: %v", err)
	// 	}
	// 	var header BitstreamWrapperHeader
	// 	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &header); err != nil {
	// 		return nil, fmt.Errorf("failed to read bitstream wrapper header: %v", err)
	// 	}
	// 	_ = header
	// 	os.WriteFile(xf.Name, data, 0644)
	// 	f.Close()
	// }
}

// DWARF returns the DWARF debug information for the Mach-O file.
func (f *File) DWARF() (*dwarf.Data, error) {
	dwarfSuffix := func(s *types.Section) string {
		sectname := s.Name
		var pfx int
		switch {
		case strings.HasPrefix(sectname, "__debug_"):
			pfx = 8
		case strings.HasPrefix(sectname, "__zdebug_"):
			pfx = 9
		default:
			return ""
		}
		// Mach-O executables truncate section names to 16 characters, mangling some DWARF sections.
		// As of DWARFv5 these are the only problematic section names (see DWARFv5 Appendix G).
		for _, longname := range []string{
			"__debug_str_offsets",
			"__zdebug_line_str",
			"__zdebug_loclists",
			"__zdebug_pubnames",
			"__zdebug_pubtypes",
			"__zdebug_rnglists",
			"__zdebug_str_offsets",
		} {
			if sectname == longname[:16] {
				sectname = longname
				break
			}
		}
		return sectname[pfx:]
	}
	appleSuffix := func(s *types.Section) string {
		switch {
		case strings.HasPrefix(s.Name, "__apple_"):
			return s.Name[8:]
		default:
			return ""
		}
	}
	sectionData := func(s *types.Section) ([]byte, error) {
		b, err := s.Data()
		if err != nil && uint64(len(b)) < s.Size {
			return nil, err
		}

		if len(b) >= 12 && string(b[:4]) == "ZLIB" {
			dlen := binary.BigEndian.Uint64(b[4:12])
			r, err := zlib.NewReader(bytes.NewBuffer(b[12:]))
			if err != nil {
				return nil, err
			}
			// dlen is untrusted: only allocate what the stream really inflates to.
			var dbuf []byte
			if dlen < safeAllocChunk {
				dbuf = make([]byte, dlen)
				if _, err := io.ReadFull(r, dbuf); err != nil {
					return nil, err
				}
			} else if dbuf, err = saferio.ReadData(r, dlen); err != nil {
				return nil, err
			}
			if err := r.Close(); err != nil {
				return nil, err
			}
			b = dbuf
		}
		return b, nil
	}

	// There are many other DWARF sections, but these
	// are the ones the debug/dwarf package uses.
	// Don't bother loading others.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections and DWARF5 sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; ok {
			// Already handled.
			continue
		}

		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}

		if suffix == "types" {
			err = d.AddTypes(fmt.Sprintf("types-%d", i), b)
		} else if suffix == "names" {
			if err := d.AddNames(suffix, b); err != nil {
				return nil, err
			}
		} else {
			err = d.AddSection(".debug_"+suffix, b)
		}
		if err != nil {
			return nil, err
		}
	}

	// Look for Apple HASH table .apple_names, .apple_types, .apple_namespaces or .apple_objc sections.
	for _, s := range f.Sections {
		suffix := appleSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; ok {
			// Already handled.
			continue
		}

		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
		// TODO: finish implementing this.
		if err := d.AddHashes(suffix, b); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (f *File) GetBindInfo() (types.Binds, error) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	return f.getBindInfoLocked()
}

func (f *File) getBindInfoLocked() (types.Binds, error) {
	if f.bindsDone || f.binds != nil {
		return f.binds, nil
	}

	var (
		binds           types.Binds
		threadedRebases []types.Rebase
	)
	parse := func(off, size uint32, kind types.BindKind) error {
		if size == 0 {
			return nil
		}
		dat, err := saferio.ReadDataAt(f.cr, uint64(size), int64(off))
		if err != nil {
			return fmt.Errorf("failed to read %s bind info: %v", kind, err)
		}
		bs, threaded, err := f.parseBinds(bytes.NewReader(dat), kind)
		if err != nil {
			return err
		}
		binds = append(binds, bs...)
		threadedRebases = append(threadedRebases, threaded...)
		return nil
	}

	if dinfo := f.DyldInfo(); dinfo != nil {
		if err := parse(dinfo.BindOff, dinfo.BindSize, types.BIND_KIND); err != nil {
			return nil, err
		}
		if err := parse(dinfo.WeakBindOff, dinfo.WeakBindSize, types.WEAK_KIND); err != nil {
			return nil, err
		}
		if err := parse(dinfo.LazyBindOff, dinfo.LazyBindSize, types.LAZY_KIND); err != nil {
			return nil, err
		}
	} else if dinfo := f.DyldInfoOnly(); dinfo != nil {
		if err := parse(dinfo.BindOff, dinfo.BindSize, types.BIND_KIND); err != nil {
			return nil, err
		}
		if err := parse(dinfo.WeakBindOff, dinfo.WeakBindSize, types.WEAK_KIND); err != nil {
			return nil, err
		}
		if err := parse(dinfo.LazyBindOff, dinfo.LazyBindSize, types.LAZY_KIND); err != nil {
			return nil, err
		}
	} else {
		return nil, ErrMachODyldInfoNotFound
	}

	f.binds = binds
	f.threadedRebases = threadedRebases
	f.bindsDone = true
	return f.binds, nil
}

func (f *File) GetRebaseInfo() ([]types.Rebase, error) {
	f.fixupsMu.Lock()
	defer f.fixupsMu.Unlock()
	return f.getRebaseInfoLocked()
}

func (f *File) getRebaseInfoLocked() ([]types.Rebase, error) {
	if f.rebasesDone {
		return f.rebases, nil
	}
	var (
		rebaseOff  uint32
		rebaseSize uint32
	)

	switch {
	case f.DyldInfo() != nil:
		dinfo := f.DyldInfo()
		rebaseOff = dinfo.RebaseOff
		rebaseSize = dinfo.RebaseSize
	case f.DyldInfoOnly() != nil:
		dinfo := f.DyldInfoOnly()
		rebaseOff = dinfo.RebaseOff
		rebaseSize = dinfo.RebaseSize
	default:
		return nil, ErrMachODyldInfoNotFound
	}

	var rebases []types.Rebase
	if rebaseSize > 0 {
		dat, err := saferio.ReadDataAt(f.cr, uint64(rebaseSize), int64(rebaseOff))
		if err != nil {
			return nil, fmt.Errorf("failed to read rebase info: %v", err)
		}

		rebases, err = f.parseRebase(bytes.NewReader(dat))
		if err != nil {
			return nil, err
		}
	}
	// Original ARM64e uses the bind opcode stream to carry mixed bind/rebase
	// chains. Parse it even when the dedicated rebase stream is empty.
	if _, err := f.getBindInfoLocked(); err != nil {
		return nil, err
	}
	rebases = append(rebases, f.threadedRebases...)

	f.rebases = rebases
	f.rebasesDone = true
	return f.rebases, nil
}

func (f *File) GetExports() ([]trie.TrieExport, error) {
	var exports []trie.TrieExport
	seen := make(map[string]struct{})
	appendUnique := func(source []trie.TrieExport) {
		for _, export := range source {
			if _, ok := seen[export.Name]; ok {
				continue
			}
			seen[export.Name] = struct{}{}
			exports = append(exports, export)
		}
	}

	// Preserve the historical LC_DYLD_INFO(_ONLY) precedence. Some transition
	// binaries carry both commands and point them at the same trie; parsing the
	// classic source first also makes its result authoritative when names overlap.
	hasSource := false
	if dinfo := f.DyldInfo(); dinfo != nil {
		hasSource = true
		if dinfo.ExportSize > 0 {
			dat, err := saferio.ReadDataAt(f.cr, uint64(dinfo.ExportSize), int64(dinfo.ExportOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read bind info: %v", err)
			}
			classic, err := trie.ParseTrieExports(bytes.NewReader(dat), f.GetBaseAddress())
			if err != nil {
				return nil, err
			}
			appendUnique(classic)
		}
	} else if dinfo := f.DyldInfoOnly(); dinfo != nil {
		hasSource = true
		if dinfo.ExportSize > 0 {
			// addr := linkedit.Addr + (uint64(dinfo.ExportOff) - linkedit.Offset)
			dat, err := saferio.ReadDataAt(f.cr, uint64(dinfo.ExportSize), int64(dinfo.ExportOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read bind info: %v", err)
			}
			classic, err := trie.ParseTrieExports(bytes.NewReader(dat), f.GetBaseAddress())
			if err != nil {
				return nil, err
			}
			appendUnique(classic)
		}
	}

	// LC_DYLD_EXPORTS_TRIE is a complete modern replacement for the export
	// fields in dyld_info_command. It remains valid without LC_SYMTAB or
	// LC_DYSYMTAB, so the runtime-facing aggregate must consume it directly.
	if f.DyldExportsTrie() != nil {
		hasSource = true
		modern, err := f.DyldExports()
		if err != nil {
			return nil, err
		}
		appendUnique(modern)
	}

	if !hasSource {
		return nil, ErrMachODyldInfoNotFound
	}
	return exports, nil
}

// GetDyldInfo 获取聚合的 dyld 信息 (用于 iunios 运行时加载)
// 返回 Rebases, Binds, Exports 的聚合结构
func (f *File) GetDyldInfo() (*types.DyldInfo, error) {
	dyldInfo := &types.DyldInfo{}

	// 获取 Rebase 信息
	rebases, err := f.GetRebaseInfo()
	if err != nil && err != ErrMachODyldInfoNotFound {
		return nil, fmt.Errorf("failed to get rebase info: %w", err)
	}
	dyldInfo.Rebases = rebases

	// 获取 Bind 信息
	binds, err := f.GetBindInfo()
	if err != nil && err != ErrMachODyldInfoNotFound {
		return nil, fmt.Errorf("failed to get bind info: %w", err)
	}
	dyldInfo.Binds = binds

	// 获取 Export 信息
	trieExports, err := f.GetExports()
	if err != nil && err != ErrMachODyldInfoNotFound {
		return nil, fmt.Errorf("failed to get export info: %w", err)
	}
	// 转换 trie.TrieExport 到 types.Export
	for _, te := range trieExports {
		export := types.Export{
			Name:   te.Name,
			Flags:  te.Flags,
			VMAddr: te.Address,
		}
		if te.Flags.StubAndResolver() {
			export.Resolver = te.Other
		}
		dyldInfo.Exports = append(dyldInfo.Exports, export)
	}

	return dyldInfo, nil
}

func arm64eFixupMetadata(raw uint64) *types.Arm64eFixupMetadata {
	metadata := &types.Arm64eFixupMetadata{Raw: raw, Authenticated: raw>>63 != 0}
	if metadata.Authenticated {
		metadata.Diversity = uint16(raw >> 32)
		metadata.AddressDiversity = (raw & (uint64(1) << 48)) != 0
		metadata.Key = uint8((raw >> 49) & 0x3)
	}
	return metadata
}

func decodeOriginalArm64eThreadedRebase(raw, preferredLoadAddress uint64) (uint64, error) {
	if raw&(uint64(1)<<62) != 0 {
		return 0, errors.New("ARM64e threaded word is a bind, not a rebase")
	}
	if raw>>63 != 0 {
		offset := raw & 0xffffffff
		if preferredLoadAddress > ^uint64(0)-offset {
			return 0, fmt.Errorf("authenticated ARM64e target offset %#x overflows base %#x", offset, preferredLoadAddress)
		}
		return preferredLoadAddress + offset, nil
	}
	target := raw & ((uint64(1) << 43) - 1)
	high8 := (raw >> 43) & 0xff
	return high8<<56 | target, nil
}

func originalArm64eBindAddend(raw uint64) int64 {
	if raw>>63 != 0 {
		return 0
	}
	addend := int64((raw >> 32) & 0x7ffff)
	if addend&(1<<18) != 0 {
		addend -= 1 << 19
	}
	return addend
}

func (f *File) parseBinds(r *bytes.Reader, kind types.BindKind) ([]types.Bind, []types.Rebase, error) {
	var binds []types.Bind
	var threadedRebases []types.Rebase
	var ordinalTable []types.Bind
	var ordinalTableSize uint64
	var segOffset uint64
	bind := types.Bind{Kind: kind, Type: types.BIND_TYPE_POINTER}
	var libraryOrdinal int
	var libraryOrdinalSet bool
	var symbolSet bool
	var segmentSet bool
	if kind == types.WEAK_KIND {
		libraryOrdinal = types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP
		libraryOrdinalSet = true
		bind.Dylib = f.LibraryOrdinalName(libraryOrdinal)
	}

	segments := f.Segments()
	dylibCount := len(f.ImportedLibraries())
	segmentForBind := func() (*Segment, error) {
		if !segmentSet || uint64(bind.SegmentIndex) >= uint64(len(segments)) {
			return nil, fmt.Errorf("bind segment index %d is not set or out of range", bind.SegmentIndex)
		}
		segment := segments[bind.SegmentIndex]
		if segment == nil {
			return nil, fmt.Errorf("bind segment index %d is nil", bind.SegmentIndex)
		}
		return segment, nil
	}
	validateBindTarget := func() error {
		if !symbolSet {
			return errors.New("bind is missing BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM")
		}
		if !libraryOrdinalSet {
			return errors.New("bind is missing BIND_OPCODE_SET_DYLIB_ORDINAL")
		}
		if libraryOrdinal > dylibCount {
			return fmt.Errorf("bind library ordinal %d exceeds dependent dylib count %d", libraryOrdinal, dylibCount)
		}
		if libraryOrdinal < types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP {
			return fmt.Errorf("bind library ordinal %d is below the lowest special ordinal %d", libraryOrdinal, types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP)
		}
		switch bind.Type {
		case types.BIND_TYPE_POINTER, types.BIND_TYPE_TEXT_ABSOLUTE32, types.BIND_TYPE_TEXT_PCREL32:
		default:
			return fmt.Errorf("bind has unknown type %d", bind.Type)
		}
		return nil
	}
	validateBindLocation := func(segment *Segment) error {
		width := f.pointerSize()
		if segment.Memsz < width || segOffset > segment.Memsz-width {
			return fmt.Errorf("bind location %s+%#x (width %d) exceeds segment VM size %#x", segment.Name, segOffset, width, segment.Memsz)
		}
		if segment.Addr > math.MaxUint64-segOffset {
			return fmt.Errorf("bind VM address %#x+%#x overflows", segment.Addr, segOffset)
		}
		return nil
	}
	checkedAdvance := func(delta uint64) error {
		if segOffset > math.MaxUint64-delta {
			return fmt.Errorf("bind segment offset %#x + %#x overflows", segOffset, delta)
		}
		segOffset += delta
		return nil
	}
	checkedAddressULEBAdvance := func(delta uint64) error {
		segment, err := segmentForBind()
		if err != nil {
			return err
		}

		// Old Apple linkers encode a backwards address delta as its 64-bit
		// two's-complement value in this nominally ULEB operand. dyld applies
		// uint64 modular addition, then validates the resulting bind location.
		next := segOffset + delta
		if delta <= math.MaxInt64 {
			if next < segOffset {
				return fmt.Errorf("bind segment offset %#x + address ULEB %#x overflows", segOffset, delta)
			}
		} else if next > segOffset {
			return fmt.Errorf("bind segment offset %#x + backward address ULEB %#x underflows", segOffset, delta)
		}

		width := f.pointerSize()
		if segment.Memsz < width || next > segment.Memsz-width {
			return fmt.Errorf("bind address ULEB moves location to %s+%#x (width %d), outside segment VM size %#x", segment.Name, next, width, segment.Memsz)
		}
		segOffset = next
		return nil
	}
	appendOrdinaryBind := func() error {
		if err := validateBindTarget(); err != nil {
			return err
		}
		segment, err := segmentForBind()
		if err != nil {
			return err
		}
		if err := validateBindLocation(segment); err != nil {
			return err
		}
		if sec := f.FindSectionForVMAddr(segment.Addr + segOffset); sec != nil {
			bind.Section = sec.Name
		}
		bind.SegOffset = segOffset
		binds = append(binds, bind)
		return nil
	}

	useThreadedRebaseBind := false

	for {
		ptr, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		imm := ptr & types.BIND_IMMEDIATE_MASK
		opcode := ptr & types.BIND_OPCODE_MASK
		switch opcode {
		case types.BIND_OPCODE_DONE:
			if kind != types.LAZY_KIND {
				return binds, threadedRebases, nil
			}
			// In a lazy-bind stream DONE delimits entries but does not reset
			// parser state. dyld permits subsequent entries to reuse the current
			// symbol, ordinal, addend, and advanced segment offset.
		case types.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
			if kind == types.WEAK_KIND {
				return nil, nil, errors.New("unexpected dylib ordinal in weak bind stream")
			}
			libraryOrdinal = int(imm)
			libraryOrdinalSet = true
			bind.Dylib = f.LibraryOrdinalName(libraryOrdinal)
		case types.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
			if kind == types.WEAK_KIND {
				return nil, nil, errors.New("unexpected dylib ordinal in weak bind stream")
			}
			ordinal, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			if ordinal > uint64(math.MaxInt) {
				return nil, nil, fmt.Errorf("bind library ordinal %#x exceeds int", ordinal)
			}
			libraryOrdinal = int(ordinal)
			libraryOrdinalSet = true
			bind.Dylib = f.LibraryOrdinalName(libraryOrdinal)
		case types.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
			if kind == types.WEAK_KIND {
				return nil, nil, errors.New("unexpected dylib ordinal in weak bind stream")
			}
			if imm == 0 {
				libraryOrdinal = 0
			} else {
				libraryOrdinal = int(int8(types.BIND_OPCODE_MASK | imm))
			}
			libraryOrdinalSet = true
			bind.Dylib = f.LibraryOrdinalName(libraryOrdinal)
		case types.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			s, err := readString(r)
			if err != nil {
				return nil, nil, err
			}
			name := strings.Trim(s, "\x00")
			if len(name) > 0 && name[0] == '_' {
				if strings.Contains(name, ".") {
					name = name[1:]
				} else if strings.HasPrefix(name, "_OBJC_CLASS_$_") || strings.HasPrefix(name, "_OBJC_METACLASS_$_") {
					// Keep ObjC class imports byte-for-byte consistent with chained
					// imports. ObjC metadata consumers remove the full ABI prefix;
					// stripping only the first underscore here produces the bogus
					// class name "OBJC_CLASS_$_Foo".
				} else {
					name = demangle.Filter(name[1:])
				}
			}
			bind.Name = name
			bind.Flags = imm
			symbolSet = true
		case types.BIND_OPCODE_SET_TYPE_IMM:
			if kind == types.LAZY_KIND {
				return nil, nil, errors.New("unexpected BIND_OPCODE_SET_TYPE_IMM in lazy bind stream")
			}
			bind.Type = imm
		case types.BIND_OPCODE_SET_ADDEND_SLEB:
			addend, err := trie.ReadSleb128(r)
			if err != nil {
				return nil, nil, err
			}
			bind.Addend = addend
		case types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			if int(imm) >= len(segments) {
				return nil, nil, fmt.Errorf("bind segment index %d out of range (segments=%d)", imm, len(segments))
			}
			segOffset, err = trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			segment := segments[imm]
			bind.SegmentIndex = uint32(imm)
			bind.Start = segment.Addr
			bind.Segment = segment.Name
			bind.SegStart = segment.Offset
			segmentSet = true
		case types.BIND_OPCODE_ADD_ADDR_ULEB:
			if kind == types.LAZY_KIND {
				return nil, nil, errors.New("unexpected BIND_OPCODE_ADD_ADDR_ULEB in lazy bind stream")
			}
			out, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			if err := checkedAddressULEBAdvance(out); err != nil {
				return nil, nil, err
			}
		case types.BIND_OPCODE_DO_BIND:
			if useThreadedRebaseBind {
				if err := validateBindTarget(); err != nil {
					return nil, nil, err
				}
				if bind.Type != types.BIND_TYPE_POINTER {
					return nil, nil, fmt.Errorf("threaded bind target has unsupported type %d", bind.Type)
				}
				if uint64(len(ordinalTable)) >= ordinalTableSize {
					return nil, nil, fmt.Errorf("threaded bind ordinal table exceeds declared size %d", ordinalTableSize)
				}
				ordinalTable = append(ordinalTable, bind)
			} else {
				if err := appendOrdinaryBind(); err != nil {
					return nil, nil, err
				}
				if err := checkedAdvance(f.pointerSize()); err != nil {
					return nil, nil, err
				}
			}
		case types.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			if kind == types.LAZY_KIND {
				return nil, nil, errors.New("unexpected BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB in lazy bind stream")
			}
			if err := appendOrdinaryBind(); err != nil {
				return nil, nil, err
			}
			off, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			if off > math.MaxUint64-f.pointerSize() {
				return nil, nil, fmt.Errorf("bind advance %#x + pointer size overflows", off)
			}
			if err := checkedAdvance(off + f.pointerSize()); err != nil {
				return nil, nil, err
			}
		case types.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			if kind == types.LAZY_KIND {
				return nil, nil, errors.New("unexpected BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED in lazy bind stream")
			}
			if err := appendOrdinaryBind(); err != nil {
				return nil, nil, err
			}
			if err := checkedAdvance((uint64(imm) + 1) * f.pointerSize()); err != nil {
				return nil, nil, err
			}
		case types.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			if kind == types.LAZY_KIND {
				return nil, nil, errors.New("unexpected BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB in lazy bind stream")
			}
			count, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			skip, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, nil, err
			}
			if count == 0 {
				continue
			}
			if skip > math.MaxUint64-f.pointerSize() {
				return nil, nil, fmt.Errorf("bind skip %#x + pointer size overflows", skip)
			}
			advance := skip + f.pointerSize()
			if err := validateBindTarget(); err != nil {
				return nil, nil, err
			}
			segment, err := segmentForBind()
			if err != nil {
				return nil, nil, err
			}
			if err := validateBindLocation(segment); err != nil {
				return nil, nil, err
			}
			maxOffset := segment.Memsz - f.pointerSize()
			maxCount := (maxOffset-segOffset)/advance + 1
			if count > maxCount {
				return nil, nil, fmt.Errorf("bind repeat count %d exceeds %d locations remaining in segment %s", count, maxCount, segment.Name)
			}
			for i := uint64(0); i < count; i++ {
				if err := appendOrdinaryBind(); err != nil {
					return nil, nil, err
				}
				if err := checkedAdvance(advance); err != nil {
					return nil, nil, err
				}
			}
		case types.BIND_OPCODE_THREADED:
			if kind != types.BIND_KIND {
				return nil, nil, fmt.Errorf("unexpected BIND_OPCODE_THREADED in %s bind stream", kind)
			}
			switch imm {
			case types.BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
				ordinalTableSize, err = trie.ReadUleb128(r)
				if err != nil {
					return nil, nil, err
				}
				if ordinalTableSize > 0xffff {
					return nil, nil, fmt.Errorf("threaded bind ordinal table size %d exceeds 65535", ordinalTableSize)
				}
				ordinalTable = make([]types.Bind, 0, ordinalTableSize)
				useThreadedRebaseBind = true
			case types.BIND_SUBOPCODE_THREADED_APPLY:
				if !useThreadedRebaseBind {
					return nil, nil, errors.New("threaded apply encountered before ordinal table size")
				}
				if !f.isArm64e() {
					return nil, nil, errors.New("original threaded bind chain is only valid for ARM64e")
				}
				segment, err := segmentForBind()
				if err != nil {
					return nil, nil, err
				}
				for steps := uint64(0); ; steps++ {
					if segment.Filesz < 8 || segOffset > segment.Filesz-8 {
						return nil, nil, fmt.Errorf("threaded fixup %s+%#x exceeds file-backed segment size %#x", segment.Name, segOffset, segment.Filesz)
					}
					if steps > segment.Filesz/8 {
						return nil, nil, fmt.Errorf("threaded fixup chain in %s does not terminate", segment.Name)
					}
					if segment.Offset > math.MaxUint64-segOffset {
						return nil, nil, fmt.Errorf("threaded fixup file offset %#x+%#x overflows", segment.Offset, segOffset)
					}
					fileOffset := segment.Offset + segOffset
					if fileOffset > math.MaxInt64 {
						return nil, nil, fmt.Errorf("threaded fixup file offset %#x exceeds int64", fileOffset)
					}
					if segment.Addr > math.MaxUint64-segOffset {
						return nil, nil, fmt.Errorf("threaded fixup VM address %#x+%#x overflows", segment.Addr, segOffset)
					}
					var rawBytes [8]byte
					n, err := f.cr.ReadAt(rawBytes[:], int64(fileOffset))
					if n != len(rawBytes) {
						if err == nil {
							err = io.ErrUnexpectedEOF
						}
						return nil, nil, fmt.Errorf("failed to read threaded pointer at %s+%#x: %w", segment.Name, segOffset, err)
					}
					if err != nil && !errors.Is(err, io.EOF) {
						return nil, nil, fmt.Errorf("failed to read threaded pointer at %s+%#x: %w", segment.Name, segOffset, err)
					}
					raw := f.ByteOrder.Uint64(rawBytes[:])
					metadata := arm64eFixupMetadata(raw)
					slotVMAddr := segment.Addr + segOffset
					section := ""
					if sec := f.FindSectionForVMAddr(slotVMAddr); sec != nil {
						section = sec.Name
					}
					if raw&(uint64(1)<<62) == 0 {
						target, err := decodeOriginalArm64eThreadedRebase(raw, f.preferredLoadAddress())
						if err != nil {
							return nil, nil, fmt.Errorf("decode threaded rebase at %#x: %w", slotVMAddr, err)
						}
						threadedRebases = append(threadedRebases, types.Rebase{
							Type:         types.REBASE_TYPE_THREADED_POINTER_ARM64E,
							SegmentIndex: bind.SegmentIndex,
							Segment:      segment.Name,
							Section:      section,
							Start:        segment.Addr,
							Offset:       segOffset,
							Value:        target,
							Arm64e:       metadata,
						})
					} else {
						ordinal := raw & 0xffff
						if ordinal >= uint64(len(ordinalTable)) {
							return nil, nil, fmt.Errorf("threaded bind ordinal %d out of range (table entries=%d, declared=%d)", ordinal, len(ordinalTable), ordinalTableSize)
						}
						threadedBind := ordinalTable[ordinal]
						threadedBind.Type = types.BIND_TYPE_THREADED_BIND
						threadedBind.SegmentIndex = bind.SegmentIndex
						threadedBind.Segment = segment.Name
						threadedBind.Section = section
						threadedBind.Start = segment.Addr
						threadedBind.SegStart = segment.Offset
						threadedBind.SegOffset = segOffset
						threadedBind.Value = raw
						threadedBind.Addend += originalArm64eBindAddend(raw)
						threadedBind.Arm64e = metadata
						binds = append(binds, threadedBind)
					}

					next := (raw >> 51) & 0x7ff
					if next == 0 {
						break
					}
					advance := next * 8
					if segOffset > ^uint64(0)-advance {
						return nil, nil, errors.New("threaded fixup chain offset overflow")
					}
					segOffset += advance
				}
			default:
				return nil, nil, fmt.Errorf("bad threaded bind subopcode %#02x", imm)
			}
		default:
			return nil, nil, fmt.Errorf("bad bind opcode %#02x", opcode)
		}
	}

	return binds, threadedRebases, nil
}

func (f *File) parseRebase(r *bytes.Reader) ([]types.Rebase, error) {
	var rebase types.Rebase
	var rebases []types.Rebase
	var segmentSet bool
	segments := f.Segments()

	checkedAdvance := func(delta uint64) error {
		if rebase.Offset > math.MaxUint64-delta {
			return fmt.Errorf("rebase segment offset %#x + %#x overflows", rebase.Offset, delta)
		}
		rebase.Offset += delta
		return nil
	}
	appendRebase := func() error {
		if !segmentSet {
			return errors.New("classic rebase is missing REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB")
		}
		if err := f.readClassicRebaseTarget(&rebase); err != nil {
			return err
		}
		segment := segments[rebase.SegmentIndex]
		if segment.Addr > math.MaxUint64-rebase.Offset {
			return fmt.Errorf("classic rebase VM address %#x+%#x overflows", segment.Addr, rebase.Offset)
		}
		if sec := f.FindSectionForVMAddr(segment.Addr + rebase.Offset); sec != nil {
			rebase.Section = sec.Name
		}
		rebases = append(rebases, rebase)
		return nil
	}
	maxRepeatCount := func(advance uint64) (uint64, error) {
		if !segmentSet {
			return 0, errors.New("classic rebase is missing REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB")
		}
		segment, width, err := f.classicRebaseSegmentAndWidth(&rebase)
		if err != nil {
			return 0, err
		}
		if width > segment.Filesz || rebase.Offset > segment.Filesz-width {
			return 0, fmt.Errorf("classic rebase at %s+%#x (width %d) is outside segment file-backed range %#x", segment.Name, rebase.Offset, width, segment.Filesz)
		}
		if advance == 0 {
			return 0, errors.New("classic rebase repeat has zero advance")
		}
		return (segment.Filesz-width-rebase.Offset)/advance + 1, nil
	}

	for {
		ptr, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		imm := ptr & types.REBASE_IMMEDIATE_MASK
		opcode := ptr & types.REBASE_OPCODE_MASK

		switch opcode {
		case types.REBASE_OPCODE_DONE:
			if r.Len() > 15 {
				return nil, fmt.Errorf("rebase opcodes terminated early with %d trailing bytes", r.Len())
			}
			return rebases, nil
		case types.REBASE_OPCODE_SET_TYPE_IMM:
			rebase.Type = imm
		case types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			if int(imm) >= len(segments) {
				return nil, fmt.Errorf("rebase segment index %d out of range (segments=%d)", imm, len(segments))
			}
			if segments[imm] == nil {
				return nil, fmt.Errorf("rebase segment index %d is nil", imm)
			}
			rebase.SegmentIndex = uint32(imm)
			rebase.Start = segments[imm].Addr
			rebase.Segment = segments[imm].Name
			segmentSet = true
			rebase.Offset, err = trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
		case types.REBASE_OPCODE_ADD_ADDR_ULEB:
			off, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			if err := checkedAdvance(off); err != nil {
				return nil, err
			}
		case types.REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
			if err := checkedAdvance(uint64(imm) * f.pointerSize()); err != nil {
				return nil, err
			}
		case types.REBASE_OPCODE_DO_REBASE_IMM_TIMES:
			for i := byte(0); i < imm; i++ {
				if err := appendRebase(); err != nil {
					return nil, err
				}
				if err := checkedAdvance(f.pointerSize()); err != nil {
					return nil, err
				}
			}
		case types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
			count, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			if count == 0 {
				continue
			}
			maxCount, err := maxRepeatCount(f.pointerSize())
			if err != nil {
				return nil, err
			}
			if count > maxCount {
				return nil, fmt.Errorf("rebase repeat count %d exceeds %d locations remaining in segment %s", count, maxCount, rebase.Segment)
			}
			for i := uint64(0); i < count; i++ {
				if err := appendRebase(); err != nil {
					return nil, err
				}
				if err := checkedAdvance(f.pointerSize()); err != nil {
					return nil, err
				}
			}
		case types.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
			if err := appendRebase(); err != nil {
				return nil, err
			}
			off, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			if off > math.MaxUint64-f.pointerSize() {
				return nil, fmt.Errorf("rebase advance %#x + pointer size overflows", off)
			}
			if err := checkedAdvance(off + f.pointerSize()); err != nil {
				return nil, err
			}
		case types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
			count, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			skip, err := trie.ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			if count == 0 {
				continue
			}
			if skip > math.MaxUint64-f.pointerSize() {
				return nil, fmt.Errorf("rebase skip %#x + pointer size overflows", skip)
			}
			advance := skip + f.pointerSize()
			maxCount, err := maxRepeatCount(advance)
			if err != nil {
				return nil, err
			}
			if count > maxCount {
				return nil, fmt.Errorf("rebase repeat count %d exceeds %d locations remaining in segment %s", count, maxCount, rebase.Segment)
			}
			for i := uint64(0); i < count; i++ {
				if err := appendRebase(); err != nil {
					return nil, err
				}
				if err := checkedAdvance(advance); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("bad rebase opcode %#02x", opcode)
		}
	}

	return rebases, nil
}

func (f *File) classicRebaseSegmentAndWidth(rebase *types.Rebase) (*Segment, uint64, error) {
	if rebase == nil {
		return nil, 0, errors.New("cannot read a nil classic rebase")
	}

	var width uint64
	switch rebase.Type {
	case types.REBASE_TYPE_POINTER:
		width = f.pointerSize()
	case types.REBASE_TYPE_TEXT_ABSOLUTE32, types.REBASE_TYPE_TEXT_PCREL32:
		width = 4
	default:
		return nil, 0, fmt.Errorf("unknown classic rebase type %d", rebase.Type)
	}

	segments := f.Segments()
	if uint64(rebase.SegmentIndex) >= uint64(len(segments)) {
		return nil, 0, fmt.Errorf("classic rebase segment index %d out of range (segments=%d)", rebase.SegmentIndex, len(segments))
	}
	segment := segments[rebase.SegmentIndex]
	if segment == nil {
		return nil, 0, fmt.Errorf("classic rebase segment index %d is nil", rebase.SegmentIndex)
	}
	if segment.Name != rebase.Segment {
		return nil, 0, fmt.Errorf("classic rebase segment index %d names %q, not %q", rebase.SegmentIndex, segment.Name, rebase.Segment)
	}
	return segment, width, nil
}

// readClassicRebaseTarget reads the target stored at one classic dyld rebase
// slot. REBASE_TYPE_POINTER follows the target Mach-O pointer width, while the
// two text relocation forms always encode a 32-bit field.
func (f *File) readClassicRebaseTarget(rebase *types.Rebase) error {
	if f.cr == nil {
		return errors.New("cannot read a classic rebase without a Mach-O reader")
	}

	segment, width, err := f.classicRebaseSegmentAndWidth(rebase)
	if err != nil {
		return err
	}
	if width > segment.Filesz || rebase.Offset > segment.Filesz-width {
		return fmt.Errorf("classic rebase at %s+%#x (width %d) is outside segment file-backed range %#x", segment.Name, rebase.Offset, width, segment.Filesz)
	}
	if segment.Offset > math.MaxUint64-rebase.Offset {
		return fmt.Errorf("classic rebase file offset %#x+%#x overflows", segment.Offset, rebase.Offset)
	}
	fileOffset := segment.Offset + rebase.Offset
	if fileOffset > math.MaxInt64 {
		return fmt.Errorf("classic rebase file offset %#x exceeds int64", fileOffset)
	}
	data := make([]byte, width)
	n, err := f.cr.ReadAt(data, int64(fileOffset))
	if n != len(data) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read %d-byte classic rebase target at file offset %#x: %w", width, fileOffset, err)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read %d-byte classic rebase target at file offset %#x: %w", width, fileOffset, err)
	}
	value, err := decodePointerValue(data, width, f.ByteOrder)
	if err != nil {
		return fmt.Errorf("decode %d-byte classic rebase target at file offset %#x: %w", width, fileOffset, err)
	}
	rebase.Value = value
	return nil
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
func (f *File) ImportedSymbols() ([]Symbol, error) {
	if f.Dysymtab == nil || f.Symtab == nil {
		return nil, &FormatError{0, "missing symbol table", nil}
	}

	st := f.Symtab
	dt := f.Dysymtab
	var all []Symbol
	all = append(all, st.Syms[dt.Iundefsym:dt.Iundefsym+dt.Nundefsym]...)
	return all, nil
}

// ImportedSymbolNames returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
func (f *File) ImportedSymbolNames() ([]string, error) {
	var all []string

	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to get imported symbols: %v", err)
	}

	for _, s := range syms {
		all = append(all, s.Name)
	}

	return all, nil
}

// ImportedLibraries returns the paths of all libraries
// referred to by the binary f that are expected to be
// linked with the binary at dynamic link time.
func (f *File) ImportedLibraries() []string {
	var all []string
	for _, l := range f.Loads {
		switch v := l.(type) {
		case *LoadDylib:
			all = append(all, v.Name)
		case *WeakDylib:
			all = append(all, v.Name)
		case *ReExportDylib:
			all = append(all, v.Name)
		case *UpwardDylib:
			all = append(all, v.Name)
		case *LazyLoadDylib:
			all = append(all, v.Name)
		}
	}
	return all
}

// LibraryOrdinalName returns the depancy library oridnal's name
func (f *File) LibraryOrdinalName(libraryOrdinal int) string {
	dylibs := f.ImportedLibraries()

	if libraryOrdinal > 0 {
		if libraryOrdinal > len(dylibs) {
			return "ordinal-too-large"
		}
		return filepath.Base(dylibs[libraryOrdinal-1])
	}

	switch libraryOrdinal {
	case types.BIND_SPECIAL_DYLIB_SELF:
		return "this-image"
	case types.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
		return "main-executable"
	case types.BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
		return "flat-namespace"
	case types.BIND_SPECIAL_DYLIB_WEAK_LOOKUP:
		return "weak-coalesce"
	default:
		return "unknown-ordinal"
	}
}

// FindSymbolAddress returns the address of the named symbol.
//
// 行为变更说明: Mach-O 符号名区分大小写，以前全部用 strings.EqualFold 比较，
// 同时存在 _value_A 和 _value_a 时，查 _value_a 会返回排在前面的 _value_A；
// chained fixup 的 self-bind 靠这个函数解析，指针因此可能指向错误的符号。
// 现在精确匹配优先（先符号表、再导出表）；完全没有精确匹配时才退回原来的
// 不区分大小写匹配，且顺序与以前相同，所以以前能解析出来的名字现在仍然能解析。
//
// The precedence is: first exact match in the symbol table, first exact match
// in the exports, first case-insensitive match in the symbol table, first
// case-insensitive match in the exports. findSymbolAddressLinear is the plain
// scan that defines this; the code below returns the same results from the
// lookup indexes in symindex.go once a table has been queried often enough.
func (f *File) FindSymbolAddress(symbol string) (uint64, error) {
	if f.Symtab == nil {
		return 0, &FormatError{0, "missing symbol table", nil}
	}
	syms := f.Symtab.Syms
	var (
		foldAddr  uint64
		foldFound bool
	)
	symIndex, symIndexed := f.symtabNameIndex(syms)
	if symIndexed {
		if i, ok := symIndex.exact[symbol]; ok {
			if syms[i].Name != symbol {
				return f.findSymbolAddressStale(symbol)
			}
			return syms[i].Value, nil
		}
	} else {
		for _, sym := range syms {
			if sym.Name == symbol {
				return sym.Value, nil
			}
			if !foldFound && strings.EqualFold(sym.Name, symbol) {
				foldAddr, foldFound = sym.Value, true
			}
		}
	}
	// symtabFold completes foldAddr/foldFound for the indexed case, where the
	// case-insensitive match is only looked up once it is actually needed.
	symtabFold := func() bool {
		if symIndexed {
			symIndexed = false
			if i, ok := symIndex.foldFirst(symbol); ok {
				if !strings.EqualFold(syms[i].Name, symbol) {
					return false
				}
				foldAddr, foldFound = syms[i].Value, true
			}
		}
		return true
	}

	exports, err := f.cachedExports()
	if err != nil {
		if err != ErrMachODyldInfoNotFound {
			if !symtabFold() {
				return f.findSymbolAddressStale(symbol)
			}
			if foldFound {
				// the previous code returned the symbol-table match before
				// ever looking at the exports
				return foldAddr, nil
			}
			return 0, fmt.Errorf("failed to get exports: %v", err)
		}
	}
	expIndex, expIndexed := f.exportsNameIndex(exports)
	if expIndexed {
		if i, ok := expIndex.exact[symbol]; ok {
			return exports[i].Address, nil
		}
		if !symtabFold() {
			return f.findSymbolAddressStale(symbol)
		}
		if !foldFound {
			if i, ok := expIndex.foldFirst(symbol); ok {
				foldAddr, foldFound = exports[i].Address, true
			}
		}
	} else {
		if !symtabFold() {
			return f.findSymbolAddressStale(symbol)
		}
		for _, sym := range exports {
			if sym.Name == symbol {
				return sym.Address, nil
			}
			if !foldFound && strings.EqualFold(sym.Name, symbol) {
				foldAddr, foldFound = sym.Address, true
			}
		}
	}
	if foldFound {
		return foldAddr, nil
	}
	return 0, fmt.Errorf("symbol not found in macho symtab")
}

// findSymbolAddressStale answers a lookup whose index hit did not match the
// live symbol table (an element was edited in place).
func (f *File) findSymbolAddressStale(symbol string) (uint64, error) {
	f.resetSymbolIndexes()
	return f.findSymbolAddressLinear(symbol)
}

// FindAddressSymbols returns the symbols at addr: the symbol table entries in
// table order followed by the LC_DYLD_EXPORTS_TRIE exports in trie order.
// findAddressSymbolsLinear is the plain scan that defines the result.
func (f *File) FindAddressSymbols(addr uint64) ([]Symbol, error) {
	if f.Symtab == nil {
		return nil, &FormatError{0, "missing symbol table", nil}
	}
	var syms []Symbol
	all := f.Symtab.Syms
	if order, ok := f.symtabAddrIndex(all); ok {
		for _, i := range valueRange(order, func(i int) uint64 { return all[i].Value }, addr) {
			syms = append(syms, all[i])
		}
	} else {
		for _, sym := range all {
			if sym.Value == addr {
				syms = append(syms, sym)
			}
		}
	}
	if f.DyldExportsTrie() != nil && f.DyldExportsTrie().Size > 0 {
		exports, err := f.DyldExports()
		if err != nil {
			return nil, fmt.Errorf("failed to get exports: %v", err)
		}
		if order, ok := f.dyldExportsAddrIndex(exports); ok {
			for _, i := range valueRange(order, func(i int) uint64 { return exports[i].Address }, addr) {
				syms = append(syms, Symbol{Name: exports[i].Name, Value: exports[i].Address})
			}
		} else {
			for _, sym := range exports {
				if sym.Address == addr {
					syms = append(syms, Symbol{Name: sym.Name, Value: sym.Address})
				}
			}
		}
	}
	if len(syms) > 0 {
		return syms, nil
	}
	return nil, fmt.Errorf("symbol(s) not found in macho symtab for addr %#x", addr)
}

// SetSwiftAutoDemangle toggles automatic demangling of Swift metadata strings when parsing structures.
func (f *File) SetSwiftAutoDemangle(enabled bool) {
	f.swiftAutoDemangle = enabled
}

// SwiftAutoDemangle reports whether Swift metadata strings are automatically demangled.
func (f *File) SwiftAutoDemangle() bool {
	return f.swiftAutoDemangle
}

// LoadExt 加载 iunios 运行时需要的扩展信息
// 包括: Entry, ThreadEntry, Entitlements, DynamicExports, Slide, VMSize, RelocationBase
func (f *File) LoadExt() error {
	// 提取 LC_MAIN 入口点
	for _, l := range f.Loads {
		if ep, ok := l.(*EntryPoint); ok {
			// EntryOffset 是相对于 __TEXT 段的偏移
			textSeg := f.Segment("__TEXT")
			if textSeg != nil {
				f.Entry = textSeg.Addr + ep.EntryOffset
			} else {
				f.Entry = ep.EntryOffset
			}
			break
		}
	}

	// 提取 LC_UNIXTHREAD 入口点
	for _, l := range f.Loads {
		if ut, ok := l.(*UnixThread); ok {
			f.ThreadEntry = ut.PC()
			break
		}
	}

	// 提取 Entitlements
	if cs := f.CodeSignature(); cs != nil {
		f.Entitlements = cs.Entitlements
	}

	// 提取 DynamicExports
	if f.Dysymtab != nil && f.Symtab != nil {
		for i := f.Dysymtab.Iextdefsym; i < f.Dysymtab.Iextdefsym+f.Dysymtab.Nextdefsym; i++ {
			if int(i) >= len(f.Symtab.Syms) {
				break
			}
			sym := f.Symtab.Syms[i]
			vmaddr := sym.Value
			// ARM Thumb 函数标记
			if sym.Desc.IsArmThumbDefintion() {
				vmaddr |= 1
			}
			f.DynamicExports = append(f.DynamicExports, &DynamicExport{
				Name:   sym.Name,
				VMAddr: vmaddr,
			})
		}
	}

	// 计算 Slide, VMSize, RelocationBase
	var vmaddrMin uint64 = ^uint64(0) // MaxUint64
	var vmaddrMax uint64
	var firstSegmentAddress uint64
	var firstWritableSegmentAddress uint64
	var hasFirstSegment bool
	var hasFirstWritableSegment bool
	var hasXNUHIBSegment bool

	for _, seg := range f.Segments() {
		// Dysymtab relocation addresses are based on load-command order, not
		// numerical VM-address order (mach-o/loader.h, dysymtab_command).
		if !hasFirstSegment {
			firstSegmentAddress = seg.Addr
			hasFirstSegment = true
		}
		if !hasFirstWritableSegment && seg.Prot.Write() {
			firstWritableSegmentAddress = seg.Addr
			hasFirstWritableSegment = true
		}
		if seg.Name == "__HIB" {
			hasXNUHIBSegment = true
		}

		if seg.Name == "__PAGEZERO" {
			continue
		}
		if seg.Name == "__TEXT" {
			f.Slide = seg.Addr
		}
		if vmaddrMin > seg.Addr {
			vmaddrMin = seg.Addr
		}
		if vmaddrMax < (seg.Addr + seg.Memsz) {
			vmaddrMax = seg.Addr + seg.Memsz
		}
	}

	if vmaddrMin != ^uint64(0) && vmaddrMax > vmaddrMin {
		f.VMSize = vmaddrMax - vmaddrMin
	}

	// dyld images use the first writable segment only with MH_SPLIT_SEGS.
	// Legacy x86_64 XNU kernel executables are an independent boot format:
	// their LC_DYSYMTAB KASLR slots are based at the first writable segment
	// despite not setting MH_SPLIT_SEGS. __HIB distinguishes that format from
	// ordinary MH_EXECUTE user images.
	isLegacyX86Kernel := f.FileHeader.CPU == types.CPUAmd64 &&
		f.FileHeader.Type == types.MH_EXECUTE && hasXNUHIBSegment
	if f.FileHeader.Flags.SplitSegs() || isLegacyX86Kernel {
		if hasFirstWritableSegment {
			f.RelocationBase = firstWritableSegmentAddress
		}
	} else {
		if hasFirstSegment {
			f.RelocationBase = firstSegmentAddress
		}
	}

	return nil
}
