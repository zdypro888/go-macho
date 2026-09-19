package macho

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/zdypro888/go-macho/internal/saferio"
	"github.com/zdypro888/go-macho/pkg/codesign"
	ctypes "github.com/zdypro888/go-macho/pkg/codesign/types"
	"github.com/zdypro888/go-macho/pkg/fixupchains"
	"github.com/zdypro888/go-macho/pkg/trie"
	"github.com/zdypro888/go-macho/types"
)

type segInfo struct {
	Start uint64
	End   uint64
}
type segMapInfo struct {
	Name       string
	Old        segInfo
	New        segInfo
	OrigMemsz  uint64
	OrigFilesz uint64
}

func (i segMapInfo) LessThan(o segMapInfo) bool {
	return i.Old.Start < o.Old.Start
}

type exportSegMap []segMapInfo

func (m exportSegMap) Len() int {
	return len(m)
}

func (m exportSegMap) Less(i, j int) bool {
	return m[i].LessThan(m[j])
}

func (m exportSegMap) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

func (m exportSegMap) Remap(offset uint64) (uint64, error) {
	for _, segInfo := range m {
		if segInfo.Old.Start <= offset && offset <= segInfo.Old.End {
			return segInfo.New.Start + (offset - segInfo.Old.Start), nil
		}
	}
	return 0, fmt.Errorf("failed to remap offset %#x", offset)
}

func (m exportSegMap) RemapSeg(name string, offset uint64) (uint64, uint64, error) {
	for _, segInfo := range m {
		if segInfo.Name == name {
			return segInfo.New.Start + (offset - segInfo.Old.Start), (segInfo.New.End - segInfo.New.Start), nil
		}
	}
	return 0, 0, fmt.Errorf("failed to remap offset %#x", offset)
}

func (m exportSegMap) Lookup(name string) (segMapInfo, bool) {
	for _, info := range m {
		if info.Name == name {
			return info, true
		}
	}
	return segMapInfo{}, false
}

func pageAlign(off, align uint64) uint64 {
	if (off % align) != 0 {
		off += align - (off % align)
	}
	return off
}

// pointerAlignPad returns the number of zero bytes needed to
// align currentLen up to the next multiple of ptrSize.
func pointerAlignPad(currentLen int, ptrSize uint64) int {
	rem := uint64(currentLen) % ptrSize
	if rem == 0 {
		return 0
	}
	return int(ptrSize - rem)
}

func (f *File) textSegmentFirstSectionRelOff(inCache bool) (uint64, error) {
	textSeg := f.Segment("__TEXT")
	if textSeg == nil {
		return 0, nil
	}
	for i := uint32(0); i < textSeg.Nsect; i++ {
		idx := uint64(textSeg.Firstsect) + uint64(i)
		if idx >= uint64(len(f.Sections)) {
			return 0, fmt.Errorf("__TEXT section index %d out of range", idx)
		}
		sec := f.Sections[int(idx)]
		if sec.Offset == 0 {
			continue
		}
		if inCache {
			if sec.Addr < textSeg.Addr {
				return 0, fmt.Errorf("__TEXT section %s address %#x precedes segment address %#x", sec.Name, sec.Addr, textSeg.Addr)
			}
			return sec.Addr - textSeg.Addr, nil
		}
		if uint64(sec.Offset) < textSeg.Offset {
			return 0, fmt.Errorf("__TEXT section %s offset %#x precedes segment offset %#x", sec.Name, sec.Offset, textSeg.Offset)
		}
		return uint64(sec.Offset) - textSeg.Offset, nil
	}
	return 0, nil
}

// exportSegmentsReadable reports whether it is safe to pre-allocate total bytes
// for the export buffer: the last byte of every segment's file data has to be
// readable and the segment sizes have to add up to at least total. Growing the
// buffer is only an optimization, so a false result never fails the export; it
// just keeps a bogus filesize from being allocated on its word alone.
func (f *File) exportSegmentsReadable(inCache bool, total uint64) bool {
	if total > uint64(^uint(0)>>1) {
		return false
	}
	var sum uint64
	var b [1]byte
	for _, seg := range f.Segments() {
		if seg.Filesz == 0 {
			continue
		}
		aligned := pageAlign(seg.Filesz, f.pageSize())
		if aligned < seg.Filesz || sum+aligned < sum {
			return false
		}
		sum += aligned
		last := seg.Filesz - 1
		if inCache {
			if seg.Addr > math.MaxUint64-last {
				return false
			}
			if n, _ := f.cr.ReadAtAddr(b[:], seg.Addr+last); n != 1 {
				return false
			}
			continue
		}
		if f.sr == nil || seg.Offset > math.MaxInt64 || last > math.MaxInt64-seg.Offset {
			return false
		}
		if n, _ := f.sr.ReadAt(b[:], int64(seg.Offset+last)); n != 1 {
			return false
		}
	}
	return total <= sum
}

func textSegmentWriteStart(firstSectionRelOff, endOfLoadsOffset, dataLen uint64) (uint64, error) {
	dataStart := firstSectionRelOff
	if endOfLoadsOffset > dataStart {
		dataStart = endOfLoadsOffset
	}
	if dataStart > dataLen {
		return 0, fmt.Errorf("__TEXT data start %#x exceeds segment data length %#x", dataStart, dataLen)
	}
	return dataStart, nil
}

// Export exports an in-memory or cached dylib|kext MachO to a file
func (f *File) Export(path string, dcf *fixupchains.DyldChainedFixups, baseAddress uint64, locals []Symbol) (err error) {
	var buf bytes.Buffer
	var lebuf *bytes.Buffer
	var segMap exportSegMap

	inCache := f.FileHeader.Flags.DylibInCache()
	pgSz := f.pageSize()

	// create segment offset map
	var newSegOffset uint64
	for _, seg := range f.Segments() {
		segMap = append(segMap, segMapInfo{
			Name: seg.Name,
			Old: segInfo{
				Start: seg.Offset,
				End:   seg.Offset + seg.Filesz,
			},
			New: segInfo{
				Start: newSegOffset,
				End:   newSegOffset + pageAlign(seg.Filesz, pgSz),
			},
			OrigMemsz:  seg.Memsz,
			OrigFilesz: seg.Filesz,
		})
		newSegOffset += pageAlign(seg.Filesz, pgSz)
	}

	sort.Sort(segMap)

	// pre-allocate output buffer to avoid repeated doubling during writes
	if len(segMap) > 0 {
		if total := segMap[len(segMap)-1].New.End; total < safeAllocChunk || f.exportSegmentsReadable(inCache, total) {
			buf.Grow(int(total))
		}
	}

	// save original __TEXT layout before load commands rewrite changes offsets
	origTextFirstSectRelOff, err := f.textSegmentFirstSectionRelOff(inCache)
	if err != nil {
		return err
	}

	if err := f.optimizeLoadCommands(segMap, inCache); err != nil {
		return fmt.Errorf("failed to optimize load commands: %v", err)
	}

	if inCache {
		lebuf, err = f.optimizeLinkedit(locals)
		if err != nil {
			return fmt.Errorf("failed to optimize linkedit: %v", err)
		}
		// optimizeLinkedit rebuilds __LINKEDIT with its actual size;
		// update the segMap so the write loop uses the correct bounds
		// (the original segMap entry used the shared cache __LINKEDIT size).
		linkedit := f.Segment("__LINKEDIT")
		for i := range segMap {
			if segMap[i].Name == "__LINKEDIT" {
				segMap[i].New.End = segMap[i].New.Start + linkedit.Filesz
				segMap[i].OrigFilesz = linkedit.Filesz
				break
			}
		}
	}

	if err := f.optimizeObjC(segMap); err != nil {
		return fmt.Errorf("failed to optimize ObjC: %v", err)
	}

	// if err := f.optimizeStubs(segMap); err != nil {
	// 	return fmt.Errorf("failed to optimize ObjC: %v", err)
	// }

	if inCache {
		f.FileHeader.Flags &= 0x7FFFFFFF // remove in-cache bit
		// Strip LC_DYLD_CHAINED_FIXUPS: the fixup chain data in the
		// shared cache is not reconstructed during export, so the
		// remapped offset would point to invalid data. Callers that
		// need rebasing (e.g. slide info) handle it post-export.
		for _, l := range f.Loads {
			if _, ok := l.(*DyldChainedFixups); ok {
				if err := f.FileTOC.RemoveLoad(l); err != nil {
					return fmt.Errorf("failed to remove LC_DYLD_CHAINED_FIXUPS: %v", err)
				}
				break
			}
		}
	}

	if err := f.FileHeader.Write(&buf, f.ByteOrder); err != nil {
		return fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	if err := f.writeLoadCommands(&buf); err != nil {
		return fmt.Errorf("failed to write load commands: %v", err)
	}

	endOfLoadsOffset := uint64(buf.Len())
	// readOriginalSegment returns smi.OrigFilesz bytes of the segment. Sizes
	// below safeAllocChunk take the historical make+read path verbatim; larger
	// ones are read in chunks so a bogus filesize fails at the first missing
	// chunk instead of allocating the declared amount up front.
	readOriginalSegment := func(seg *Segment, smi segMapInfo) ([]byte, error) {
		if smi.OrigFilesz >= safeAllocChunk {
			if inCache {
				return readDataAtAddr(f.cr, smi.OrigFilesz, seg.Addr)
			}
			if f.sr == nil {
				return nil, fmt.Errorf("source file reader is unavailable")
			}
			if smi.Old.Start > math.MaxInt64 {
				return nil, fmt.Errorf("original segment offset %#x exceeds int64", smi.Old.Start)
			}
			return readDataAt(f.sr, smi.OrigFilesz, int64(smi.Old.Start))
		}
		dat := make([]byte, smi.OrigFilesz)
		var (
			n   int
			err error
		)
		if inCache {
			n, err = f.cr.ReadAtAddr(dat, seg.Addr)
		} else {
			// optimizeLoadCommands has already replaced seg.Offset with the
			// exported layout. Read standalone Mach-O bytes from the immutable
			// source reader at the offset captured in segMap instead of asking
			// the now-mutated VM address converter for an offset.
			if f.sr == nil {
				return nil, fmt.Errorf("source file reader is unavailable")
			}
			if smi.Old.Start > math.MaxInt64 {
				return nil, fmt.Errorf("original segment offset %#x exceeds int64", smi.Old.Start)
			}
			n, err = f.sr.ReadAt(dat, int64(smi.Old.Start))
		}
		if err != nil {
			return nil, err
		}
		if n != len(dat) {
			return nil, io.ErrUnexpectedEOF
		}
		return dat, nil
	}
	// zeroPad appends n zero bytes. n derives from segment sizes in the file,
	// so it is written in bounded pieces rather than through one make(n).
	zeroPad := func(n uint64) error {
		if n < safeAllocChunk {
			_, err := buf.Write(make([]byte, n))
			return err
		}
		if n > math.MaxInt64 {
			return fmt.Errorf("padding size %#x exceeds allocation limit", n)
		}
		zeros := make([]byte, safeAllocChunk)
		for n > 0 {
			next := min(n, uint64(len(zeros)))
			if _, err := buf.Write(zeros[:next]); err != nil {
				return err
			}
			n -= next
		}
		return nil
	}

	// Write out segment data to buffer
	for _, seg := range f.Segments() {
		smi, _ := segMap.Lookup(seg.Name)
		if seg.Filesz > 0 {
			// pad buffer to this segment's expected start offset
			if uint64(buf.Len()) < smi.New.Start {
				if err := zeroPad(smi.New.Start - uint64(buf.Len())); err != nil {
					return fmt.Errorf("failed to write pre-segment padding for %s: %v", seg.Name, err)
				}
			}
			switch seg.Name {
			case "__TEXT":
				// read original __TEXT data from cache (use original filesz)
				dat, err := readOriginalSegment(seg, smi)
				if err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				// write __TEXT data after the header+load commands we already wrote
				dataStart, err := textSegmentWriteStart(origTextFirstSectRelOff, endOfLoadsOffset, uint64(len(dat)))
				if err != nil {
					return err
				}
				if dataStart > endOfLoadsOffset {
					// pad gap between end of load commands and first section
					if err := zeroPad(dataStart - endOfLoadsOffset); err != nil {
						return fmt.Errorf("failed to write __TEXT LC-to-section padding: %v", err)
					}
				}
				if _, err := buf.Write(dat[dataStart:]); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			case "__LINKEDIT":
				if inCache {
					if _, err := buf.Write(lebuf.Bytes()); err != nil {
						return fmt.Errorf("failed to write optimized segment %s to export buffer: %v", seg.Name, err)
					}
				} else {
					dat, err := readOriginalSegment(seg, smi)
					if err != nil {
						return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
					}
					if _, err := buf.Write(dat); err != nil {
						return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
					}
				}
			default:
				dat, err := readOriginalSegment(seg, smi)
				if err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				if _, err := buf.Write(dat); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			}
		}
		// pad to segment's page-aligned end
		if uint64(buf.Len()) < smi.New.End {
			if err := zeroPad(smi.New.End - uint64(buf.Len())); err != nil {
				return fmt.Errorf("failed to write post-segment padding for %s: %v", seg.Name, err)
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0755); err != nil {
		return fmt.Errorf("failed to write exported MachO to file %s: %w", path, err)
	}

	return nil
}

func cloneCodeSignBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func cloneCodeSignConfig(config *codesign.Config) codesign.Config {
	cloned := *config
	if config.SpecialSlots != nil {
		cloned.SpecialSlots = make([]ctypes.SpecialSlot, len(config.SpecialSlots))
		copy(cloned.SpecialSlots, config.SpecialSlots)
	}
	for index := range cloned.SpecialSlots {
		cloned.SpecialSlots[index].Hash = cloneCodeSignBytes(config.SpecialSlots[index].Hash)
	}
	cloned.InfoPlist = cloneCodeSignBytes(config.InfoPlist)
	cloned.Entitlements = cloneCodeSignBytes(config.Entitlements)
	cloned.EntitlementsDER = cloneCodeSignBytes(config.EntitlementsDER)
	cloned.LaunchConstraintsSelf = cloneCodeSignBytes(config.LaunchConstraintsSelf)
	cloned.LaunchConstraintsParent = cloneCodeSignBytes(config.LaunchConstraintsParent)
	cloned.LaunchConstraintsResponsible = cloneCodeSignBytes(config.LaunchConstraintsResponsible)
	cloned.LibraryConstraints = cloneCodeSignBytes(config.LibraryConstraints)
	cloned.ResourceDirSlotHash = cloneCodeSignBytes(config.ResourceDirSlotHash)
	if config.CertChain != nil {
		cloned.CertChain = make([]*x509.Certificate, len(config.CertChain))
		copy(cloned.CertChain, config.CertChain)
	}
	if config.RawComponents != nil {
		cloned.RawComponents = make(map[ctypes.SlotType][]byte, len(config.RawComponents))
		for slot, payload := range config.RawComponents {
			cloned.RawComponents[slot] = cloneCodeSignBytes(payload)
		}
	}
	return cloned
}

func checkedAlign(value, alignment uint64) (uint64, error) {
	if alignment == 0 {
		return 0, fmt.Errorf("alignment must not be zero")
	}
	remainder := value % alignment
	if remainder == 0 {
		return value, nil
	}
	padding := alignment - remainder
	if value > math.MaxUint64-padding {
		return 0, fmt.Errorf("aligning %#x to %#x bytes overflows", value, alignment)
	}
	return value + padding, nil
}

func (f *File) writeCodeSignFileHeader(buf *bytes.Buffer) error {
	headerSize := int(f.HdrSize())
	encoded := make([]byte, headerSize)
	if written := f.FileHeader.Put(encoded, f.ByteOrder); written != headerSize {
		return fmt.Errorf("encoded Mach-O header size %d, want %d", written, headerSize)
	}
	if _, err := buf.Write(encoded); err != nil {
		return fmt.Errorf("failed to write Mach-O header: %w", err)
	}
	return nil
}

func (f *File) validateCodeSignatureLoadSpace(text *Segment, commandSize uint32) error {
	if f.NCommands == math.MaxUint32 || uint64(f.SizeCommands)+uint64(commandSize) > math.MaxUint32 {
		return fmt.Errorf("adding LC_CODE_SIGNATURE overflows the Mach-O load-command header")
	}
	loadEnd := uint64(f.HdrSize()) + uint64(f.LoadSize()) + uint64(commandSize)
	for index := uint32(0); index < text.Nsect; index++ {
		sectionIndex := uint64(text.Firstsect) + uint64(index)
		if sectionIndex >= uint64(len(f.Sections)) {
			return fmt.Errorf("__TEXT section index %d is outside the section table", sectionIndex)
		}
		section := f.Sections[int(sectionIndex)]
		if section.Offset == 0 {
			continue
		}
		if loadEnd > uint64(section.Offset) {
			return fmt.Errorf("not enough header padding for LC_CODE_SIGNATURE: load commands end at %#x, first __TEXT section starts at %#x", loadEnd, section.Offset)
		}
		break
	}
	return nil
}

func (f *File) CodeSign(config *codesign.Config) (retErr error) {
	if config == nil {
		return fmt.Errorf("codesign config must not be nil")
	}
	working := cloneCodeSignConfig(config)
	cfg := &working
	var cs *CodeSignature

	cfg.InitSlotHashes() // initialize slot hashes with default empty slot hashes

	cfg.IsMain = f.Type == types.MH_EXECUTE

	text := f.Segment("__TEXT")
	if text == nil {
		return fmt.Errorf("failed to find __TEXT segment")
	}
	cfg.TextOffset = uint64(text.Offset)
	cfg.TextSize = uint64(text.Filesz)

	// check if there is an embedded Info.plist
	if infoPlist, err := f.GetEmbeddedInfoPlist(); err == nil {
		cfg.InfoPlist = infoPlist
	}

	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return fmt.Errorf("failed to find __LINKEDIT segment")
	}

	if cfg.ResourceDirSlotHash != nil {
		cfg.SlotHashes.ResourceDir = cfg.ResourceDirSlotHash
	}

	if cs = f.CodeSignature(); cs != nil { // existing code signature
		// import settings from existing code signature
		if primary := cs.PrimaryCodeDirectory(); primary != nil {
			if cfg.ID == "" {
				cfg.ID = primary.ID
			}
			if cfg.TeamID == "" {
				cfg.TeamID = primary.TeamID
			}
			if cfg.Flags&ctypes.ADHOC != 0 {
				cfg.Flags &= ^ctypes.LINKER_SIGNED // remove linker signed flag TODO: should I do this?
			}
			if cfg.Entitlements == nil {
				cfg.Entitlements = []byte(cs.Entitlements)
			}
			if cfg.EntitlementsDER == nil {
				cfg.EntitlementsDER = bytes.Clone(cs.EntitlementsDER)
			}
			if cfg.SpecialSlots == nil {
				cfg.SpecialSlots = append([]ctypes.SpecialSlot(nil), primary.SpecialSlots...)
				for index := range cfg.SpecialSlots {
					cfg.SpecialSlots[index].Hash = bytes.Clone(primary.SpecialSlots[index].Hash)
				}
				cfg.SpecialSlotsHashType = uint8(primary.Header.HashType)
				cfg.SpecialSlotsHashSize = primary.Header.HashSize
			}
			if cfg.LaunchConstraintsSelf == nil {
				cfg.LaunchConstraintsSelf = bytes.Clone(cs.LaunchConstraintsSelf)
			}
			if cfg.LaunchConstraintsParent == nil {
				cfg.LaunchConstraintsParent = bytes.Clone(cs.LaunchConstraintsParent)
			}
			if cfg.LaunchConstraintsResponsible == nil {
				cfg.LaunchConstraintsResponsible = bytes.Clone(cs.LaunchConstraintsResponsible)
			}
			if cfg.LibraryConstraints == nil {
				cfg.LibraryConstraints = bytes.Clone(cs.LibraryConstraints)
			}
			// Preserve embedded raw components that participate in the primary
			// Mach-O CodeDirectory. Detached identification and an old notarization
			// ticket are intentionally not carried into a newly signed Mach-O.
			for _, slot := range []ctypes.SlotType{
				ctypes.CSSLOT_INFOSLOT,
				ctypes.CSSLOT_RESOURCEDIR,
				ctypes.CSSLOT_APPLICATION,
				ctypes.CSSLOT_REP_SPECIFIC,
			} {
				payload, exists := cs.RawComponents[slot]
				if !exists {
					continue
				}
				if cfg.RawComponents == nil {
					cfg.RawComponents = make(map[ctypes.SlotType][]byte)
				}
				if _, supplied := cfg.RawComponents[slot]; !supplied {
					cfg.RawComponents[slot] = bytes.Clone(payload)
				}
			}
			if cfg.RuntimeVersion == 0 {
				if primary.Header.Runtime != 0 {
					cfg.RuntimeVersion = primary.Header.Runtime
				} else if bvs := f.BuildVersions(); len(bvs) > 0 {
					cfg.RuntimeVersion = bvs[0].Sdk
				} else if vm := f.VersionMin(); vm != nil {
					cfg.RuntimeVersion = vm.Sdk
				}
			}
		}
	} else { // create NEW code signature
		if cfg.ID == "" {
			return fmt.Errorf("you must supply an ID")
		}
		// infer runtime version from build or min version load commands if necessary
		if cfg.Flags&ctypes.RUNTIME != 0 {
			if cfg.RuntimeVersion == 0 {
				if bvs := f.BuildVersions(); len(bvs) > 0 {
					cfg.RuntimeVersion = bvs[0].Sdk
				} else if vm := f.VersionMin(); vm != nil {
					cfg.RuntimeVersion = vm.Sdk
				}
			}
		} else {
			cfg.RuntimeVersion = 0
		}
		cs = &CodeSignature{
			CodeSignatureCmd: types.CodeSignatureCmd{
				LoadCmd: types.LC_CODE_SIGNATURE,
				Len:     uint32(binary.Size(types.CodeSignatureCmd{})),
			},
		}
		signatureOffset := linkedit.Offset + linkedit.Filesz
		if signatureOffset < linkedit.Offset {
			return fmt.Errorf("__LINKEDIT file range overflows at offset %#x size %#x", linkedit.Offset, linkedit.Filesz)
		}
		signatureOffset, retErr = checkedAlign(signatureOffset, 16)
		if retErr != nil {
			return retErr
		}
		if signatureOffset > math.MaxUint32 {
			return fmt.Errorf("code signature offset %#x cannot be represented by LC_CODE_SIGNATURE", signatureOffset)
		}
		cs.Offset = uint32(signatureOffset)
		if err := f.validateCodeSignatureLoadSpace(text, cs.LoadSize()); err != nil {
			return err
		}
	}

	linkeditEnd := linkedit.Offset + linkedit.Filesz
	if linkeditEnd < linkedit.Offset {
		return fmt.Errorf("__LINKEDIT file range overflows at offset %#x size %#x", linkedit.Offset, linkedit.Filesz)
	}
	signatureOffset := uint64(cs.Offset)
	if signatureOffset < linkedit.Offset {
		return fmt.Errorf("LC_CODE_SIGNATURE offset %#x precedes __LINKEDIT offset %#x", signatureOffset, linkedit.Offset)
	}
	if existing := f.CodeSignature(); existing != nil {
		signatureEnd := signatureOffset + uint64(cs.Size)
		if signatureEnd < signatureOffset {
			return fmt.Errorf("LC_CODE_SIGNATURE range overflows at offset %#x size %#x", signatureOffset, cs.Size)
		}
		if signatureEnd > linkeditEnd {
			return fmt.Errorf("LC_CODE_SIGNATURE range [%#x,%#x) exceeds __LINKEDIT range [%#x,%#x)", signatureOffset, signatureEnd, linkedit.Offset, linkeditEnd)
		}
	}

	cfg.CodeSize = signatureOffset

	// cache __LINKEDIT data (up to but not including any existing code signature) for saving later.
	// if the actual data doesn't go up to a page boundary (because we're adding a new signature), pad it with zeroes
	ledataLength := signatureOffset - linkedit.Offset
	maxInt := uint64(^uint(0) >> 1)
	if ledataLength > maxInt {
		return fmt.Errorf("__LINKEDIT prefix size %#x exceeds platform allocation limit", ledataLength)
	}
	size := ledataLength
	if size > linkedit.Filesz {
		size = linkedit.Filesz
	}
	var ledata []byte
	if ledataLength < safeAllocChunk {
		ledata = make([]byte, int(ledataLength))
		if n, err := f.cr.ReadAtAddr(ledata[:size], linkedit.Addr); err != nil {
			return fmt.Errorf("failed to read __LINKEDIT data: read=%d, %v", n, err)
		}
	} else {
		// Same bytes as above, but the part backed by the file is read in
		// chunks first so a bogus size fails before it is allocated.
		prefix, err := readDataAtAddr(f.cr, size, linkedit.Addr)
		if err != nil {
			return fmt.Errorf("failed to read __LINKEDIT data: read=%d, %v", len(prefix), err)
		}
		ledata = append(prefix, make([]byte, int(ledataLength-size))...)
	}

	estimatedSignatureSize := codesign.EstimateCodeSignatureSize(cfg)
	if estimatedSignatureSize == math.MaxUint64 || ledataLength > math.MaxUint64-estimatedSignatureSize {
		return fmt.Errorf("estimated code signature size overflows __LINKEDIT")
	}
	newLinkeditFilesz, err := checkedAlign(ledataLength+estimatedSignatureSize, f.pageSize())
	if err != nil {
		return fmt.Errorf("failed to align __LINKEDIT file size: %w", err)
	}
	newLinkeditMemsz, err := checkedAlign(newLinkeditFilesz, f.pageSize())
	if err != nil {
		return fmt.Errorf("failed to align __LINKEDIT memory size: %w", err)
	}
	newLinkeditEnd := linkedit.Offset + newLinkeditFilesz
	if newLinkeditEnd < linkedit.Offset || newLinkeditEnd < signatureOffset {
		return fmt.Errorf("new __LINKEDIT range overflows or ends before LC_CODE_SIGNATURE")
	}
	newSignatureSize := newLinkeditEnd - signatureOffset
	if newSignatureSize > math.MaxUint32 || newLinkeditFilesz > maxInt {
		return fmt.Errorf("new code signature or __LINKEDIT size cannot be represented")
	}

	originalHeader := f.FileHeader
	originalLoads := append(loads(nil), f.Loads...)
	originalLinkeditFilesz, originalLinkeditMemsz := linkedit.Filesz, linkedit.Memsz
	originalLEData := f.ledata
	originalCodeSignatureCmd := cs.CodeSignatureCmd
	committed := false
	defer func() {
		if committed {
			return
		}
		f.FileHeader = originalHeader
		f.Loads = originalLoads
		linkedit.Filesz = originalLinkeditFilesz
		linkedit.Memsz = originalLinkeditMemsz
		cs.CodeSignatureCmd = originalCodeSignatureCmd
		f.ledata = originalLEData
	}()

	if f.CodeSignature() == nil {
		f.AddLoad(cs)
	}
	linkedit.Filesz = newLinkeditFilesz
	linkedit.Memsz = newLinkeditMemsz
	cs.Size = uint32(newSignatureSize)

	// read data to be signed; pad to beginning of code signature if necessary (in case we added a signature to a not-page-aligned-size file)
	if signatureOffset > maxInt {
		return fmt.Errorf("code signing range %#x exceeds platform allocation limit", signatureOffset)
	}
	readLength := linkedit.Offset + size
	if readLength < linkedit.Offset || readLength > signatureOffset {
		return fmt.Errorf("code signing read range %#x is outside signature offset %#x", readLength, signatureOffset)
	}
	var data []byte
	if signatureOffset < safeAllocChunk {
		data = make([]byte, int(signatureOffset))
		if _, err := f.ReadAt(data[:int(readLength)], 0); err != nil {
			return fmt.Errorf("failed to read codesign data: %v", err)
		}
	} else {
		prefix, err := readDataAt(f, readLength, 0)
		if err != nil {
			return fmt.Errorf("failed to read codesign data: %v", err)
		}
		data = append(prefix, make([]byte, int(signatureOffset-readLength))...)
	}
	// write modified file header and load commands (including __LINKEDIT and CodeSignature), since they are covered by hashes
	var buf bytes.Buffer
	if err := f.writeCodeSignFileHeader(&buf); err != nil {
		return fmt.Errorf("failed to write updated header: %v", err)
	}
	if err := f.writeLoadCommands(&buf); err != nil {
		return fmt.Errorf("failed to write updated load commands: %v", err)
	}
	if uint64(buf.Len()) > signatureOffset {
		return fmt.Errorf("updated Mach-O header and load commands end at %#x, after code signature offset %#x", buf.Len(), signatureOffset)
	}
	copy(data, buf.Bytes())

	// sign data and add it to the new LINKEDIT segment
	csdata, err := codesign.Sign(bytes.NewReader(data), cfg)
	if err != nil {
		return fmt.Errorf("failed to create codesignature data: %w", err)
	}
	newLEData := bytes.NewBuffer(ledata)
	if uint64(len(csdata)) > newSignatureSize {
		return fmt.Errorf("new code signature data is larger than the allocated LC_CODE_SIGNATURE region")
	}
	if _, err := newLEData.Write(csdata); err != nil {
		return fmt.Errorf("failed to write codesign data to linkedit segment data: %v", err)
	}

	if linkedit.Filesz < uint64(newLEData.Len()) {
		return fmt.Errorf("new linkedit data is larger than expected")
	} else if linkedit.Filesz > uint64(newLEData.Len()) { // pad with zeros
		padding := linkedit.Filesz - uint64(newLEData.Len())
		if padding > maxInt {
			return fmt.Errorf("new __LINKEDIT padding %#x exceeds platform allocation limit", padding)
		}
		if _, err := newLEData.Write(make([]byte, int(padding))); err != nil {
			return fmt.Errorf("failed to write linkedit segment padding: %v", err)
		}
	}

	f.ledata = newLEData
	*config = working
	committed = true
	return nil
}

func (f *File) Save(outpath string) error {
	var buf bytes.Buffer
	if err := f.SaveBuffer(&buf); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outpath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", outpath, err)
	}

	if err := os.WriteFile(outpath, buf.Bytes(), 0755); err != nil {
		return fmt.Errorf("failed to save MachO to file %s: %w", outpath, err)
	}

	return nil
}

func (f *File) SaveBuffer(buf *bytes.Buffer) error {
	if err := f.writeCodeSignFileHeader(buf); err != nil {
		return fmt.Errorf("failed to write file header to buffer: %v", err)
	}

	if err := f.writeLoadCommands(buf); err != nil {
		return fmt.Errorf("failed to write load commands: %v", err)
	}

	endOfLoadsOffset := uint64(buf.Len())

	// Write out segment data to buffer
	for _, seg := range f.Segments() {
		if seg.Filesz > 0 {
			switch seg.Name {
			case "__TEXT":
				dat, err := readDataAtAddr(f.cr, seg.Filesz, seg.Addr)
				if err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				if endOfLoadsOffset > uint64(len(dat)) {
					return fmt.Errorf("load commands end %#x exceeds segment %s data length %#x", endOfLoadsOffset, seg.Name, len(dat))
				}
				if _, err := buf.Write(dat[endOfLoadsOffset:]); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			case "__LINKEDIT":
				if f.ledata != nil && f.ledata.Len() > 0 && f.CodeSignature() != nil {
					if _, err := buf.Write(f.ledata.Bytes()); err != nil {
						return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
					}
				} else {
					dat, err := readDataAtAddr(f.cr, seg.Filesz, seg.Addr)
					if err != nil {
						return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
					}
					if _, err := buf.Write(dat); err != nil {
						return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
					}
				}
			default:
				dat, err := readDataAtAddr(f.cr, seg.Filesz, seg.Addr)
				if err != nil {
					return fmt.Errorf("failed to read segment %s data: %v", seg.Name, err)
				}
				if _, err := buf.Write(dat); err != nil {
					return fmt.Errorf("failed to write segment %s to export buffer: %v", seg.Name, err)
				}
			}
		}
	}

	return nil
}

// exportedSegmentMemsz returns the vmsize of an exported segment whose new,
// page-aligned file size is filesz.
//
// 行为变更说明: 以前凡是 origMemsz > origFilesz 都用 filesz + (origMemsz - origFilesz)。
// filesz 是按页对齐后的大小，当它已经大于 origFilesz 时，对齐补出来的那部分被重复
// 计入：/bin/ls 的 __LINKEDIT（filesz 0x5a60, vmsize 0x8000）导出后 vmsize 变成
// 0xa5a0，既不按页对齐，又大于原值。zerofill 区的地址是固定的（到 段起始 + origMemsz
// 为止），所以这种情况取 max(filesz, origMemsz)，/bin/ls 导出后恢复为 0x8000。
// 其余情况与之前完全相同：filesz <= origFilesz（包括纯 zerofill 段 filesz=0、以及
// 文件大小本来就按页对齐的带 bss 的 __DATA）仍用原公式，没有 zerofill 时仍取 filesz。
func exportedSegmentMemsz(filesz, origFilesz, origMemsz uint64) uint64 {
	switch {
	case origMemsz <= origFilesz:
		return filesz
	case filesz > origFilesz:
		return max(filesz, origMemsz)
	default:
		return filesz + (origMemsz - origFilesz)
	}
}

func (f *File) optimizeLoadCommands(segMap exportSegMap, inCache bool) error {
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)

			off, sz, err := segMap.RemapSeg(seg.Name, seg.Offset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in segment %s: %v", seg.Name, err)
			}
			smi, _ := segMap.Lookup(seg.Name)
			seg.Offset = off
			seg.Filesz = sz
			// preserve extra virtual memory for zerofill sections (.bss etc.)
			seg.Memsz = exportedSegmentMemsz(sz, smi.OrigFilesz, smi.OrigMemsz)

			for i := uint32(0); i < seg.Nsect; i++ {
				sect := f.Sections[i+seg.Firstsect]
				if sect.Offset != 0 {
					if inCache {
						// For in-cache dylibs, section offsets are cache-relative
						// and can't be reliably remapped via segMap (cache offsets
						// from different mappings can collide with segment ranges).
						// Compute from VM addresses instead.
						f.Sections[i+seg.Firstsect].Offset = uint32(seg.Offset + (sect.Addr - seg.Addr))
					} else {
						newOff, err := segMap.Remap(uint64(sect.Offset))
						if err != nil {
							// Fallback to VM-address-based calculation
							newOff = seg.Offset + (sect.Addr - seg.Addr)
						}
						f.Sections[i+seg.Firstsect].Offset = uint32(newOff)
					}
				}
			}
		case types.LC_SYMTAB:
			if !inCache {
				symoff, err := segMap.Remap(uint64(l.(*Symtab).Symoff))
				if err != nil {
					return fmt.Errorf("failed to remap symbol offset in %s: %v", l.Command(), err)
				}
				stroff, err := segMap.Remap(uint64(l.(*Symtab).Stroff))
				if err != nil {
					return fmt.Errorf("failed to remap string offset in %s: %v", l.Command(), err)
				}
				l.(*Symtab).Symoff = uint32(symoff)
				l.(*Symtab).Stroff = uint32(stroff)
			}
		case types.LC_DYSYMTAB:
			if !inCache {
				if l.(*Dysymtab).Tocoffset > 0 {
					tocoffset, err := segMap.Remap(uint64(l.(*Dysymtab).Tocoffset))
					if err != nil {
						return fmt.Errorf("failed to remap Tocoffset in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Tocoffset = uint32(tocoffset)
				}
				if l.(*Dysymtab).Modtaboff > 0 {
					modtaboff, err := segMap.Remap(uint64(l.(*Dysymtab).Modtaboff))
					if err != nil {
						return fmt.Errorf("failed to remap Modtaboff in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Modtaboff = uint32(modtaboff)
				}
				if l.(*Dysymtab).Extrefsymoff > 0 {
					extrefsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Extrefsymoff))
					if err != nil {
						return fmt.Errorf("failed to remap Extrefsymoff in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Extrefsymoff = uint32(extrefsymoff)
				}
				if l.(*Dysymtab).Indirectsymoff > 0 {
					indirectsymoff, err := segMap.Remap(uint64(l.(*Dysymtab).Indirectsymoff))
					if err != nil {
						return fmt.Errorf("failed to remap Indirectsymoff in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Indirectsymoff = uint32(indirectsymoff)
				}
				if l.(*Dysymtab).Extreloff > 0 {
					extreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Extreloff))
					if err != nil {
						return fmt.Errorf("failed to remap Extreloff in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Extreloff = uint32(extreloff)
				}
				if l.(*Dysymtab).Locreloff > 0 {
					locreloff, err := segMap.Remap(uint64(l.(*Dysymtab).Locreloff))
					if err != nil {
						return fmt.Errorf("failed to remap Locreloff in %s: %v", l.Command(), err)
					}
					l.(*Dysymtab).Locreloff = uint32(locreloff)
				}
			}
		case types.LC_CODE_SIGNATURE:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*CodeSignature).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*CodeSignature).Offset = uint32(off)
			}
		case types.LC_SEGMENT_SPLIT_INFO:
			// <rdar://problem/23212513> dylibs iOS 9 dyld caches have bogus LC_SEGMENT_SPLIT_INFO
			// off, err := segMap.Remap(uint64(l.(*SplitInfo).Offset))
			// if err != nil {
			// 	return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			// }
			// l.(*SplitInfo).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*EncryptionInfo).Offset = uint32(off)
		case types.LC_DYLD_INFO:
			if !inCache {
				if l.(*DyldInfo).RebaseOff > 0 {
					rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfo).RebaseOff))
					if err != nil {
						return fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfo).RebaseOff = uint32(rebaseOff)
				}
				if l.(*DyldInfo).BindOff > 0 {
					bindOff, err := segMap.Remap(uint64(l.(*DyldInfo).BindOff))
					if err != nil {
						return fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfo).BindOff = uint32(bindOff)
				}
				if l.(*DyldInfo).WeakBindOff > 0 {
					weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).WeakBindOff))
					if err != nil {
						return fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfo).WeakBindOff = uint32(weakBindOff)
				}
				if l.(*DyldInfo).LazyBindOff > 0 {
					lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfo).LazyBindOff))
					if err != nil {
						return fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfo).LazyBindOff = uint32(lazyBindOff)
				}
				if l.(*DyldInfo).ExportOff > 0 {
					exportOff, err := segMap.Remap(uint64(l.(*DyldInfo).ExportOff))
					if err != nil {
						return fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfo).ExportOff = uint32(exportOff)
				}
			}
		case types.LC_DYLD_INFO_ONLY:
			if !inCache {
				if l.(*DyldInfoOnly).RebaseOff > 0 {
					rebaseOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).RebaseOff))
					if err != nil {
						return fmt.Errorf("failed to remap RebaseOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfoOnly).RebaseOff = uint32(rebaseOff)
				}
				if l.(*DyldInfoOnly).BindOff > 0 {
					bindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).BindOff))
					if err != nil {
						return fmt.Errorf("failed to remap BindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfoOnly).BindOff = uint32(bindOff)
				}
				if l.(*DyldInfoOnly).WeakBindOff > 0 {
					weakBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).WeakBindOff))
					if err != nil {
						return fmt.Errorf("failed to remap WeakBindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfoOnly).WeakBindOff = uint32(weakBindOff)
				}
				if l.(*DyldInfoOnly).LazyBindOff > 0 {
					lazyBindOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).LazyBindOff))
					if err != nil {
						return fmt.Errorf("failed to remap LazyBindOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfoOnly).LazyBindOff = uint32(lazyBindOff)
				}
				if l.(*DyldInfoOnly).ExportOff > 0 {
					exportOff, err := segMap.Remap(uint64(l.(*DyldInfoOnly).ExportOff))
					if err != nil {
						return fmt.Errorf("failed to remap ExportOff in %s: %v", l.Command(), err)
					}
					l.(*DyldInfoOnly).ExportOff = uint32(exportOff)
				}
			}
		case types.LC_FUNCTION_STARTS:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*FunctionStarts).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*FunctionStarts).Offset = uint32(off)
			}
		case types.LC_MAIN:
			// EntryOffset is relative to __TEXT segment start, not an absolute
			// file offset, so it does not need remapping.
		case types.LC_DATA_IN_CODE:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*DataInCode).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*DataInCode).Offset = uint32(off)
			}
		case types.LC_FUNCTION_VARIANTS:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*FunctionVariants).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*FunctionVariants).Offset = uint32(off)
			}
		case types.LC_FUNCTION_VARIANT_FIXUPS:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*FunctionVariantFixups).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*FunctionVariantFixups).Offset = uint32(off)
			}
		case types.LC_LAZY_LOAD_DYLIB_INFO:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*LazyLoadDylibInfo).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*LazyLoadDylibInfo).Offset = uint32(off)
			}
		case types.LC_DYLIB_CODE_SIGN_DRS:
			off, err := segMap.Remap(uint64(l.(*DylibCodeSignDrs).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*DylibCodeSignDrs).Offset = uint32(off)
		case types.LC_ENCRYPTION_INFO_64:
			off, err := segMap.Remap(uint64(l.(*EncryptionInfo64).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*EncryptionInfo64).Offset = uint32(off)
		case types.LC_LINKER_OPTIMIZATION_HINT:
			off, err := segMap.Remap(uint64(l.(*LinkerOptimizationHint).Offset))
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*LinkerOptimizationHint).Offset = uint32(off)
		case types.LC_DYLD_EXPORTS_TRIE:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*DyldExportsTrie).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*DyldExportsTrie).Offset = uint32(off)
			}
		case types.LC_DYLD_CHAINED_FIXUPS:
			if !inCache {
				off, err := segMap.Remap(uint64(l.(*DyldChainedFixups).Offset))
				if err != nil {
					return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
				}
				l.(*DyldChainedFixups).Offset = uint32(off)
			}
		case types.LC_FILESET_ENTRY:
			off, err := segMap.Remap(l.(*FilesetEntry).FileOffset)
			if err != nil {
				return fmt.Errorf("failed to remap offset in %s: %v", l.Command(), err)
			}
			l.(*FilesetEntry).FileOffset = off
		}
	}
	return nil
}

type stub struct {
	ADRP uint64
	LDR  uint64
	BR   uint64
}

type authStub struct {
	ADRP uint32
	ADD  uint32
	LDR  uint32
	BRAA uint32
}

// TODO: 🚧 finish this
func (f *File) optimizeStubs(segMap exportSegMap) (*bytes.Buffer, error) {
	var buf bytes.Buffer

	writeAuthStub := func(saddr, paddr uint64) ([]byte, error) {
		adrpDelta := (paddr & ^uint64(4096)) - (saddr & ^uint64(4096))
		immhi := (adrpDelta >> 9) & (0x00FFFFE0)
		immlo := (adrpDelta << 17) & (0x60000000)
		addOffset := paddr - (paddr & ^uint64(4096))
		imm12 := (addOffset << 10) & 0x3FFC00
		stub := authStub{
			ADRP: 0x90000011 | uint32(immlo|immhi),
			ADD:  0x91000231 | uint32(imm12),
			LDR:  0xF9400230,
			BRAA: 0xD71F0A11,
		}
		if err := binary.Write(&buf, binary.LittleEndian, stub); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	if autGOT := f.Section("__DATA_CONST", "__auth_got"); autGOT != nil {
		data, err := autGOT.Data()
		if err != nil {
			return nil, err
		}
		gots := make([]uint64, autGOT.Size/f.pointerSize())
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &gots); err != nil {
			return nil, err
		}
		for i, got := range gots {
			if got == 0 {
				continue
			}
			writeAuthStub(autGOT.Addr+uint64(i)*f.pointerSize(), got)
		}
	}

	return &buf, nil
}

func (f *File) optimizeObjC(segMap exportSegMap) error {

	// classes, err := f.GetObjCClasses()
	// if err != nil {
	// 	if errors.Is(err, ErrObjcSectionNotFound) {
	// 		return nil
	// 	}
	// 	return err
	// }

	// for _, class := range classes {
	// 	if _, err := f.GetOffset(class.ClassPtr); err != nil {
	// 		fmt.Println(class)
	// 	} else {
	// 		fmt.Println("WRITE TO LINKEDIT")
	// 	}
	// }

	return nil // TODO: impliment this
}

type rebuiltSymEntry struct {
	sym           Symbol
	name          string
	indirectName  string
	originalIndex int
}

func internRebuiltSymbolString(names *bytes.Buffer, offsets map[string]uint32, name string) (uint32, error) {
	if offset, ok := offsets[name]; ok {
		return offset, nil
	}
	const maxUint32 = uint64(^uint32(0))
	current := uint64(names.Len())
	needed := uint64(len(name)) + 1
	if current > maxUint32 || needed > maxUint32-current {
		return 0, fmt.Errorf("rebuilt symbol string table exceeds uint32 size")
	}
	offset := uint32(current)
	if _, err := names.WriteString(name + "\x00"); err != nil {
		return 0, err
	}
	offsets[name] = offset
	return offset, nil
}

func writeRebuiltSymbol(lebuf, names *bytes.Buffer, stringOffsets map[string]uint32, is64 bool, byteOrder binary.ByteOrder, entry rebuiltSymEntry) error {
	if byteOrder == nil {
		return fmt.Errorf("cannot rebuild symbol without a byte order")
	}
	nameOffset, err := internRebuiltSymbolString(names, stringOffsets, entry.name)
	if err != nil {
		return err
	}
	value := entry.sym.Value
	if entry.sym.Type.IsIndirectSym() {
		if entry.indirectName == "" {
			return fmt.Errorf("indirect symbol %q has no target name", entry.name)
		}
		targetOffset, err := internRebuiltSymbolString(names, stringOffsets, entry.indirectName)
		if err != nil {
			return err
		}
		value = uint64(targetOffset)
	}
	nlist := types.Nlist{
		Name: nameOffset,
		Type: entry.sym.Type,
		Sect: entry.sym.Sect,
		Desc: entry.sym.Desc,
	}
	if is64 {
		return binary.Write(lebuf, byteOrder, types.Nlist64{Nlist: nlist, Value: value})
	}
	if value > uint64(^uint32(0)) {
		return fmt.Errorf("symbol %q value %#x does not fit in a 32-bit nlist", entry.name, value)
	}
	return binary.Write(lebuf, byteOrder, types.Nlist32{Nlist: nlist, Value: uint32(value)})
}

func remapIndirectSymbols(indirect, oldToNew []uint32, oldMapped []bool) ([]uint32, error) {
	if len(oldToNew) != len(oldMapped) {
		return nil, fmt.Errorf("invalid symbol-index mapping: %d indices, %d validity entries", len(oldToNew), len(oldMapped))
	}
	remapped := make([]uint32, len(indirect))
	const sentinelMask = uint32(types.INDIRECT_SYMBOL_LOCAL | types.INDIRECT_SYMBOL_ABS)
	for idx, oldIndex := range indirect {
		if oldIndex&sentinelMask != 0 {
			remapped[idx] = oldIndex
			continue
		}
		if uint64(oldIndex) >= uint64(len(oldToNew)) || !oldMapped[oldIndex] {
			return nil, fmt.Errorf("indirect symbol entry %d references removed or out-of-range symbol index %d", idx, oldIndex)
		}
		newIndex := oldToNew[oldIndex]
		if newIndex&sentinelMask != 0 {
			return nil, fmt.Errorf("remapped symbol index %d exceeds indirect-symbol index range", newIndex)
		}
		remapped[idx] = newIndex
	}
	return remapped, nil
}

func (f *File) optimizeLinkedit(locals []Symbol) (*bytes.Buffer, error) {
	var err error
	var lebuf bytes.Buffer
	var newSymNames bytes.Buffer
	var exports []trie.TrieExport

	linkedit := f.Segment("__LINKEDIT")
	if linkedit == nil {
		return nil, fmt.Errorf("unable to find __LINKEDIT segment")
	}
	if f.Dysymtab == nil {
		return nil, fmt.Errorf("binary has no LC_DYSYMTAB")
	}

	// LC_DYLD_CHAINED_FIXUPS is stripped from in-cache exports in Export();
	// no reconstruction needed here.

	// optimize LC_DYLD_EXPORTS_TRIE
	if dexpTrie := f.DyldExportsTrie(); dexpTrie != nil {
		exports, err = f.DyldExports()
		if err != nil {
			return nil, fmt.Errorf("failed to get LC_DYLD_EXPORTS_TRIE exports: %v", err)
		}
		dat, err := readDataAt(f.cr, uint64(dexpTrie.Size), int64(dexpTrie.Offset))
		if err != nil {
			return nil, fmt.Errorf("failed to read LC_DYLD_EXPORTS_TRIE data: %v", err)
		}
		dexpTrie.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_DYLD_EXPORTS_TRIE data: %v", err)
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write LC_DYLD_EXPORTS_TRIE padding: %v", err)
			}
		}
	}
	// optimize LC_DATA_IN_CODE
	if dataNCode := f.DataInCode(); dataNCode != nil {
		dat, err := readDataAt(f.cr, uint64(dataNCode.Size), int64(dataNCode.Offset))
		if err != nil {
			return nil, fmt.Errorf("failed to read LC_DATA_IN_CODE data: %v", err)
		}
		dataNCode.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_DATA_IN_CODE data: %v", err)
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write LC_DATA_IN_CODE padding: %v", err)
			}
		}
	}

	// TODO: LC_DYLIB_CODE_SIGN_DRS
	// TODO: LC_LINKER_OPTIMIZATION_HINT

	// optimize LC_FUNCTION_STARTS
	if fstarts := f.FunctionStarts(); fstarts != nil {
		dat, err := readDataAt(f.cr, uint64(fstarts.Size), int64(fstarts.Offset))
		if err != nil {
			return nil, fmt.Errorf("failed to read LC_FUNCTION_STARTS data: %v", err)
		}
		fstarts.Offset = uint32(linkedit.Offset) + uint32(lebuf.Len())
		if _, err := lebuf.Write(dat); err != nil {
			return nil, fmt.Errorf("failed to write LC_FUNCTION_STARTS data: %v", err)
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write LC_FUNCTION_STARTS padding: %v", err)
			}
		}
	}

	copyLinkEditPayload := func(command types.LoadCmd, offset *uint32, size uint32) error {
		if size == 0 {
			return nil
		}
		dat, err := saferio.ReadDataAt(f.cr, uint64(size), int64(*offset))
		if err != nil {
			return fmt.Errorf("failed to read %s data: %v", command, err)
		}
		newOffset := linkedit.Offset + uint64(lebuf.Len())
		if newOffset > uint64(^uint32(0)) {
			return fmt.Errorf("new %s data offset %#x exceeds uint32", command, newOffset)
		}
		*offset = uint32(newOffset)
		if _, err := lebuf.Write(dat); err != nil {
			return fmt.Errorf("failed to write %s data: %v", command, err)
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return fmt.Errorf("failed to write %s padding: %v", command, err)
			}
		}
		return nil
	}
	copyLinkEditData := func(l *LinkEditData) error {
		return copyLinkEditPayload(l.Command(), &l.Offset, l.Size)
	}

	// optimize LC_FUNCTION_VARIANTS
	if fvars := f.FunctionVariants(); fvars != nil {
		if err := copyLinkEditData(&fvars.LinkEditData); err != nil {
			return nil, err
		}
	}

	// optimize LC_FUNCTION_VARIANT_FIXUPS
	if fvfix := f.FunctionVariantFixups(); fvfix != nil {
		if err := copyLinkEditData(&fvfix.LinkEditData); err != nil {
			return nil, err
		}
	}

	// A binary may contain more than one LC_LAZY_LOAD_DYLIB_INFO command.
	// Their payloads live in the source cache's __LINKEDIT and therefore must
	// all be copied into the rebuilt segment before the old cache data is lost.
	for idx, lazy := range f.LazyLoadDylibInfos() {
		if err := copyLinkEditData(&lazy.LinkEditData); err != nil {
			return nil, fmt.Errorf("failed to rebuild lazy-load dylib info %d: %w", idx, err)
		}
	}

	// Modern shared caches carry valid split-segment v2 payloads. Preserve all
	// commands and relocate their data into the rebuilt __LINKEDIT; retaining an
	// old cache offset would make the exported Mach-O internally inconsistent.
	for idx, load := range f.Loads {
		split, ok := load.(*SplitInfo)
		if !ok {
			continue
		}
		if err := copyLinkEditPayload(split.Command(), &split.Offset, split.Size); err != nil {
			return nil, fmt.Errorf("failed to rebuild split-segment info %d: %w", idx, err)
		}
	}

	// optimize LC_DYLD_INFO|LC_DYLD_INFO_ONLY
	if dinfo := f.DyldInfo(); dinfo != nil {
		if dinfo.RebaseSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dinfo.RebaseSize), int64(dinfo.RebaseOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s rebase data: %v", dinfo.LoadCmd, err)
			}
			dinfo.RebaseOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s rebase data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.BindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dinfo.BindSize), int64(dinfo.BindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.BindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.WeakBindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dinfo.WeakBindSize), int64(dinfo.WeakBindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s weak bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.WeakBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s weak bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.LazyBindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dinfo.LazyBindSize), int64(dinfo.LazyBindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s lazy bind data: %v", dinfo.LoadCmd, err)
			}
			dinfo.LazyBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s lazy bind data: %v", dinfo.LoadCmd, err)
			}
		}
		if dinfo.ExportSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dinfo.ExportSize), int64(dinfo.ExportOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s export data: %v", dinfo.LoadCmd, err)
			}
			dinfo.ExportOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s export data: %v", dinfo.LoadCmd, err)
			}
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write LC_DYLD_INFO padding: %v", err)
			}
		}
	} else if dionly := f.DyldInfoOnly(); dionly != nil {
		if dionly.RebaseSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dionly.RebaseSize), int64(dionly.RebaseOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s rebase data: %v", dionly.LoadCmd, err)
			}
			dionly.RebaseOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s rebase data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.BindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dionly.BindSize), int64(dionly.BindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s bind data: %v", dionly.LoadCmd, err)
			}
			dionly.BindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.WeakBindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dionly.WeakBindSize), int64(dionly.WeakBindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s weak bind data: %v", dionly.LoadCmd, err)
			}
			dionly.WeakBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s weak bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.LazyBindSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dionly.LazyBindSize), int64(dionly.LazyBindOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s lazy bind data: %v", dionly.LoadCmd, err)
			}
			dionly.LazyBindOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s lazy bind data: %v", dionly.LoadCmd, err)
			}
		}
		if dionly.ExportSize > 0 {
			dat, err := readDataAt(f.cr, uint64(dionly.ExportSize), int64(dionly.ExportOff))
			if err != nil {
				return nil, fmt.Errorf("failed to read %s export data: %v", dionly.LoadCmd, err)
			}
			dionly.ExportOff = uint32(linkedit.Offset) + uint32(lebuf.Len())
			if _, err := lebuf.Write(dat); err != nil {
				return nil, fmt.Errorf("failed to write %s export data: %v", dionly.LoadCmd, err)
			}
		}
		if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
			if _, err := lebuf.Write(make([]byte, pad)); err != nil {
				return nil, fmt.Errorf("failed to write LC_DYLD_INFO|LC_DYLD_INFO_ONLY padding: %v", err)
			}
		}
	}

	// TODO: LC_CODE_SIGNATURE

	newSymTabOffset := uint64(lebuf.Len())

	// symbol category counters for DYSYMTAB
	var nLocalSyms, nExtdefSyms, nUndefSyms uint32

	// Collect all symbols into three categories for correct DYSYMTAB ordering:
	// locals first, then external defined, then undefined.
	var localSyms, extdefSyms, undefSyms []rebuiltSymEntry

	// extra symbols (unmapped locals from DSC, or resolved imports from fileset KC)
	for _, lsym := range locals {
		e := rebuiltSymEntry{sym: lsym, name: lsym.Name, indirectName: lsym.IndirectName, originalIndex: -1}
		switch {
		case !lsym.Type.IsExternalSym():
			localSyms = append(localSyms, e)
		case lsym.Type.IsUndefinedSym():
			undefSyms = append(undefSyms, e)
		default:
			extdefSyms = append(extdefSyms, e)
		}
	}
	// original symbol table entries
	var oldToNew []uint32
	var oldMapped []bool
	if f.Symtab != nil {
		oldToNew = make([]uint32, len(f.Symtab.Syms))
		oldMapped = make([]bool, len(f.Symtab.Syms))
		for originalIndex, sym := range f.Symtab.Syms {
			if sym.Name == "<redacted>" {
				continue
			}
			e := rebuiltSymEntry{
				sym:           sym,
				name:          sym.Name,
				indirectName:  sym.IndirectName,
				originalIndex: originalIndex,
			}
			switch {
			case !sym.Type.IsExternalSym():
				localSyms = append(localSyms, e)
			case sym.Type.IsUndefinedSym():
				undefSyms = append(undefSyms, e)
			default:
				extdefSyms = append(extdefSyms, e)
			}
		}
	}
	// re-exports from LC_DYLD_EXPORTS_TRIE (external defined)
	for _, exp := range exports {
		if exp.Flags.ReExport() {
			targetName := exp.ReExport
			if targetName == "" {
				targetName = exp.Name
			}
			extdefSyms = append(extdefSyms, rebuiltSymEntry{
				sym: Symbol{
					Name: exp.Name,
					Type: (types.N_INDR | types.N_EXT),
					Sect: 0,
					Desc: 0,
				},
				name:          exp.Name,
				indirectName:  targetName,
				originalIndex: -1,
			})
		}
	}

	nLocalSyms = uint32(len(localSyms))
	nExtdefSyms = uint32(len(extdefSyms))
	nUndefSyms = uint32(len(undefSyms))

	// first pool entry is always empty string
	newSymNames.WriteString("\x00")
	stringOffsets := map[string]uint32{"": 0}
	// write symbols in DYSYMTAB order: locals, external defined, undefined
	var newSymbolIndex uint32
	writeSym := func(e rebuiltSymEntry) error {
		if err := writeRebuiltSymbol(&lebuf, &newSymNames, stringOffsets, f.is64bit(), f.ByteOrder, e); err != nil {
			return err
		}
		if e.originalIndex >= 0 {
			oldToNew[e.originalIndex] = newSymbolIndex
			oldMapped[e.originalIndex] = true
		}
		newSymbolIndex++
		return nil
	}
	for _, e := range localSyms {
		if err := writeSym(e); err != nil {
			return nil, fmt.Errorf("failed to write local symbol to NEW linkedit data: %v", err)
		}
	}
	for _, e := range extdefSyms {
		if err := writeSym(e); err != nil {
			return nil, fmt.Errorf("failed to write extdef symbol to NEW linkedit data: %v", err)
		}
	}
	for _, e := range undefSyms {
		if err := writeSym(e); err != nil {
			return nil, fmt.Errorf("failed to write undef symbol to NEW linkedit data: %v", err)
		}
	}

	if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write symtab padding: %v", err)
		}
	}

	newIndSymTabOffset := uint64(lebuf.Len())

	// Every ordinary indirect-table entry is an index into the original
	// symtab. Symbols were just grouped into local/extdef/undef buckets and may
	// also have had entries inserted or removed, so a fixed shift is invalid.
	remappedIndirect, err := remapIndirectSymbols(f.Dysymtab.IndirectSyms, oldToNew, oldMapped)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(&lebuf, f.ByteOrder, remappedIndirect); err != nil {
		return nil, fmt.Errorf("failed to write indirect symbol table to NEW linkedit data: %v", err)
	}
	f.Dysymtab.IndirectSyms = remappedIndirect

	if pad := pointerAlignPad(lebuf.Len(), f.pointerSize()); pad > 0 {
		if _, err := lebuf.Write(make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("failed to write indirect symtab padding: %v", err)
		}
	}

	newStringPoolOffset := uint64(lebuf.Len())

	// pointer align string pool size
	for (uint64(newSymNames.Len()) % f.pointerSize()) != 0 {
		newSymNames.WriteString("\x00")
	}
	// Copy sym names
	if _, err := lebuf.Write(newSymNames.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write symbol name strings to NEW linkedit data: %v", err)
	}

	if f.Symtab != nil {
		f.Symtab.Nsyms = nLocalSyms + nExtdefSyms + nUndefSyms
		f.Symtab.Symoff = uint32(linkedit.Offset + newSymTabOffset)
		f.Symtab.Stroff = uint32(linkedit.Offset + newStringPoolOffset)
		f.Symtab.Strsize = uint32(newSymNames.Len())
	}
	// Apple convention: when LC_DATA_IN_CODE has no data, set dataoff = symoff
	if dataNCode := f.DataInCode(); dataNCode != nil && dataNCode.Size == 0 && f.Symtab != nil {
		dataNCode.Offset = f.Symtab.Symoff
	}
	f.Dysymtab.Ilocalsym = 0
	f.Dysymtab.Nlocalsym = nLocalSyms
	f.Dysymtab.Iextdefsym = nLocalSyms
	f.Dysymtab.Nextdefsym = nExtdefSyms
	f.Dysymtab.Iundefsym = nLocalSyms + nExtdefSyms
	f.Dysymtab.Nundefsym = nUndefSyms
	f.Dysymtab.Extreloff = 0
	f.Dysymtab.Nextrel = 0
	f.Dysymtab.Locreloff = 0
	f.Dysymtab.Nlocrel = 0
	f.Dysymtab.Nindirectsyms = uint32(len(f.Dysymtab.IndirectSyms))
	f.Dysymtab.Indirectsymoff = uint32(linkedit.Offset + newIndSymTabOffset)

	linkedit.Filesz = uint64(lebuf.Len())
	linkedit.Memsz = pageAlign(linkedit.Filesz, f.pageSize())

	return &lebuf, nil
}

func (f *File) writeLoadCommands(buf *bytes.Buffer) error {
	for _, l := range f.Loads {
		switch l.Command() {
		case types.LC_SEGMENT:
			fallthrough
		case types.LC_SEGMENT_64:
			seg := l.(*Segment)
			if err := seg.Write(buf, f.ByteOrder); err != nil {
				return err
			}
			for _, sect := range seg.Sections {
				if err := f.Section(sect.Seg, sect.Name).Write(buf, f.ByteOrder); err != nil {
					return err
				}
			}
		default:
			if err := l.Write(buf, f.ByteOrder); err != nil {
				return err
			}
		}
	}
	return nil
}
