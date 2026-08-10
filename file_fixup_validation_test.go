package macho

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/zdypro888/go-macho/pkg/fixupchains"
	"github.com/zdypro888/go-macho/types"
)

type boundedReadRecorder struct {
	maxRead int
}

func (r *boundedReadRecorder) Read([]byte) (int, error) { return 0, io.EOF }

func (r *boundedReadRecorder) ReadAt(p []byte, _ int64) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	return 0, io.EOF
}

func (r *boundedReadRecorder) Seek(offset int64, _ int) (int64, error) { return offset, nil }

func (r *boundedReadRecorder) SeekToAddr(uint64) error { return nil }

func (r *boundedReadRecorder) ReadAtAddr(p []byte, addr uint64) (int, error) {
	return r.ReadAt(p, int64(addr))
}

func makeLazyLoadBlob(t *testing.T, terminatePath, terminateSymbol bool) []byte {
	t.Helper()
	data := make([]byte, 36)
	binary.LittleEndian.PutUint32(data[0:4], 28) // load path
	binary.LittleEndian.PutUint32(data[4:8], 0)  // loaded flag
	binary.LittleEndian.PutUint16(data[10:12], uint16(fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND))
	binary.LittleEndian.PutUint32(data[12:16], 0) // no chain
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], 24)
	binary.LittleEndian.PutUint32(data[24:28], 32)
	copy(data[28:32], []byte{'l', 'i', 'b', 0})
	copy(data[32:36], []byte{'s', 'y', 'm', 0})
	if !terminatePath {
		data[31] = 'x'
		data = data[:32]
	}
	if !terminateSymbol {
		data[35] = 'x'
	}
	return data
}

func TestParseLazyLoadDylibInfoRequiresTerminatedStrings(t *testing.T) {
	if _, err := ParseLazyLoadDylibInfo(makeLazyLoadBlob(t, false, true), binary.LittleEndian); err == nil || !strings.Contains(err.Error(), "load path is not NUL terminated") {
		t.Fatalf("unterminated path error = %v", err)
	}
	if _, err := ParseLazyLoadDylibInfo(makeLazyLoadBlob(t, true, false), binary.LittleEndian); err == nil || !strings.Contains(err.Error(), "symbol 0 is not NUL terminated") {
		t.Fatalf("unterminated symbol error = %v", err)
	}
	parsed, err := ParseLazyLoadDylibInfo(makeLazyLoadBlob(t, true, true), binary.LittleEndian)
	if err != nil {
		t.Fatalf("valid lazy-load blob: %v", err)
	}
	if parsed.LoadPath != "lib" || len(parsed.Symbols) != 1 || parsed.Symbols[0] != "sym" {
		t.Fatalf("parsed lazy-load strings = %#v", parsed)
	}
}

func TestValidateLazyLoadImageOffsets(t *testing.T) {
	f := &File{FileTOC: FileTOC{Loads: loads{
		&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Addr: 0x100000000, Memsz: 0x8000}},
		&Segment{SegmentHeader: types.SegmentHeader{Name: "__LINKEDIT", Addr: 0x100008000, Memsz: 0x100000}},
	}}}
	if err := f.validateLazyLoadImageOffsets(&LazyLoadedDylib{FlagImageOffset: 0x8001}); err == nil || !strings.Contains(err.Error(), "flag image offset") {
		t.Fatalf("flag offset error = %v", err)
	}
	if err := f.validateLazyLoadImageOffsets(&LazyLoadedDylib{ChainStartImageOffset: 0x8001}); err == nil || !strings.Contains(err.Error(), "chain start image offset") {
		t.Fatalf("chain offset error = %v", err)
	}
	if err := f.validateLazyLoadImageOffsets(&LazyLoadedDylib{FlagImageOffset: 0x8000, ChainStartImageOffset: 0x8000}); err != nil {
		t.Fatalf("boundary offsets: %v", err)
	}
}

func TestGetLazyLoadedDylibsConcurrentCache(t *testing.T) {
	blob := makeLazyLoadBlob(t, true, true)
	vma := &types.VMAddrConverter{
		Converter:    func(value uint64) uint64 { return value },
		VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
		Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(blob), vma, 0, int64(len(blob)))
	info := &LazyLoadDylibInfo{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
		LoadCmd: types.LC_LAZY_LOAD_DYLIB_INFO,
		Offset:  0,
		Size:    uint32(len(blob)),
	}}}
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads: loads{
				&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Addr: 0, Memsz: 0x8000}},
				info,
			},
		},
		vma: vma,
		cr:  reader,
		sr:  reader,
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := f.GetLazyLoadedDylibs()
			if err != nil {
				t.Errorf("GetLazyLoadedDylibs: %v", err)
				return
			}
			if len(got) != 1 || got[0].LoadPath != "lib" {
				t.Errorf("lazy-load result = %#v", got)
			}
		}()
	}
	wg.Wait()
}

func TestParseRebaseRejectsOutOfRangeSegment(t *testing.T) {
	f := &File{FileTOC: FileTOC{Loads: loads{
		&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT"}},
	}}}
	opcodes := []byte{types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0x0f, 0}
	if _, err := f.parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "segment index 15 out of range") {
		t.Fatalf("parseRebase segment error = %v", err)
	}
}

func TestReadClassicRebaseTargetDoesNotMoveReaderCursor(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[8:], 0x1122334455667788)
	vma := &types.VMAddrConverter{
		Converter:    func(value uint64) uint64 { return value },
		VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
		Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
	if _, err := reader.Seek(3, 0); err != nil {
		t.Fatalf("position reader: %v", err)
	}
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads: loads{&Segment{SegmentHeader: types.SegmentHeader{
				Name: "__DATA", Addr: 0x1000, Memsz: 16, Offset: 8, Filesz: 16,
			}}},
		},
		cr: reader,
	}
	rebase := &types.Rebase{Type: types.REBASE_TYPE_POINTER, Segment: "__DATA"}
	if err := f.readClassicRebaseTarget(rebase); err != nil {
		t.Fatalf("readClassicRebaseTarget: %v", err)
	}
	if rebase.Value != 0x1122334455667788 {
		t.Fatalf("target = %#x", rebase.Value)
	}
	position, err := reader.Seek(0, 1)
	if err != nil {
		t.Fatalf("query cursor: %v", err)
	}
	if position != 3 {
		t.Fatalf("reader cursor moved to %d, want 3", position)
	}
}

func testClassicRebaseFile(t *testing.T, filesz uint64) *File {
	t.Helper()
	data := make([]byte, 32)
	vma := &types.VMAddrConverter{
		Converter:    func(value uint64) uint64 { return value },
		VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
		Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
	return &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads: loads{&Segment{SegmentHeader: types.SegmentHeader{
				Name: "__DATA", Addr: 0x1000, Memsz: filesz, Filesz: filesz,
			}}},
		},
		cr: reader,
	}
}

func classicRebasePrefix(offset uint64) []byte {
	opcodes := []byte{
		types.REBASE_OPCODE_SET_TYPE_IMM | types.REBASE_TYPE_POINTER,
		types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
	}
	return appendTestULEB(opcodes, offset)
}

func TestParseRebaseValidatesStateAndBoundsBeforeAppending(t *testing.T) {
	t.Run("missing segment", func(t *testing.T) {
		opcodes := []byte{
			types.REBASE_OPCODE_SET_TYPE_IMM | types.REBASE_TYPE_POINTER,
			types.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
		}
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "missing REBASE_OPCODE_SET_SEGMENT") {
			t.Fatalf("missing rebase segment error = %v", err)
		}
	})

	t.Run("empty segment name is valid", func(t *testing.T) {
		f := testClassicRebaseFile(t, 8)
		f.Segments()[0].Name = ""
		opcodes := append(classicRebasePrefix(0), types.REBASE_OPCODE_DO_REBASE_IMM_TIMES|1)
		rebases, err := f.parseRebase(bytes.NewReader(opcodes))
		if err != nil {
			t.Fatalf("empty-named rebase segment: %v", err)
		}
		if len(rebases) != 1 || rebases[0].Segment != "" || rebases[0].SegmentIndex != 0 {
			t.Fatalf("empty-named rebase segment result = %#v", rebases)
		}
	})

	t.Run("missing type", func(t *testing.T) {
		opcodes := []byte{types.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0, types.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1}
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "unknown classic rebase type 0") {
			t.Fatalf("missing rebase type error = %v", err)
		}
	})

	t.Run("offset addition overflow", func(t *testing.T) {
		opcodes := append(classicRebasePrefix(1), types.REBASE_OPCODE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, math.MaxUint64)
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "overflows") {
			t.Fatalf("overflowing rebase offset error = %v", err)
		}
	})

	t.Run("bind-and-advance overflow", func(t *testing.T) {
		opcodes := append(classicRebasePrefix(0), types.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, math.MaxUint64)
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "pointer size overflows") {
			t.Fatalf("overflowing rebase advance error = %v", err)
		}
	})

	t.Run("huge repeat count", func(t *testing.T) {
		opcodes := append(classicRebasePrefix(0), types.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)
		opcodes = appendTestULEB(opcodes, math.MaxUint64)
		opcodes = appendTestULEB(opcodes, 0)
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(opcodes)); err == nil || !strings.Contains(err.Error(), "repeat count") {
			t.Fatalf("huge rebase count error = %v", err)
		}
	})

	t.Run("done padding boundary", func(t *testing.T) {
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(make([]byte, 16))); err != nil {
			t.Fatalf("DONE plus 15-byte padding: %v", err)
		}
		if _, err := testClassicRebaseFile(t, 8).parseRebase(bytes.NewReader(make([]byte, 17))); err == nil || !strings.Contains(err.Error(), "terminated early") {
			t.Fatalf("DONE plus 16-byte padding error = %v", err)
		}
	})
}

func makeChainedStartsPayload(t *testing.T, format fixupchains.DCPtrKind) []byte {
	return makeChainedStartsPayloadWithMax(t, format, 0)
}

func makeChainedStartsPayloadWithMax(t *testing.T, format fixupchains.DCPtrKind, maxValidPointer uint32) []byte {
	t.Helper()
	headerSize := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}))
	recordSize := uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{})) + 2
	header := fixupchains.DyldChainedFixupsHeader{
		StartsOffset:  headerSize,
		ImportsOffset: headerSize + 8 + recordSize,
		SymbolsOffset: headerSize + 8 + recordSize,
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}
	record := fixupchains.DyldChainedStartsInSegment{
		Size:            recordSize,
		PageSize:        0x1000,
		PointerFormat:   format,
		MaxValidPointer: maxValidPointer,
		PageCount:       1,
	}
	var payload bytes.Buffer
	for _, value := range []any{
		header,
		uint32(1),
		uint32(8),
		record,
		fixupchains.DYLD_CHAINED_PTR_START_NONE,
	} {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatalf("write chained payload: %v", err)
		}
	}
	return payload.Bytes()
}

func makeEmptyChainedStartsPayload(t *testing.T, segmentCount uint32) []byte {
	t.Helper()
	headerSize := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}))
	startsSize := uint32(4) + segmentCount*4
	header := fixupchains.DyldChainedFixupsHeader{
		StartsOffset:  headerSize,
		ImportsOffset: headerSize + startsSize,
		SymbolsOffset: headerSize + startsSize,
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.LittleEndian, header); err != nil {
		t.Fatalf("write chained header: %v", err)
	}
	if err := binary.Write(&payload, binary.LittleEndian, segmentCount); err != nil {
		t.Fatalf("write chained segment count: %v", err)
	}
	if err := binary.Write(&payload, binary.LittleEndian, make([]uint32, segmentCount)); err != nil {
		t.Fatalf("write chained segment offsets: %v", err)
	}
	return payload.Bytes()
}

func fileWithChainedPayload(t *testing.T, payload []byte, segments ...*Segment) *File {
	t.Helper()
	vma := &types.VMAddrConverter{
		Converter:    func(value uint64) uint64 { return value },
		VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
		Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(payload), vma, 0, int64(len(payload)))
	allLoads := make(loads, 0, len(segments)+1)
	for _, segment := range segments {
		allLoads = append(allLoads, segment)
	}
	allLoads = append(allLoads, &DyldChainedFixups{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
		LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
		Offset:  0,
		Size:    uint32(len(payload)),
	}}})
	return &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads:      allLoads,
		},
		vma: vma,
		cr:  reader,
		sr:  reader,
	}
}

func TestDyldChainedFixupsValidatesImageContext(t *testing.T) {
	t.Run("too many starts segments", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeChainedStartsPayload(t, fixupchains.DYLD_CHAINED_PTR_64))
		if _, err := f.DyldChainedFixups(); err == nil || !strings.Contains(err.Error(), "segment count 1 exceeds Mach-O segment count 0") {
			t.Fatalf("segment-count error = %v", err)
		}
	})

	t.Run("pointer width mismatch", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeChainedStartsPayload(t, fixupchains.DYLD_CHAINED_PTR_32),
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Memsz: 0x1000, Filesz: 0x1000}})
		if _, err := f.DyldChainedFixups(); err == nil || !strings.Contains(err.Error(), "uses 4-byte pointers in a 8-byte Mach-O") {
			t.Fatalf("pointer-width error = %v", err)
		}
	})

	t.Run("multiple zero-size post-link insertions", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeEmptyChainedStartsPayload(t, 2),
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Memsz: 0x1000}},
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__ZERO_A"}},
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__ZERO_B"}},
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__LINKEDIT", Memsz: 0x1000}},
		)
		if _, err := f.DyldChainedFixups(); err != nil {
			t.Fatalf("zero-size post-link segments: %v", err)
		}
	})

	t.Run("nonzero CTF insertion", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeEmptyChainedStartsPayload(t, 2),
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Memsz: 0x1000}},
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__CTF", Memsz: 0x1000}},
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__LINKEDIT", Memsz: 0x1000}},
		)
		if _, err := f.DyldChainedFixups(); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("nonzero CTF error = %v", err)
		}
	})

	t.Run("max valid pointer below last data", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeChainedStartsPayloadWithMax(t, fixupchains.DYLD_CHAINED_PTR_32, 0x2000),
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__DATA", Addr: 0x1000, Memsz: 0x2000, Filesz: 0x1000}},
		)
		f.Magic = types.Magic32
		if _, err := f.DyldChainedFixups(); err == nil || !strings.Contains(err.Error(), "below last data VM address") {
			t.Fatalf("small max_valid_pointer error = %v", err)
		}
	})

	t.Run("max valid pointer boundary", func(t *testing.T) {
		f := fileWithChainedPayload(t, makeChainedStartsPayloadWithMax(t, fixupchains.DYLD_CHAINED_PTR_32, 0x3000),
			&Segment{SegmentHeader: types.SegmentHeader{Name: "__DATA", Addr: 0x1000, Memsz: 0x2000, Filesz: 0x1000}},
		)
		f.Magic = types.Magic32
		if _, err := f.DyldChainedFixups(); err != nil {
			t.Fatalf("boundary max_valid_pointer: %v", err)
		}
	})
}

func TestSegmentedRebaseUsesTargetSegmentWithoutStarts(t *testing.T) {
	headerSize := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}))
	recordSize := uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{})) + 2
	header := fixupchains.DyldChainedFixupsHeader{
		StartsOffset:  headerSize,
		ImportsOffset: headerSize + 12 + recordSize,
		SymbolsOffset: headerSize + 12 + recordSize,
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}
	record := fixupchains.DyldChainedStartsInSegment{
		Size:          recordSize,
		PageSize:      0x1000,
		PointerFormat: fixupchains.DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
		PageCount:     1,
	}
	var payload bytes.Buffer
	for _, value := range []any{
		header,
		uint32(2),
		uint32(12),
		uint32(0), // target segment has no fixup starts record
		record,
		fixupchains.DYLD_CHAINED_PTR_START_NONE,
	} {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatalf("write segmented chained payload: %v", err)
		}
	}
	f := fileWithChainedPayload(t, payload.Bytes(),
		&Segment{SegmentHeader: types.SegmentHeader{Name: "__TEXT", Addr: 0x100000000, Memsz: 0x1000}},
		&Segment{SegmentHeader: types.SegmentHeader{Name: "__DATA", Addr: 0x100004000, Memsz: 0x1000}},
	)
	dcf, err := f.DyldChainedFixups()
	if err != nil {
		t.Fatalf("DyldChainedFixups: %v", err)
	}
	if got := dcf.Starts[1].SegmentVMOffset; got != 0x4000 {
		t.Fatalf("target segment runtime offset = %#x, want %#x", got, uint64(0x4000))
	}
	raw := uint64(0x120) | uint64(1)<<28
	got, err := dcf.ResolveRawRebaseVMAddress(raw, f.GetBaseAddress(), 0)
	if err != nil {
		t.Fatalf("ResolveRawRebaseVMAddress: %v", err)
	}
	if want := uint64(0x100004120); got != want {
		t.Fatalf("segmented target = %#x, want %#x", got, want)
	}
}

func TestLinkeditReadersChunkUntrustedSizes(t *testing.T) {
	const (
		hugeSize = ^uint32(0)
		maxChunk = 10 << 20
	)
	tests := []struct {
		name  string
		loads loads
		read  func(*File) error
	}{
		{
			name: "chained fixups",
			loads: loads{&DyldChainedFixups{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
				LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
				Size:    hugeSize,
			}}}},
			read: func(f *File) error {
				_, err := f.DyldChainedFixups()
				return err
			},
		},
		{
			name: "bind info",
			loads: loads{&DyldInfo{DyldInfoCmd: types.DyldInfoCmd{
				LoadCmd:  types.LC_DYLD_INFO,
				BindSize: hugeSize,
			}}},
			read: func(f *File) error {
				_, err := f.GetBindInfo()
				return err
			},
		},
		{
			name: "rebase info",
			loads: loads{&DyldInfo{DyldInfoCmd: types.DyldInfoCmd{
				LoadCmd:    types.LC_DYLD_INFO,
				RebaseSize: hugeSize,
			}}},
			read: func(f *File) error {
				_, err := f.GetRebaseInfo()
				return err
			},
		},
		{
			name: "classic exports",
			loads: loads{&DyldInfo{DyldInfoCmd: types.DyldInfoCmd{
				LoadCmd:    types.LC_DYLD_INFO,
				ExportSize: hugeSize,
			}}},
			read: func(f *File) error {
				_, err := f.GetExports()
				return err
			},
		},
		{
			name: "classic exports info only",
			loads: loads{&DyldInfoOnly{DyldInfo: DyldInfo{DyldInfoCmd: types.DyldInfoCmd{
				LoadCmd:    types.LC_DYLD_INFO_ONLY,
				ExportSize: hugeSize,
			}}}},
			read: func(f *File) error {
				_, err := f.GetExports()
				return err
			},
		},
		{
			name: "modern exports",
			loads: loads{&DyldExportsTrie{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
				LoadCmd: types.LC_DYLD_EXPORTS_TRIE,
				Size:    hugeSize,
			}}}},
			read: func(f *File) error {
				_, err := f.DyldExports()
				return err
			},
		},
		{
			name: "modern export lookup",
			loads: loads{&DyldExportsTrie{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
				LoadCmd: types.LC_DYLD_EXPORTS_TRIE,
				Size:    hugeSize,
			}}}},
			read: func(f *File) error {
				_, err := f.GetDyldExport("_symbol")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := new(boundedReadRecorder)
			f := &File{
				FileTOC: FileTOC{ByteOrder: binary.LittleEndian, Loads: test.loads},
				cr:      reader,
				sr:      reader,
			}
			if err := test.read(f); err == nil {
				t.Fatal("huge truncated payload unexpectedly succeeded")
			}
			if reader.maxRead == 0 || reader.maxRead > maxChunk {
				t.Fatalf("largest read request = %d, want 1..%d", reader.maxRead, maxChunk)
			}
			if f.dcf != nil || f.exp != nil || f.exptrieData != nil || f.bindsDone || f.rebasesDone {
				t.Fatal("failed read published a parser cache")
			}
		})
	}
}

func appendTestULEB(dst []byte, value uint64) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		dst = append(dst, b)
		if value == 0 {
			return dst
		}
	}
}

func testClassicBindFile(memsz uint64) *File {
	return &File{FileTOC: FileTOC{
		FileHeader: types.FileHeader{Magic: types.Magic64},
		ByteOrder:  binary.LittleEndian,
		Loads: loads{&Segment{SegmentHeader: types.SegmentHeader{
			Name: "__DATA", Addr: 0x100000000, Memsz: memsz,
		}}},
	}}
}

func ordinaryBindPrefix(offset uint64) []byte {
	opcodes := []byte{
		types.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
		types.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
		'_', 's', 'y', 'm', 0,
		types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
	}
	return appendTestULEB(opcodes, offset)
}

func TestParseBindsValidatesStateAndBoundsBeforeAppending(t *testing.T) {
	t.Run("empty segment name is valid", func(t *testing.T) {
		f := testClassicBindFile(8)
		f.Segments()[0].Name = ""
		opcodes := append(ordinaryBindPrefix(0), types.BIND_OPCODE_DO_BIND)
		binds, _, err := f.parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err != nil {
			t.Fatalf("empty-named bind segment: %v", err)
		}
		if len(binds) != 1 || binds[0].Segment != "" || binds[0].SegmentIndex != 0 {
			t.Fatalf("empty-named bind segment result = %#v", binds)
		}
	})

	t.Run("location outside segment", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(1), types.BIND_OPCODE_DO_BIND)
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "exceeds segment VM size") {
			t.Fatalf("out-of-range bind error = %v", err)
		}
	})

	t.Run("backward address ULEB", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(0x20), types.BIND_OPCODE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, ^uint64(7))
		opcodes = append(opcodes, types.BIND_OPCODE_DO_BIND)
		binds, _, err := testClassicBindFile(0x40).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err != nil {
			t.Fatalf("backward bind address ULEB: %v", err)
		}
		if len(binds) != 1 || binds[0].SegOffset != 0x18 {
			t.Fatalf("backward bind address ULEB result = %#v", binds)
		}
	})

	t.Run("backward address ULEB underflow", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(4), types.BIND_OPCODE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, ^uint64(7))
		_, _, err := testClassicBindFile(0x40).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "underflows") {
			t.Fatalf("underflowing backward bind address ULEB error = %v", err)
		}
	})

	t.Run("forward address ULEB overflow", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(math.MaxUint64-4), types.BIND_OPCODE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, 8)
		_, _, err := testClassicBindFile(math.MaxUint64).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "overflows") {
			t.Fatalf("overflowing forward bind address ULEB error = %v", err)
		}
	})

	t.Run("address ULEB outside segment", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(0), types.BIND_OPCODE_ADD_ADDR_ULEB)
		opcodes = appendTestULEB(opcodes, 0x39)
		_, _, err := testClassicBindFile(0x40).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "outside segment VM size") {
			t.Fatalf("out-of-range bind address ULEB error = %v", err)
		}
	})

	t.Run("huge repeat count", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(0), types.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB)
		opcodes = appendTestULEB(opcodes, ^uint64(0))
		opcodes = appendTestULEB(opcodes, 0)
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "repeat count") {
			t.Fatalf("huge bind count error = %v", err)
		}
	})

	t.Run("missing symbol", func(t *testing.T) {
		opcodes := []byte{types.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0, types.BIND_OPCODE_DO_BIND}
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "missing BIND_OPCODE_SET_SYMBOL") {
			t.Fatalf("missing bind symbol error = %v", err)
		}
	})

	t.Run("missing ordinal", func(t *testing.T) {
		opcodes := []byte{
			types.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, '_', 's', 'y', 'm', 0,
			types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0,
			types.BIND_OPCODE_DO_BIND,
		}
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
		if err == nil || !strings.Contains(err.Error(), "missing BIND_OPCODE_SET_DYLIB_ORDINAL") {
			t.Fatalf("missing bind ordinal error = %v", err)
		}
	})

	t.Run("lazy opcode subset", func(t *testing.T) {
		opcodes := []byte{types.BIND_OPCODE_SET_TYPE_IMM | types.BIND_TYPE_POINTER}
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.LAZY_KIND)
		if err == nil || !strings.Contains(err.Error(), "unexpected BIND_OPCODE_SET_TYPE_IMM") {
			t.Fatalf("invalid lazy bind opcode error = %v", err)
		}
	})

	t.Run("weak stream ordinal", func(t *testing.T) {
		opcodes := []byte{types.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1}
		_, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.WEAK_KIND)
		if err == nil || !strings.Contains(err.Error(), "unexpected dylib ordinal") {
			t.Fatalf("invalid weak bind ordinal error = %v", err)
		}
	})

	t.Run("lazy done preserves state", func(t *testing.T) {
		opcodes := append(ordinaryBindPrefix(0),
			types.BIND_OPCODE_DO_BIND,
			types.BIND_OPCODE_DONE,
			types.BIND_OPCODE_DO_BIND,
			types.BIND_OPCODE_DONE,
		)
		binds, _, err := testClassicBindFile(16).parseBinds(bytes.NewReader(opcodes), types.LAZY_KIND)
		if err != nil {
			t.Fatalf("lazy state reuse: %v", err)
		}
		if len(binds) != 2 || binds[0].Name != "sym" || binds[1].Name != "sym" || binds[0].SegOffset != 0 || binds[1].SegOffset != 8 {
			t.Fatalf("lazy state reuse binds = %#v", binds)
		}
	})

	t.Run("bind type", func(t *testing.T) {
		for _, bindType := range []uint8{0, 15} {
			opcodes := append(ordinaryBindPrefix(0), types.BIND_OPCODE_SET_TYPE_IMM|bindType, types.BIND_OPCODE_DO_BIND)
			if _, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND); err == nil || !strings.Contains(err.Error(), "unknown type") {
				t.Errorf("bind type %d error = %v", bindType, err)
			}
		}
		for _, bindType := range []uint8{types.BIND_TYPE_POINTER, types.BIND_TYPE_TEXT_ABSOLUTE32, types.BIND_TYPE_TEXT_PCREL32} {
			opcodes := append(ordinaryBindPrefix(0), types.BIND_OPCODE_SET_TYPE_IMM|bindType, types.BIND_OPCODE_DO_BIND)
			binds, _, err := testClassicBindFile(8).parseBinds(bytes.NewReader(opcodes), types.BIND_KIND)
			if err != nil || len(binds) != 1 || binds[0].Type != bindType {
				t.Errorf("bind type %d = %#v, %v", bindType, binds, err)
			}
		}
	})

	t.Run("threaded coordinate overflow", func(t *testing.T) {
		data := make([]byte, 32)
		vma := &types.VMAddrConverter{
			Converter:    func(value uint64) uint64 { return value },
			VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
			Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
		}
		reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
		f := &File{
			FileTOC: FileTOC{
				FileHeader: types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E},
				ByteOrder:  binary.LittleEndian,
				Loads: loads{&Segment{SegmentHeader: types.SegmentHeader{
					Name: "__DATA", Addr: 0x1000, Memsz: 16, Offset: math.MaxUint64 - 4, Filesz: 16,
				}}},
			},
			cr: reader,
		}
		opcodes := []byte{
			types.BIND_OPCODE_THREADED | types.BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB,
			1,
			types.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
			types.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, '_', 's', 0,
			types.BIND_OPCODE_DO_BIND,
			types.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
		}
		opcodes = appendTestULEB(opcodes, 8)
		opcodes = append(opcodes, types.BIND_OPCODE_THREADED|types.BIND_SUBOPCODE_THREADED_APPLY)
		if _, _, err := f.parseBinds(bytes.NewReader(opcodes), types.BIND_KIND); err == nil || !strings.Contains(err.Error(), "file offset") {
			t.Fatalf("threaded coordinate overflow error = %v", err)
		}
	})
}

func TestGetBindNameAtAddressRequiresExactChainMembership(t *testing.T) {
	headerSize := uint32(binary.Size(fixupchains.DyldChainedFixupsHeader{}))
	recordSize := uint32(binary.Size(fixupchains.DyldChainedStartsInSegment{})) + 2
	header := fixupchains.DyldChainedFixupsHeader{
		StartsOffset:  headerSize,
		ImportsOffset: headerSize + 8 + recordSize,
		SymbolsOffset: headerSize + 8 + recordSize + 4,
		ImportsCount:  1,
		ImportsFormat: fixupchains.DC_IMPORT,
		SymbolsFormat: fixupchains.DC_SFORMAT_UNCOMPRESSED,
	}
	record := fixupchains.DyldChainedStartsInSegment{
		Size:          recordSize,
		PageSize:      0x1000,
		PointerFormat: fixupchains.DYLD_CHAINED_PTR_64,
		PageCount:     1,
	}
	var payload bytes.Buffer
	for _, value := range []any{
		header,
		uint32(1),
		uint32(8),
		record,
		fixupchains.DCPtrStart(0),
		fixupchains.DyldChainedImport(0),
	} {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatalf("write chained bind payload: %v", err)
		}
	}
	payload.WriteString("_symbol\x00")

	data := make([]byte, 0x1000)
	binary.LittleEndian.PutUint64(data[0:], uint64(1)<<63)
	binary.LittleEndian.PutUint64(data[8:], uint64(1)<<63) // bind-looking, but not in the chain
	vma := &types.VMAddrConverter{
		Converter:    func(value uint64) uint64 { return value },
		VMAddr2Offet: func(value uint64) (uint64, error) { return value, nil },
		Offet2VMAddr: func(value uint64) (uint64, error) { return value, nil },
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
	var machoReader types.MachoReader = reader
	dcf := fixupchains.NewChainedFixups(bytes.NewReader(payload.Bytes()), &machoReader, binary.LittleEndian)
	if err := dcf.ParseStarts(); err != nil {
		t.Fatalf("ParseStarts: %v", err)
	}
	if err := dcf.EnsureImports(); err != nil {
		t.Fatalf("EnsureImports: %v", err)
	}
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads: loads{
				&Segment{SegmentHeader: types.SegmentHeader{Name: "__DATA", Memsz: 0x1000, Filesz: 0x1000}},
				&DyldChainedFixups{},
			},
		},
		vma: vma,
		cr:  reader,
		sr:  reader,
		dcf: dcf,
	}
	if got, err := f.getBindNameAtAddress(0); err != nil || got != "symbol" {
		t.Fatalf("real chained bind name = %q, %v", got, err)
	}
	if got, err := f.getBindNameAtAddress(8); err == nil {
		t.Fatalf("same-page non-fixup returned bind %q", got)
	}
}
