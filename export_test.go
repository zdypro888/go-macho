package macho

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zdypro888/go-macho/pkg/codesign"
	ctypes "github.com/zdypro888/go-macho/pkg/codesign/types"
	"github.com/zdypro888/go-macho/types"
)

func TestExportReadsStandaloneSegmentsFromOriginalOffsets(t *testing.T) {
	newSegment := func(name string, address, offset uint64) *Segment {
		segment := &Segment{SegmentHeader: types.SegmentHeader{
			LoadCmd: types.LC_SEGMENT_64,
			Name:    name,
			Addr:    address,
			Memsz:   0x1000,
			Offset:  offset,
			Filesz:  0x1000,
		}}
		segment.Len = segment.LoadSize()
		return segment
	}

	textSegment := newSegment("__TEXT", 0, 0)
	dataSegment := newSegment("__DATA", 0x2000, 0x2000)
	linkeditSegment := newSegment("__LINKEDIT", 0x4000, 0x4000)
	fixture := &File{FileTOC: FileTOC{
		FileHeader: types.FileHeader{
			Magic:        types.Magic64,
			CPU:          types.CPUArm64,
			SubCPU:       types.CPUSubtypeArm64All,
			Type:         types.MH_DYLIB,
			NCommands:    3,
			SizeCommands: textSegment.LoadSize() + dataSegment.LoadSize() + linkeditSegment.LoadSize(),
		},
		ByteOrder: binary.LittleEndian,
		Loads:     loads{textSegment, dataSegment, linkeditSegment},
	}}

	source := make([]byte, 0x5000)
	for offset := range source {
		source[offset] = byte((offset*29 + 11) % 251)
	}
	var toc bytes.Buffer
	if err := fixture.FileHeader.Write(&toc, fixture.ByteOrder); err != nil {
		t.Fatalf("write fixture header: %v", err)
	}
	if err := fixture.writeLoadCommands(&toc); err != nil {
		t.Fatalf("write fixture load commands: %v", err)
	}
	copy(source, toc.Bytes())

	parsed, err := NewFile(bytes.NewReader(source))
	if err != nil {
		t.Fatalf("NewFile fixture: %v", err)
	}
	outputPath := filepath.Join(t.TempDir(), "exported.dylib")
	if err := parsed.Export(outputPath, nil, 0, nil); err != nil {
		t.Fatalf("Export standalone Mach-O with segment gaps: %v", err)
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	reopened, err := NewFile(bytes.NewReader(output))
	if err != nil {
		t.Fatalf("reopen export: %v", err)
	}
	for name, wantOffset := range map[string]uint64{
		"__TEXT":     0,
		"__DATA":     0x4000,
		"__LINKEDIT": 0x8000,
	} {
		segment := reopened.Segment(name)
		if segment == nil {
			t.Fatalf("reopened export is missing %s", name)
		}
		if segment.Offset != wantOffset {
			t.Fatalf("%s offset = %#x, want %#x", name, segment.Offset, wantOffset)
		}
	}
	if !bytes.Equal(output[0x4000:0x5000], source[0x2000:0x3000]) {
		t.Fatal("exported __DATA bytes did not come from the original __DATA offset")
	}
	if !bytes.Equal(output[0x8000:0x9000], source[0x4000:0x5000]) {
		t.Fatal("exported __LINKEDIT bytes did not come from the original __LINKEDIT offset")
	}
}

func TestWriteRebuiltSymbolUsesMachOWidthAndByteOrder(t *testing.T) {
	entry := rebuiltSymEntry{
		sym: Symbol{
			Type:  types.N_SECT,
			Sect:  2,
			Desc:  types.NDescType(0x1234),
			Value: 0x55667788,
		},
		name: "symbol",
	}

	var symbols bytes.Buffer
	var names bytes.Buffer
	names.WriteByte(0)
	if err := writeRebuiltSymbol(&symbols, &names, map[string]uint32{"": 0}, false, binary.BigEndian, entry); err != nil {
		t.Fatalf("writeRebuiltSymbol(32-bit): %v", err)
	}
	if symbols.Len() != binary.Size(types.Nlist32{}) {
		t.Fatalf("32-bit symbol size = %d, want %d", symbols.Len(), binary.Size(types.Nlist32{}))
	}
	got := symbols.Bytes()
	if name := binary.BigEndian.Uint32(got[0:4]); name != 1 {
		t.Fatalf("32-bit symbol name offset = %d, want 1", name)
	}
	if got[4] != byte(types.N_SECT) || got[5] != 2 {
		t.Fatalf("32-bit symbol type/section = %#x/%d", got[4], got[5])
	}
	if desc := binary.BigEndian.Uint16(got[6:8]); desc != 0x1234 {
		t.Fatalf("32-bit symbol desc = %#x, want 0x1234", desc)
	}
	if value := binary.BigEndian.Uint32(got[8:12]); value != 0x55667788 {
		t.Fatalf("32-bit symbol value = %#x, want 0x55667788", value)
	}

	overflow := entry
	overflow.sym.Value = uint64(math.MaxUint32) + 1
	if err := writeRebuiltSymbol(&bytes.Buffer{}, &bytes.Buffer{}, map[string]uint32{}, false, binary.LittleEndian, overflow); err == nil {
		t.Fatal("writeRebuiltSymbol accepted a value that does not fit Nlist32")
	}

	symbols.Reset()
	names.Reset()
	names.WriteByte(0)
	entry.sym.Value = 0x1122334455667788
	if err := writeRebuiltSymbol(&symbols, &names, map[string]uint32{"": 0}, true, binary.LittleEndian, entry); err != nil {
		t.Fatalf("writeRebuiltSymbol(64-bit): %v", err)
	}
	if symbols.Len() != binary.Size(types.Nlist64{}) {
		t.Fatalf("64-bit symbol size = %d, want %d", symbols.Len(), binary.Size(types.Nlist64{}))
	}
	if value := binary.LittleEndian.Uint64(symbols.Bytes()[8:16]); value != entry.sym.Value {
		t.Fatalf("64-bit symbol value = %#x, want %#x", value, entry.sym.Value)
	}
}

func TestOptimizeLinkeditCopiesEveryLazyLoadPayload(t *testing.T) {
	source := make([]byte, 64)
	payload1 := []byte{0x11, 0x22, 0x33}
	payload2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	copy(source[4:], payload1)
	copy(source[20:], payload2)

	linkedit := &Segment{SegmentHeader: types.SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__LINKEDIT",
		Offset:  0x100,
	}}
	newLazy := func(offset uint32, size int) *LazyLoadDylibInfo {
		return &LazyLoadDylibInfo{LinkEditData: LinkEditData{
			LinkEditDataCmd: types.LinkEditDataCmd{
				LoadCmd: types.LC_LAZY_LOAD_DYLIB_INFO,
				Len:     uint32(binary.Size(types.LinkEditDataCmd{})),
				Offset:  offset,
				Size:    uint32(size),
			},
		}}
	}
	lazy1 := newLazy(4, len(payload1))
	lazy2 := newLazy(20, len(payload2))
	reader := types.NewCustomSectionReader(bytes.NewReader(source), nil, 0, int64(len(source)))
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads:      loads{linkedit, lazy1, lazy2},
		},
		Dysymtab: &Dysymtab{},
		cr:       reader,
	}

	rebuilt, err := f.optimizeLinkedit(nil)
	if err != nil {
		t.Fatalf("optimizeLinkedit: %v", err)
	}
	if lazy1.Offset != 0x100 {
		t.Fatalf("first lazy payload offset = %#x, want 0x100", lazy1.Offset)
	}
	if lazy2.Offset != 0x108 {
		t.Fatalf("second lazy payload offset = %#x, want 0x108", lazy2.Offset)
	}
	if got := rebuilt.Bytes()[0:len(payload1)]; !bytes.Equal(got, payload1) {
		t.Fatalf("first lazy payload = %x, want %x", got, payload1)
	}
	secondOffset := int(lazy2.Offset - uint32(linkedit.Offset))
	if got := rebuilt.Bytes()[secondOffset : secondOffset+len(payload2)]; !bytes.Equal(got, payload2) {
		t.Fatalf("second lazy payload = %x, want %x", got, payload2)
	}
}

func TestOptimizeLinkeditCopiesEverySplitInfoPayload(t *testing.T) {
	source := make([]byte, 64)
	payload1 := []byte{types.DYLD_CACHE_ADJ_V2_FORMAT, 0x11, 0x22}
	payload2 := []byte{types.DYLD_CACHE_ADJ_V2_FORMAT, 0xaa, 0xbb, 0xcc, 0xdd}
	copy(source[4:], payload1)
	copy(source[24:], payload2)

	linkedit := &Segment{SegmentHeader: types.SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__LINKEDIT",
		Offset:  0x100,
	}}
	newSplit := func(offset uint32, size int) *SplitInfo {
		return &SplitInfo{SegmentSplitInfoCmd: types.SegmentSplitInfoCmd{
			LoadCmd: types.LC_SEGMENT_SPLIT_INFO,
			Len:     uint32(binary.Size(types.SegmentSplitInfoCmd{})),
			Offset:  offset,
			Size:    uint32(size),
		}}
	}
	split1 := newSplit(4, len(payload1))
	split2 := newSplit(24, len(payload2))
	reader := types.NewCustomSectionReader(bytes.NewReader(source), nil, 0, int64(len(source)))
	f := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
			Loads:      loads{linkedit, split1, split2},
		},
		Dysymtab: &Dysymtab{},
		cr:       reader,
	}

	rebuilt, err := f.optimizeLinkedit(nil)
	if err != nil {
		t.Fatalf("optimizeLinkedit: %v", err)
	}
	if split1.Offset != 0x100 {
		t.Fatalf("first split payload offset = %#x, want 0x100", split1.Offset)
	}
	if split2.Offset != 0x108 {
		t.Fatalf("second split payload offset = %#x, want 0x108", split2.Offset)
	}
	if got := rebuilt.Bytes()[:len(payload1)]; !bytes.Equal(got, payload1) {
		t.Fatalf("first split payload = %x, want %x", got, payload1)
	}
	secondOffset := int(split2.Offset - uint32(linkedit.Offset))
	if got := rebuilt.Bytes()[secondOffset : secondOffset+len(payload2)]; !bytes.Equal(got, payload2) {
		t.Fatalf("second split payload = %x, want %x", got, payload2)
	}
}

type codeSignFixture struct {
	file       *File
	text       *Segment
	linkedit   *Segment
	section    *types.Section
	source     []byte
	oldLoadEnd uint32
}

func newCodeSignFixture(t *testing.T, magic types.Magic, headerPadding uint32, existing *types.CodeSignatureCmd) codeSignFixture {
	t.Helper()
	segmentCommand := types.LC_SEGMENT_64
	cpu := types.CPUAmd64
	if magic == types.Magic32 {
		segmentCommand = types.LC_SEGMENT
		cpu = types.CPUI386
	}

	section := &types.Section{SectionHeader: types.SectionHeader{
		Name: "__text",
		Seg:  "__TEXT",
		Size: 64,
	}}
	if magic == types.Magic32 {
		section.Type = 32
	}
	text := &Segment{SegmentHeader: types.SegmentHeader{
		LoadCmd:   segmentCommand,
		Name:      "__TEXT",
		Memsz:     0x1000,
		Filesz:    0x1000,
		Nsect:     1,
		Firstsect: 0,
	}, Sections: []*types.Section{section}}
	text.Len = text.LoadSize()
	linkedit := &Segment{SegmentHeader: types.SegmentHeader{
		LoadCmd: segmentCommand,
		Name:    "__LINKEDIT",
		Addr:    0x1000,
		Memsz:   0x1000,
		Offset:  0x1000,
		Filesz:  0x100,
	}}
	linkedit.Len = linkedit.LoadSize()
	fixtureLoads := loads{text, linkedit}
	if existing != nil {
		command := *existing
		fixtureLoads = append(fixtureLoads, &CodeSignature{CodeSignatureCmd: command})
	}

	var commandBytes uint32
	for _, load := range fixtureLoads {
		commandBytes += load.LoadSize()
	}
	headerSize := uint32(types.FileHeaderSize64)
	if magic == types.Magic32 {
		headerSize = types.FileHeaderSize32
	}
	oldLoadEnd := headerSize + commandBytes
	section.Offset = oldLoadEnd + headerPadding
	section.Addr = uint64(section.Offset)

	source := make([]byte, 0x8000)
	for index := range source {
		source[index] = byte((index*31 + 7) % 251)
	}
	converter := &types.VMAddrConverter{
		Converter: func(address uint64) uint64 { return address },
		VMAddr2Offet: func(address uint64) (uint64, error) {
			return address, nil
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			return offset, nil
		},
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(source), converter, 0, int64(len(source)))
	file := &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{
				Magic:        magic,
				CPU:          cpu,
				Type:         types.MH_EXECUTE,
				NCommands:    uint32(len(fixtureLoads)),
				SizeCommands: commandBytes,
			},
			ByteOrder: binary.LittleEndian,
			Loads:     fixtureLoads,
			Sections:  []*types.Section{section},
		},
		vma: converter,
		cr:  reader,
		sr:  reader,
	}
	return codeSignFixture{file: file, text: text, linkedit: linkedit, section: section, source: source, oldLoadEnd: oldLoadEnd}
}

func codeSignTOCBytes(t *testing.T, file *File) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := file.writeCodeSignFileHeader(&output); err != nil {
		t.Fatalf("write FileHeader: %v", err)
	}
	if err := file.writeLoadCommands(&output); err != nil {
		t.Fatalf("write load commands: %v", err)
	}
	return bytes.Clone(output.Bytes())
}

func configWithoutSigner(config *codesign.Config) codesign.Config {
	cloned := cloneCodeSignConfig(config)
	cloned.SignerFunction = nil
	return cloned
}

func assertCodeSignRollback(t *testing.T, fixture codeSignFixture, beforeTOC []byte, beforeLoads loads, beforeLEData *bytes.Buffer, beforeLinkeditFilesz, beforeLinkeditMemsz uint64) {
	t.Helper()
	if got := codeSignTOCBytes(t, fixture.file); !bytes.Equal(got, beforeTOC) {
		t.Fatalf("TOC changed after failed CodeSign\n got: %x\nwant: %x", got, beforeTOC)
	}
	if len(fixture.file.Loads) != len(beforeLoads) {
		t.Fatalf("load count after failure = %d, want %d", len(fixture.file.Loads), len(beforeLoads))
	}
	for index := range beforeLoads {
		if fixture.file.Loads[index] != beforeLoads[index] {
			t.Fatalf("load %d identity changed after failure", index)
		}
	}
	if fixture.file.ledata != beforeLEData {
		t.Fatal("linkedit staging buffer changed after failure")
	}
	if fixture.linkedit.Filesz != beforeLinkeditFilesz || fixture.linkedit.Memsz != beforeLinkeditMemsz {
		t.Fatalf("__LINKEDIT size after failure = %#x/%#x, want %#x/%#x", fixture.linkedit.Filesz, fixture.linkedit.Memsz, beforeLinkeditFilesz, beforeLinkeditMemsz)
	}
}

func TestCodeSignRollsBackFileAndConfigOnSignerFailure(t *testing.T) {
	sentinel := errors.New("sentinel signer failure")
	for _, existing := range []bool{false, true} {
		name := "new signature"
		if existing {
			name = "replacement signature"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newCodeSignFixture(t, types.Magic64, 16, nil)
			if existing {
				initial := &codesign.Config{ID: "com.example.rollback", Flags: ctypes.ADHOC}
				if err := fixture.file.CodeSign(initial); err != nil {
					t.Fatalf("initial CodeSign: %v", err)
				}
			}

			beforeTOC := codeSignTOCBytes(t, fixture.file)
			beforeLoads := append(loads(nil), fixture.file.Loads...)
			beforeLEData := fixture.file.ledata
			beforeLinkeditFilesz, beforeLinkeditMemsz := fixture.linkedit.Filesz, fixture.linkedit.Memsz
			config := &codesign.Config{
				ID:             "com.example.rollback",
				Flags:          ctypes.ADHOC,
				Entitlements:   []byte("<plist><dict/></plist>"),
				RawComponents:  map[ctypes.SlotType][]byte{ctypes.CSSLOT_APPLICATION: {1, 2, 3}},
				SignerFunction: func([]byte) ([]byte, error) { return nil, sentinel },
			}
			beforeConfig := configWithoutSigner(config)
			if err := fixture.file.CodeSign(config); !errors.Is(err, sentinel) {
				t.Fatalf("CodeSign error = %v, want sentinel", err)
			}
			assertCodeSignRollback(t, fixture, beforeTOC, beforeLoads, beforeLEData, beforeLinkeditFilesz, beforeLinkeditMemsz)
			if got := configWithoutSigner(config); !reflect.DeepEqual(got, beforeConfig) {
				t.Fatalf("config changed after failed CodeSign\n got: %#v\nwant: %#v", got, beforeConfig)
			}

			config.SignerFunction = nil
			if err := fixture.file.CodeSign(config); err != nil {
				t.Fatalf("retry CodeSign after rollback: %v", err)
			}
		})
	}
}

func TestCodeSignRejectsSignatureOutsideLinkeditWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		command types.CodeSignatureCmd
		want    string
	}{
		{
			name: "before linkedit",
			command: types.CodeSignatureCmd{
				LoadCmd: types.LC_CODE_SIGNATURE,
				Len:     uint32(binary.Size(types.CodeSignatureCmd{})),
				Offset:  0x800,
				Size:    12,
			},
			want: "precedes __LINKEDIT",
		},
		{
			name: "past linkedit end",
			command: types.CodeSignatureCmd{
				LoadCmd: types.LC_CODE_SIGNATURE,
				Len:     uint32(binary.Size(types.CodeSignatureCmd{})),
				Offset:  0x1080,
				Size:    0x90,
			},
			want: "exceeds __LINKEDIT",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodeSignFixture(t, types.Magic64, 16, &test.command)
			beforeTOC := codeSignTOCBytes(t, fixture.file)
			beforeLoads := append(loads(nil), fixture.file.Loads...)
			config := &codesign.Config{ID: "com.example.invalid", Flags: ctypes.ADHOC}
			beforeConfig := configWithoutSigner(config)
			if err := fixture.file.CodeSign(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("CodeSign error = %v, want substring %q", err, test.want)
			}
			assertCodeSignRollback(t, fixture, beforeTOC, beforeLoads, nil, 0x100, 0x1000)
			if got := configWithoutSigner(config); !reflect.DeepEqual(got, beforeConfig) {
				t.Fatalf("config changed after rejected signature: %#v", got)
			}
		})
	}
}

func TestCodeSignRequiresFullLoadCommandHeaderPadding(t *testing.T) {
	for _, magic := range []types.Magic{types.Magic32, types.Magic64} {
		for _, padding := range []uint32{0, 15, 16} {
			name := magic.String() + "/padding-" + string(rune('0'+padding/10)) + string(rune('0'+padding%10))
			t.Run(name, func(t *testing.T) {
				fixture := newCodeSignFixture(t, magic, padding, nil)
				payload := bytes.Clone(fixture.source[fixture.section.Offset : fixture.section.Offset+uint32(fixture.section.Size)])
				config := &codesign.Config{ID: "com.example.headerpad", Flags: ctypes.ADHOC}
				err := fixture.file.CodeSign(config)
				if padding < uint32(binary.Size(types.CodeSignatureCmd{})) {
					if err == nil || !strings.Contains(err.Error(), "not enough header padding") {
						t.Fatalf("CodeSign error = %v, want insufficient header padding", err)
					}
					if fixture.file.CodeSignature() != nil {
						t.Fatal("failed CodeSign added LC_CODE_SIGNATURE")
					}
					return
				}
				if err != nil {
					t.Fatalf("CodeSign with exact header padding: %v", err)
				}
				var output bytes.Buffer
				if err := fixture.file.SaveBuffer(&output); err != nil {
					t.Fatalf("SaveBuffer: %v", err)
				}
				start := int(fixture.section.Offset)
				end := start + len(payload)
				if end > output.Len() || !bytes.Equal(output.Bytes()[start:end], payload) {
					t.Fatalf("first __TEXT section changed after signing")
				}
			})
		}
	}
}

func oldSpecialSlotDigest(t *testing.T, hashType uint8, hashSize uint8, data []byte) []byte {
	t.Helper()
	var digest []byte
	switch hashType {
	case uint8(ctypes.HASHTYPE_SHA1):
		sum := sha1.Sum(data)
		digest = sum[:]
	case uint8(ctypes.HASHTYPE_SHA256_TRUNCATED):
		sum := sha256.Sum256(data)
		digest = sum[:]
	case uint8(ctypes.HASHTYPE_SHA384):
		sum := sha512.Sum384(data)
		digest = sum[:]
	default:
		t.Fatalf("unsupported test hash type %d", hashType)
	}
	return bytes.Clone(digest[:hashSize])
}

func blobBytes(t *testing.T, magic ctypes.Magic, payload []byte) []byte {
	t.Helper()
	data, err := ctypes.NewBlob(magic, payload).Bytes()
	if err != nil {
		t.Fatalf("encode blob: %v", err)
	}
	return data
}

func TestSignRehashesPreviousSpecialSlotsAcrossDigestAlgorithms(t *testing.T) {
	for _, algorithm := range []struct {
		name     string
		hashType uint8
		hashSize uint8
	}{
		{name: "SHA-1", hashType: uint8(ctypes.HASHTYPE_SHA1), hashSize: sha1.Size},
		{name: "truncated SHA-256", hashType: uint8(ctypes.HASHTYPE_SHA256_TRUNCATED), hashSize: sha1.Size},
		{name: "SHA-384", hashType: uint8(ctypes.HASHTYPE_SHA384), hashSize: sha512.Size384},
	} {
		t.Run(algorithm.name, func(t *testing.T) {
			code := bytes.Repeat([]byte{0x4d}, ctypes.PAGE_SIZE+9)
			info := []byte("<plist><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>")
			rawResource := []byte("resource-directory-component")
			entitlements := []byte("<plist><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>")
			entitlementsDER := []byte{0x30, 0x03, 0x01, 0x01, 0xff}
			constraint := []byte{0x31, 0x82, 0x01, 0x00}
			previous := []ctypes.SpecialSlot{
				{Index: 1, Hash: oldSpecialSlotDigest(t, algorithm.hashType, algorithm.hashSize, info)},
				{Index: 3, Hash: oldSpecialSlotDigest(t, algorithm.hashType, algorithm.hashSize, rawResource)},
				{Index: 5, Hash: oldSpecialSlotDigest(t, algorithm.hashType, algorithm.hashSize, blobBytes(t, ctypes.MAGIC_EMBEDDED_ENTITLEMENTS, entitlements))},
				{Index: 7, Hash: oldSpecialSlotDigest(t, algorithm.hashType, algorithm.hashSize, blobBytes(t, ctypes.MAGIC_EMBEDDED_ENTITLEMENTS_DER, entitlementsDER))},
				{Index: 8, Hash: oldSpecialSlotDigest(t, algorithm.hashType, algorithm.hashSize, blobBytes(t, ctypes.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, constraint))},
			}
			config := &codesign.Config{
				ID:                    "com.example.digest-migration",
				Flags:                 ctypes.ADHOC,
				CodeSize:              uint64(len(code)),
				SpecialSlots:          previous,
				SpecialSlotsHashType:  algorithm.hashType,
				SpecialSlotsHashSize:  algorithm.hashSize,
				InfoPlist:             info,
				Entitlements:          entitlements,
				EntitlementsDER:       entitlementsDER,
				LaunchConstraintsSelf: constraint,
				RawComponents:         map[ctypes.SlotType][]byte{ctypes.CSSLOT_RESOURCEDIR: rawResource},
			}
			config.InitSlotHashes()
			signature, err := codesign.Sign(bytes.NewReader(code), config)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			parsed, err := codesign.ParseCodeSignature(signature)
			if err != nil {
				t.Fatalf("ParseCodeSignature: %v", err)
			}
			primary := parsed.PrimaryCodeDirectory()
			if primary == nil || uint8(primary.Header.HashType) != uint8(ctypes.HASHTYPE_SHA256) || primary.Header.HashSize != sha256.Size {
				t.Fatalf("new primary CodeDirectory digest = %#v", primary)
			}
			if parsed.Entitlements != string(entitlements) || !bytes.Equal(parsed.EntitlementsDER, entitlementsDER) || !bytes.Equal(parsed.LaunchConstraintsSelf, constraint) {
				t.Fatal("rehash changed an embedded special-slot payload")
			}
		})
	}

	t.Run("changed component still fails old digest validation", func(t *testing.T) {
		original := []byte("<plist><dict/></plist>")
		changed := []byte("<plist><dict><key>changed</key><true/></dict></plist>")
		config := &codesign.Config{
			ID:                   "com.example.changed",
			Flags:                ctypes.ADHOC,
			CodeSize:             32,
			Entitlements:         changed,
			SpecialSlots:         []ctypes.SpecialSlot{{Index: 5, Hash: oldSpecialSlotDigest(t, uint8(ctypes.HASHTYPE_SHA1), sha1.Size, blobBytes(t, ctypes.MAGIC_EMBEDDED_ENTITLEMENTS, original))}},
			SpecialSlotsHashType: uint8(ctypes.HASHTYPE_SHA1),
			SpecialSlotsHashSize: sha1.Size,
		}
		config.InitSlotHashes()
		if _, err := codesign.Sign(bytes.NewReader(make([]byte, config.CodeSize)), config); err == nil || !strings.Contains(err.Error(), "slot 5 hashes do not match") {
			t.Fatalf("Sign error = %v, want old digest mismatch", err)
		}
	})
}

func TestSignExplicitEntitlementsDeletionClearsSlotFiveBinding(t *testing.T) {
	oldEntitlements := []byte("<plist><dict><key>old</key><true/></dict></plist>")
	oldBlob := blobBytes(t, ctypes.MAGIC_EMBEDDED_ENTITLEMENTS, oldEntitlements)
	oldHash := sha256.Sum256(oldBlob)
	code := bytes.Repeat([]byte{0x62}, 64)
	config := &codesign.Config{
		ID:                   "com.example.clear-entitlements",
		Flags:                ctypes.ADHOC,
		CodeSize:             uint64(len(code)),
		Entitlements:         []byte{},
		SpecialSlots:         []ctypes.SpecialSlot{{Index: 5, Hash: oldHash[:]}},
		SpecialSlotsHashType: uint8(ctypes.HASHTYPE_SHA256),
		SpecialSlotsHashSize: sha256.Size,
		RawComponents:        map[ctypes.SlotType][]byte{ctypes.CSSLOT_REP_SPECIFIC: []byte("forces-slot-six")},
	}
	config.InitSlotHashes()
	config.SlotHashes.Entitlements = bytes.Clone(oldHash[:]) // simulate reuse after an earlier Sign call
	signature, err := codesign.Sign(bytes.NewReader(code), config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := codesign.ParseCodeSignature(signature)
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if parsed.Entitlements != "" {
		t.Fatalf("deleted entitlements were emitted: %q", parsed.Entitlements)
	}
	primary := parsed.PrimaryCodeDirectory()
	if primary == nil {
		t.Fatal("missing primary CodeDirectory")
	}
	foundSlotFive := false
	for _, slot := range primary.SpecialSlots {
		if slot.Index == 5 {
			foundSlotFive = true
		}
		if slot.Index == 5 && bytes.Count(slot.Hash, []byte{0}) != len(slot.Hash) {
			t.Fatalf("slot 5 remains bound without an entitlements blob: %x", slot.Hash)
		}
	}
	if !foundSlotFive {
		t.Fatal("slot 6 signature did not encode the intervening zero slot 5")
	}
	if primary.Header.NSpecialSlots != 6 {
		t.Fatalf("special slot count = %d, want slot 6 raw component to remain", primary.Header.NSpecialSlots)
	}
}

func TestFileCodeSignPreservesNonNilEmptyEntitlementsAsDeletion(t *testing.T) {
	fixture := newCodeSignFixture(t, types.Magic64, 16, nil)
	initialEntitlements := []byte("<plist><dict><key>old</key><true/></dict></plist>")
	initial := &codesign.Config{
		ID:           "com.example.file-clear-entitlements",
		Flags:        ctypes.ADHOC,
		Entitlements: initialEntitlements,
	}
	if err := fixture.file.CodeSign(initial); err != nil {
		t.Fatalf("initial CodeSign: %v", err)
	}
	command := fixture.file.CodeSignature()
	if command == nil {
		t.Fatal("initial CodeSign did not add LC_CODE_SIGNATURE")
	}
	prefixLength := uint64(command.Offset) - fixture.linkedit.Offset
	parsed, err := codesign.ParseCodeSignature(fixture.file.ledata.Bytes()[int(prefixLength):])
	if err != nil {
		t.Fatalf("parse initial signature: %v", err)
	}
	command.CodeSignature = *parsed
	if command.Entitlements != string(initialEntitlements) {
		t.Fatalf("initial entitlements = %q", command.Entitlements)
	}

	clear := &codesign.Config{
		Flags:        ctypes.ADHOC,
		Entitlements: make([]byte, 0), // non-nil is the public deletion sentinel
	}
	if err := fixture.file.CodeSign(clear); err != nil {
		t.Fatalf("CodeSign deleting entitlements: %v", err)
	}
	if clear.Entitlements == nil {
		t.Fatal("CodeSign collapsed explicit empty entitlements to nil")
	}
	parsed, err = codesign.ParseCodeSignature(fixture.file.ledata.Bytes()[int(prefixLength):])
	if err != nil {
		t.Fatalf("parse replacement signature: %v", err)
	}
	if parsed.Entitlements != "" {
		t.Fatalf("replacement retained entitlements: %q", parsed.Entitlements)
	}
	primary := parsed.PrimaryCodeDirectory()
	if primary == nil {
		t.Fatal("replacement missing primary CodeDirectory")
	}
	if primary.Header.NSpecialSlots >= 5 {
		t.Fatalf("replacement special slot count = %d, want slot 5 omitted", primary.Header.NSpecialSlots)
	}
}
