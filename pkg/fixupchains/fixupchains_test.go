package fixupchains

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

type bytesMachoReader struct {
	*bytes.Reader
}

func (reader *bytesMachoReader) SeekToAddr(addr uint64) error {
	_, err := reader.Seek(int64(addr), io.SeekStart)
	return err
}

func (reader *bytesMachoReader) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	return reader.ReadAt(buf, int64(addr))
}

func TestLookupFunctionality(t *testing.T) {
	tests := []struct {
		name          string
		setupFixups   func() *DyldChainedFixups
		targetOffset  uint64
		wantFound     bool
		wantAuth      bool
		wantDiversity uint64
	}{
		{
			name: "lookup auth rebase by target",
			setupFixups: func() *DyldChainedFixups {
				dcf := &DyldChainedFixups{
					fixups: make(map[uint64][]Fixup),
					Starts: []DyldChainedStarts{
						{
							DyldChainedStartsInSegment: DyldChainedStartsInSegment{
								PointerFormat: DYLD_CHAINED_PTR_ARM64E,
							},
							Fixups: []Fixup{},
						},
					},
				}

				// Create an auth rebase fixup
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: 0x1234567890ABCDEF, // Example pointer with diversity
					Fixup:   0x1000,
				}

				// Add to both places
				dcf.Starts[0].Fixups = append(dcf.Starts[0].Fixups, authRebase)
				dcf.addTargetFixup(authRebase.Target(), authRebase)
				dcf.chainsParsed = true

				return dcf
			},
			targetOffset:  types.ExtractBits(0x1234567890ABCDEF, 0, 32), // Target from the pointer
			wantFound:     true,
			wantAuth:      true,
			wantDiversity: types.ExtractBits(0x1234567890ABCDEF, 32, 16), // Diversity from the pointer
		},
		{
			name: "lookup regular rebase by target",
			setupFixups: func() *DyldChainedFixups {
				dcf := &DyldChainedFixups{
					fixups: make(map[uint64][]Fixup),
					Starts: []DyldChainedStarts{
						{
							DyldChainedStartsInSegment: DyldChainedStartsInSegment{
								PointerFormat: DYLD_CHAINED_PTR_64,
							},
							Fixups: []Fixup{},
						},
					},
				}

				// Create a regular rebase fixup
				rebase := DyldChainedPtr64Rebase{
					Pointer: 0x0000000100000000,
					Fixup:   0x2000,
				}

				// Add to both places
				dcf.Starts[0].Fixups = append(dcf.Starts[0].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				dcf.chainsParsed = true

				return dcf
			},
			targetOffset:  types.ExtractBits(0x0000000100000000, 0, 36), // Target from the pointer
			wantFound:     true,
			wantAuth:      false,
			wantDiversity: 0,
		},
		{
			name: "lookup non-existent target",
			setupFixups: func() *DyldChainedFixups {
				return &DyldChainedFixups{
					fixups:       make(map[uint64][]Fixup),
					Starts:       []DyldChainedStarts{},
					chainsParsed: true,
				}
			},
			targetOffset:  0x9999,
			wantFound:     false,
			wantAuth:      false,
			wantDiversity: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcf := tt.setupFixups()

			fixups := dcf.LookupByTarget(tt.targetOffset)
			found := len(fixups) > 0
			if found != tt.wantFound {
				t.Errorf("LookupByTarget() found = %v, want %v", found, tt.wantFound)
				return
			}

			if !found {
				return
			}

			// Test GetAuthRebase for auth fixups
			if tt.wantAuth {
				auth, ok := dcf.GetAuthRebase(tt.targetOffset)
				if !ok {
					t.Error("GetAuthRebase() failed to find auth fixup")
					return
				}

				if diversity := auth.Diversity(); diversity != tt.wantDiversity {
					t.Errorf("Diversity() = %v, want %v", diversity, tt.wantDiversity)
				}
			}

			// Verify the fixup is the correct type
			fixup := fixups[0]
			if tt.wantAuth {
				if _, ok := fixup.(Auth); !ok {
					t.Errorf("Expected Auth fixup, got %T", fixup)
				}
			} else {
				if _, ok := fixup.(Rebase); !ok {
					t.Errorf("Expected Rebase fixup, got %T", fixup)
				}
			}
		})
	}
}

func TestLookupByOffset(t *testing.T) {
	dcf := &DyldChainedFixups{
		chainsParsed: true,
		Starts: []DyldChainedStarts{
			{
				Fixups: []Fixup{
					DyldChainedPtrArm64eRebase{
						Pointer: 0x1111111111111111,
						Fixup:   0x1000,
					},
					DyldChainedPtrArm64eAuthRebase{
						Pointer: 0x2222222222222222,
						Fixup:   0x2000,
					},
					DyldChainedPtrArm64eBind{
						Pointer: 0x3333333333333333,
						Fixup:   0x3000,
						Import:  "symbol",
					},
				},
			},
		},
	}

	tests := []struct {
		offset    uint64
		wantFound bool
		wantType  string
	}{
		{0x1000, true, "rebase"},
		{0x2000, true, "auth-rebase"},
		{0x3000, true, "bind"},
		{0x4000, false, ""},
	}

	for _, tt := range tests {
		fixup, found := dcf.LookupByOffset(tt.offset)
		if found != tt.wantFound {
			t.Errorf("LookupByOffset(0x%x) found = %v, want %v", tt.offset, found, tt.wantFound)
			continue
		}

		if found {
			var kind string
			switch fixup.(type) {
			case *DyldChainedPtrArm64eRebase, DyldChainedPtrArm64eRebase:
				kind = "rebase"
			case *DyldChainedPtrArm64eAuthRebase, DyldChainedPtrArm64eAuthRebase:
				kind = "auth-rebase"
			case *DyldChainedPtrArm64eBind, DyldChainedPtrArm64eBind:
				kind = "bind"
			default:
				kind = "unknown"
			}
			if kind != tt.wantType {
				t.Errorf("LookupByOffset(0x%x) returned %s, want %s", tt.offset, kind, tt.wantType)
			}
		}
	}
}

// mockChainedFixups creates a basic mock DyldChainedFixups for testing GetFixupAtOffset
func mockChainedFixups() *DyldChainedFixups {
	// Create minimal mock data for testing
	dcf := &DyldChainedFixups{
		DyldChainedFixupsHeader: DyldChainedFixupsHeader{
			FixupsVersion: 0,
			StartsOffset:  32,
			ImportsOffset: 100,
			SymbolsOffset: 200,
			ImportsCount:  2,
			ImportsFormat: DC_IMPORT,
			SymbolsFormat: DC_SFORMAT_UNCOMPRESSED,
		},
		PointerFormat: DYLD_CHAINED_PTR_64,
		Starts: []DyldChainedStarts{
			{
				DyldChainedStartsInSegment: DyldChainedStartsInSegment{
					Size:            40,
					PageSize:        0x4000, // 16KB pages
					PointerFormat:   DYLD_CHAINED_PTR_64,
					SegmentOffset:   0x10000, // Start at 64KB
					MaxValidPointer: 0xFFFFFF,
					PageCount:       4,
				},
				PageStarts: []DCPtrStart{
					0x100,                       // Page 0: fixup at offset 0x100
					DYLD_CHAINED_PTR_START_NONE, // Page 1: no fixups
					0x200,                       // Page 2: fixup at offset 0x200
					DYLD_CHAINED_PTR_START_NONE, // Page 3: no fixups
				},
			},
		},
		Imports: []DcfImport{
			{Name: "_printf", Import: DyldChainedImport(0x123)},
			{Name: "_malloc", Import: DyldChainedImport(0x456)},
		},
		fixups:         make(map[uint64][]Fixup),
		metadataParsed: true,
		importsParsed:  true,
		chainsParsed:   false,
	}

	// Create mock reader with some data
	data := make([]byte, 0x30000)
	dcf.r = bytes.NewReader(data)
	dcf.sr = &bytesMachoReader{Reader: bytes.NewReader(data)}
	dcf.bo = binary.LittleEndian

	return dcf
}

func TestGetFixupAtOffset(t *testing.T) {
	tests := []struct {
		name        string
		offset      uint64
		expectError bool
		errorType   error
	}{
		{
			name:        "offset with no fixup page",
			offset:      0x10000 + 0x4000 + 0x100, // Page 1 + some offset (page has no fixups)
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset not aligned to pointer size",
			offset:      0x10000 + 0x101, // Page 0 + misaligned offset
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset not aligned to stride",
			offset:      0x10000 + 0x102, // Page 0 + offset not aligned to 4-byte stride
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "aligned offset not present in chain",
			offset:      0x10000 + 0x104,
			expectError: true,
			errorType:   ErrNoFixupAtOffset,
		},
		{
			name:        "offset outside segment range",
			offset:      0x8000, // Before segment start
			expectError: true,
		},
	}

	dcf := mockChainedFixups()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixup, err := dcf.GetFixupAtOffset(tt.offset)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetFixupAtOffset() expected error but got none")
					return
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("GetFixupAtOffset() error = %v, want %v", err, tt.errorType)
				}
				if fixup != nil {
					t.Errorf("GetFixupAtOffset() expected nil fixup but got %v", fixup)
				}
			} else {
				if err != nil {
					t.Errorf("GetFixupAtOffset() unexpected error = %v", err)
					return
				}
				if fixup == nil {
					t.Errorf("GetFixupAtOffset() expected fixup but got nil")
				}
			}
		})
	}
}

func TestResolveRebaseVMAddressBasesAndBounds(t *testing.T) {
	const (
		sharedCacheBase = uint64(0x180000000)
		sharedOffset    = uint64(0x1234)
	)
	shared := &DyldChainedFixups{PointerFormat: DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE}
	shared.SetSharedCacheBaseAddress(sharedCacheBase)
	rebase := DyldChainedPtrArm64eSharedCacheRebase{Pointer: sharedOffset}
	want := sharedCacheBase + sharedOffset
	if got, err := shared.ResolveRebaseVMAddress(rebase, 0x100000000, 0); err != nil || got != want {
		t.Fatalf("ResolveRebaseVMAddress shared cache = %#x, %v; want %#x", got, err, want)
	}
	if got, err := shared.ResolveRawRebaseVMAddress(sharedOffset, 0x100000000, 0); err != nil || got != want {
		t.Fatalf("ResolveRawRebaseVMAddress shared cache = %#x, %v; want %#x", got, err, want)
	}

	v2 := &DyldChainedFixups{PointerFormat: DYLD_CHAINED_PTR_SHARED_CACHE_V2}
	v2.SetSharedCacheBaseAddress(sharedCacheBase)
	if got, err := v2.ResolveRebaseVMAddress(DyldChainedPtrSharedCacheV2Rebase{}, 0x100000000, 0); err != nil || got != 0 {
		t.Fatalf("ResolveRebaseVMAddress v2 NULL = %#x, %v; want 0", got, err)
	}

	offset := &DyldChainedFixups{PointerFormat: DYLD_CHAINED_PTR_64_OFFSET}
	if _, err := offset.ResolveRebaseVMAddress(DyldChainedPtr64RebaseOffset{Pointer: 2}, math.MaxUint64, 0); err == nil {
		t.Fatal("ResolveRebaseVMAddress accepted overflowing base plus runtime offset")
	}
	if _, err := offset.ResolveRebaseVMAddress(DyldChainedPtr64RebaseOffset{}, math.MaxUint64-1, 2); err == nil {
		t.Fatal("ResolveRebaseVMAddress accepted overflowing slide")
	}

	segmented := &DyldChainedFixups{
		PointerFormat: DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
		Starts: []DyldChainedStarts{{
			SegmentVMOffset: math.MaxUint64,
		}},
	}
	if _, err := segmented.ResolveRebaseVMAddress(DyldChainedPtrArm64eSegmentedRebase{Pointer: 1}, 0, 0); err == nil {
		t.Fatal("ResolveRebaseVMAddress accepted overflowing segmented target")
	}
}

func TestGetAuthRebaseChecksKernelAuthBit(t *testing.T) {
	const target = uint64(0x1234)
	for _, authenticated := range []bool{false, true} {
		raw := target
		if authenticated {
			raw |= uint64(1) << 63
		}
		rebase := DyldChainedPtr64KernelCacheRebase{Pointer: raw}
		dcf := &DyldChainedFixups{
			fixups:       map[uint64][]Fixup{target: {rebase}},
			chainsParsed: true,
		}
		_, got := dcf.GetAuthRebase(target)
		if got != authenticated {
			t.Fatalf("GetAuthRebase authenticated=%v returned %v", authenticated, got)
		}
	}
}

func TestLookupByTargetPreservesEveryLocationAndFindsLaterAuthRebase(t *testing.T) {
	const target = uint64(0x2345)
	first := DyldChainedPtr64RebaseOffset{Pointer: target, Fixup: 0x10}
	second := DyldChainedPtr64RebaseOffset{Pointer: target, Fixup: 0x28}
	dcf := &DyldChainedFixups{
		fixups:       make(map[uint64][]Fixup),
		chainsParsed: true,
	}
	dcf.addTargetFixup(target, first)
	dcf.addTargetFixup(target, second)

	fixups := dcf.LookupByTarget(target)
	if len(fixups) != 2 || fixups[0].Offset() != first.Offset() || fixups[1].Offset() != second.Offset() {
		t.Fatalf("LookupByTarget = %#v, want both locations %#x/%#x", fixups, first.Offset(), second.Offset())
	}
	fixups[0] = nil
	if again := dcf.LookupByTarget(target); len(again) != 2 || again[0] == nil {
		t.Fatalf("LookupByTarget exposed its internal slice: %#v", again)
	}

	unauth := DyldChainedPtr64KernelCacheRebase{Pointer: target, Fixup: 0x40}
	auth := DyldChainedPtr64KernelCacheRebase{Pointer: target | uint64(1)<<63, Fixup: 0x48}
	authFixups := &DyldChainedFixups{
		fixups:       make(map[uint64][]Fixup),
		chainsParsed: true,
	}
	authFixups.addTargetFixup(target, unauth)
	authFixups.addTargetFixup(target, auth)
	got, ok := authFixups.GetAuthRebase(target)
	if !ok || got.Offset() != auth.Offset() {
		t.Fatalf("GetAuthRebase = %#v, %v; want later authenticated location %#x", got, ok, auth.Offset())
	}
}

func TestLookupByTargetUsesEncodedSharedCacheV2Target(t *testing.T) {
	const (
		target = uint64(0x1234)
		high8  = uint64(0xab)
	)
	raw := high8<<56 | target // next=0, so the one-pointer chain terminates
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, raw)
	dcf := &DyldChainedFixups{
		PointerFormat: DYLD_CHAINED_PTR_SHARED_CACHE_V2,
		Starts: []DyldChainedStarts{{
			DyldChainedStartsInSegment: DyldChainedStartsInSegment{
				PageSize:      0x1000,
				PointerFormat: DYLD_CHAINED_PTR_SHARED_CACHE_V2,
				PageCount:     1,
			},
			PageStarts: []DCPtrStart{0},
		}},
		fixups:       make(map[uint64][]Fixup),
		bo:           binary.LittleEndian,
		sr:           &bytesMachoReader{Reader: bytes.NewReader(data)},
		chainsParsed: true,
	}
	if err := dcf.walkDcFixupChain(0, 0, 0); err != nil {
		t.Fatalf("walkDcFixupChain: %v", err)
	}
	fixups := dcf.LookupByTarget(target)
	if len(fixups) != 1 {
		t.Fatalf("LookupByTarget(%#x) = %#v, want one V2 rebase", target, fixups)
	}
	rebase, ok := fixups[0].(DyldChainedPtrSharedCacheV2Rebase)
	if !ok || rebase.Target() != target || rebase.UnpackedTarget() != high8<<56|target {
		t.Fatalf("V2 rebase = %#v, want target=%#x high8=%#x", fixups[0], target, high8)
	}
}

func Test32PointerFormatsUseFormatSpecificNextFields(t *testing.T) {
	tests := []struct {
		name          string
		format        DCPtrKind
		data          []byte
		wantOffsets   []uint64
		lookupOffset  uint64
		lookupPresent bool
	}{
		{
			name:   "cache ignores generic32 next bits inside its target",
			format: DYLD_CHAINED_PTR_32_CACHE,
			data: func() []byte {
				data := make([]byte, 8)
				binary.LittleEndian.PutUint32(data, uint32(1)<<26)
				return data
			}(),
			wantOffsets:   []uint64{0},
			lookupOffset:  4,
			lookupPresent: false,
		},
		{
			name:   "firmware reads all six next bits",
			format: DYLD_CHAINED_PTR_32_FIRMWARE,
			data: func() []byte {
				data := make([]byte, 132)
				binary.LittleEndian.PutUint32(data, uint32(1)<<31)
				binary.LittleEndian.PutUint32(data[128:], 0x1234)
				return data
			}(),
			wantOffsets:   []uint64{0, 128},
			lookupOffset:  128,
			lookupPresent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcf := &DyldChainedFixups{
				PointerFormat: tt.format,
				Starts: []DyldChainedStarts{{
					DyldChainedStartsInSegment: DyldChainedStartsInSegment{
						PageSize:      0x1000,
						PointerFormat: tt.format,
						PageCount:     1,
					},
					PageStarts: []DCPtrStart{0},
				}},
				fixups:         make(map[uint64][]Fixup),
				bo:             binary.LittleEndian,
				sr:             &bytesMachoReader{Reader: bytes.NewReader(tt.data)},
				metadataParsed: true,
				importsParsed:  true,
			}

			if err := dcf.walkDcFixupChain(0, 0, 0); err != nil {
				t.Fatalf("walkDcFixupChain: %v", err)
			}
			if len(dcf.Starts[0].Fixups) != len(tt.wantOffsets) {
				t.Fatalf("walk produced %d fixups, want %d: %#v", len(dcf.Starts[0].Fixups), len(tt.wantOffsets), dcf.Starts[0].Fixups)
			}
			for index, wantOffset := range tt.wantOffsets {
				if got := dcf.Starts[0].Fixups[index].Offset(); got != wantOffset {
					t.Fatalf("fixup[%d] offset = %#x, want %#x", index, got, wantOffset)
				}
			}

			fixup, err := dcf.GetFixupAtOffset(tt.lookupOffset)
			if tt.lookupPresent {
				if err != nil {
					t.Fatalf("GetFixupAtOffset(%#x): %v", tt.lookupOffset, err)
				}
				if fixup.Offset() != tt.lookupOffset {
					t.Fatalf("lookup offset = %#x, want %#x", fixup.Offset(), tt.lookupOffset)
				}
			} else if !errors.Is(err, ErrNoFixupAtOffset) {
				t.Fatalf("GetFixupAtOffset(%#x) error = %v, want ErrNoFixupAtOffset", tt.lookupOffset, err)
			}
		})
	}
}

func TestParseImportsRejectsHugeCountBeforeAllocation(t *testing.T) {
	dcf := &DyldChainedFixups{
		DyldChainedFixupsHeader: DyldChainedFixupsHeader{
			ImportsOffset: 28,
			SymbolsOffset: 32,
			ImportsCount:  math.MaxUint32,
			ImportsFormat: DC_IMPORT_ADDEND64,
			SymbolsFormat: DC_SFORMAT_UNCOMPRESSED,
		},
		r:  bytes.NewReader(make([]byte, 32)),
		bo: binary.LittleEndian,
	}

	if err := dcf.parseImports(); err == nil {
		t.Fatal("parseImports accepted an imports count that cannot fit in the payload")
	}
	if dcf.Imports != nil {
		t.Fatalf("parseImports mutated imports after rejecting the table: %#v", dcf.Imports)
	}
}

func TestEnsureImportsRejectsStartsMetadataOverlap(t *testing.T) {
	header := DyldChainedFixupsHeader{
		FixupsVersion: 0,
		StartsOffset:  uint32(binary.Size(DyldChainedFixupsHeader{})),
		ImportsOffset: uint32(binary.Size(DyldChainedFixupsHeader{})),
		SymbolsOffset: uint32(binary.Size(DyldChainedFixupsHeader{})) + 4,
		ImportsCount:  1,
		ImportsFormat: DC_IMPORT,
		SymbolsFormat: DC_SFORMAT_UNCOMPRESSED,
	}
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.LittleEndian, header); err != nil {
		t.Fatalf("write chained-fixups header: %v", err)
	}
	if err := binary.Write(&payload, binary.LittleEndian, uint32(0)); err != nil {
		t.Fatalf("write zero-segment starts table: %v", err)
	}

	dcf := &DyldChainedFixups{
		r:  bytes.NewReader(payload.Bytes()),
		bo: binary.LittleEndian,
	}
	if err := dcf.EnsureImports(); err == nil || !strings.Contains(err.Error(), "overlaps starts metadata") {
		t.Fatalf("EnsureImports overlap error = %v", err)
	}
	if dcf.importsParsed || dcf.Imports != nil {
		t.Fatalf("EnsureImports published imports after rejecting overlap: parsed=%v imports=%#v", dcf.importsParsed, dcf.Imports)
	}
}

func TestEnsureImportsValidatesZeroCountHeader(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DyldChainedFixupsHeader)
		want   string
	}{
		{
			name: "unknown imports format",
			mutate: func(header *DyldChainedFixupsHeader) {
				header.ImportsFormat = ImportFormat(math.MaxUint32)
			},
			want: "unknown chained imports format",
		},
		{
			name: "unknown symbols format",
			mutate: func(header *DyldChainedFixupsHeader) {
				header.SymbolsFormat = DCSymbolsFormat(math.MaxUint32)
			},
			want: "unknown chained symbols format",
		},
		{
			name: "historical compressed symbols format",
			mutate: func(header *DyldChainedFixupsHeader) {
				header.SymbolsFormat = DC_SFORMAT_ZLIB_COMPRESSED
			},
			want: "unknown chained symbols format",
		},
		{
			name: "symbols offset beyond payload",
			mutate: func(header *DyldChainedFixupsHeader) {
				header.SymbolsOffset = math.MaxUint32
			},
			want: "exceed payload size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := chainedStartsPayload(t, DYLD_CHAINED_PTR_64)
			var header DyldChainedFixupsHeader
			if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &header); err != nil {
				t.Fatalf("read header: %v", err)
			}
			tt.mutate(&header)
			var encoded bytes.Buffer
			if err := binary.Write(&encoded, binary.LittleEndian, header); err != nil {
				t.Fatalf("write header: %v", err)
			}
			copy(payload[:encoded.Len()], encoded.Bytes())

			dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
			if err := dcf.EnsureImports(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("EnsureImports error = %v, want %q", err, tt.want)
			}
			if dcf.importsParsed {
				t.Fatal("EnsureImports published zero-count cache after invalid header")
			}
		})
	}
}

func TestValidateImportCountUsesPointerOrdinalCapacity(t *testing.T) {
	tests := []struct {
		name   string
		format DCPtrKind
		count  uint32
		ok     bool
	}{
		{name: "arm64e below maximum", format: DYLD_CHAINED_PTR_ARM64E, count: 0xfffe, ok: true},
		{name: "arm64e at maximum", format: DYLD_CHAINED_PTR_ARM64E, count: 0xffff},
		{name: "userland24 below maximum", format: DYLD_CHAINED_PTR_ARM64E_USERLAND24, count: 0xfffffe, ok: true},
		{name: "userland24 at maximum", format: DYLD_CHAINED_PTR_ARM64E_USERLAND24, count: 0xffffff},
		{name: "format without binds", format: DYLD_CHAINED_PTR_64_KERNEL_CACHE, count: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcf := &DyldChainedFixups{
				DyldChainedFixupsHeader: DyldChainedFixupsHeader{ImportsCount: tt.count},
				PointerFormat:           tt.format,
			}
			err := dcf.validateImportCount()
			if tt.ok && err != nil {
				t.Fatalf("validateImportCount: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("validateImportCount accepted an unencodable import count")
			}
		})
	}
}

func TestChainedImportLibraryOrdinalUsesAppleSignedTail(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{name: "8-bit positive 200", got: DyldChainedImport(200).LibOrdinal(), want: 200},
		{name: "8-bit positive ceiling", got: DyldChainedImport(0xf0).LibOrdinal(), want: 240},
		{name: "8-bit negative tail", got: DyldChainedImport(0xf1).LibOrdinal(), want: -15},
		{name: "16-bit positive 40000", got: DyldChainedImport64(40000).LibOrdinal(), want: 40000},
		{name: "16-bit positive ceiling", got: DyldChainedImport64(0xfff0).LibOrdinal(), want: 65520},
		{name: "16-bit negative tail", got: DyldChainedImport64(0xfff1).LibOrdinal(), want: -15},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("LibOrdinal() = %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestFullChainWalkStopsBeforeNextPointerStartLeavesPage(t *testing.T) {
	data := make([]byte, 0x2000)
	binary.LittleEndian.PutUint64(data[0xff8:], uint64(4)<<51) // next start is 0x1008
	binary.LittleEndian.PutUint64(data[0x1008:], 0)
	reader := &bytesMachoReader{Reader: bytes.NewReader(data)}
	dcf := &DyldChainedFixups{
		Starts: []DyldChainedStarts{{
			DyldChainedStartsInSegment: DyldChainedStartsInSegment{
				PageSize:      0x1000,
				PointerFormat: DYLD_CHAINED_PTR_64,
				SegmentOffset: 0,
				PageCount:     2,
			},
			PageStarts: []DCPtrStart{0xff8, DYLD_CHAINED_PTR_START_NONE},
		}},
		Imports:       []DcfImport{},
		importsParsed: true,
		fixups:        make(map[uint64][]Fixup),
		sr:            reader,
		bo:            binary.LittleEndian,
	}
	if err := dcf.walkDcFixupChain(0, 0, 0xff8); err != nil {
		t.Fatalf("walkDcFixupChain: %v", err)
	}
	if len(dcf.Starts[0].Fixups) != 1 || dcf.Starts[0].Fixups[0].Offset() != 0xff8 {
		t.Fatalf("published fixups = %#v, want only offset 0xff8", dcf.Starts[0].Fixups)
	}
}

func exactMembershipTestFixups(raw uint64, imports []DcfImport) *DyldChainedFixups {
	data := make([]byte, 0x1000)
	binary.LittleEndian.PutUint64(data, raw)
	reader := &bytesMachoReader{Reader: bytes.NewReader(data)}
	return &DyldChainedFixups{
		PointerFormat: DYLD_CHAINED_PTR_64,
		Starts: []DyldChainedStarts{{
			DyldChainedStartsInSegment: DyldChainedStartsInSegment{
				PageSize:      0x1000,
				PointerFormat: DYLD_CHAINED_PTR_64,
				PageCount:     1,
			},
			PageStarts: []DCPtrStart{0},
		}},
		Imports:        imports,
		metadataParsed: true,
		importsParsed:  true,
		sr:             reader,
		bo:             binary.LittleEndian,
	}
}

func TestRebaseRequiresExactChainMembership(t *testing.T) {
	dcf := exactMembershipTestFixups(0, nil)
	if got, err := dcf.RebaseRaw(0, 0, 0); err != nil || got != 0 {
		t.Fatalf("chain-start RebaseRaw() = %#x, %v", got, err)
	}
	if _, err := dcf.RebaseRaw(8, 0, 0); !errors.Is(err, ErrNoFixupAtOffset) {
		t.Fatalf("same-page non-member error = %v, want ErrNoFixupAtOffset", err)
	}

	bind := exactMembershipTestFixups(uint64(1)<<63, []DcfImport{{
		Name:   "symbol",
		Import: DyldChainedImport(0),
	}})
	if _, err := bind.RebaseRaw(0, 0, 0); err == nil || !strings.Contains(err.Error(), "bind, not a rebase") {
		t.Fatalf("bind-slot RebaseRaw error = %v", err)
	}
}

func TestBindOrdinalMustIndexImports(t *testing.T) {
	tests := []struct {
		name   string
		format DCPtrKind
		raw    uint64
	}{
		{name: "generic64", format: DYLD_CHAINED_PTR_64_OFFSET, raw: uint64(1) | uint64(1)<<63},
		{name: "arm64e24", format: DYLD_CHAINED_PTR_ARM64E_USERLAND24, raw: uint64(1) | uint64(1)<<62},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 8)
			binary.LittleEndian.PutUint64(data, tt.raw)
			dcf := &DyldChainedFixups{
				PointerFormat: tt.format,
				Imports:       []DcfImport{{Name: "only-ordinal-zero"}},
				Starts: []DyldChainedStarts{{
					DyldChainedStartsInSegment: DyldChainedStartsInSegment{
						PageSize:      0x1000,
						PointerFormat: tt.format,
						PageCount:     1,
					},
					PageStarts: []DCPtrStart{0},
				}},
				fixups:         make(map[uint64][]Fixup),
				bo:             binary.LittleEndian,
				sr:             &bytesMachoReader{Reader: bytes.NewReader(data)},
				metadataParsed: true,
				importsParsed:  true,
			}
			if _, err := dcf.readAndDecodeFixup(tt.format, 0); err == nil || !strings.Contains(err.Error(), "bind ordinal 1") {
				t.Fatalf("point decode error = %v", err)
			}
			if err := dcf.walkDcFixupChain(0, 0, 0); err == nil || !strings.Contains(err.Error(), "bind ordinal 1") {
				t.Fatalf("full walk error = %v", err)
			}
			if len(dcf.Starts[0].Fixups) != 0 {
				t.Fatalf("full walk published invalid bind: %#v", dcf.Starts[0].Fixups)
			}
		})
	}
}

func chainedStartsPayloadWithPageMetadata(t *testing.T, format DCPtrKind, pageSize uint16, pageStarts []DCPtrStart, chainStarts []uint16) []byte {
	t.Helper()
	headerSize := uint32(binary.Size(DyldChainedFixupsHeader{}))
	recordSize := uint32(binary.Size(DyldChainedStartsInSegment{})) + uint32(len(pageStarts)+len(chainStarts))*2
	header := DyldChainedFixupsHeader{
		StartsOffset:  headerSize,
		ImportsOffset: headerSize + 8 + recordSize,
		SymbolsOffset: headerSize + 8 + recordSize,
		ImportsFormat: DC_IMPORT,
	}
	record := DyldChainedStartsInSegment{
		Size:          recordSize,
		PageSize:      pageSize,
		PointerFormat: format,
		PageCount:     uint16(len(pageStarts)),
	}
	var payload bytes.Buffer
	for _, value := range []any{
		header,
		uint32(1),
		uint32(8),
		record,
		pageStarts,
		chainStarts,
	} {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatalf("write chained starts payload: %v", err)
		}
	}
	return payload.Bytes()
}

func chainedStartsPayload(t *testing.T, format DCPtrKind) []byte {
	return chainedStartsPayloadWithPageMetadata(t, format, 0x1000, []DCPtrStart{DYLD_CHAINED_PTR_START_NONE}, nil)
}

func unparsedGeneric64Fixups(t *testing.T) (*DyldChainedFixups, *bytesMachoReader) {
	t.Helper()
	payload := chainedStartsPayloadWithPageMetadata(t, DYLD_CHAINED_PTR_64, 0x1000, []DCPtrStart{0}, nil)
	data := make([]byte, 0x1000)
	binary.LittleEndian.PutUint64(data, 0x1234)
	reader := &bytesMachoReader{Reader: bytes.NewReader(data)}
	var machoReader types.MachoReader = reader
	return NewChainedFixups(bytes.NewReader(payload), &machoReader, binary.LittleEndian), reader
}

func TestParseDoesNotMoveSharedReaderCursor(t *testing.T) {
	dcf, reader := unparsedGeneric64Fixups(t)
	if _, err := reader.Seek(7, io.SeekStart); err != nil {
		t.Fatalf("position reader: %v", err)
	}
	if _, err := dcf.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	position, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("query reader cursor: %v", err)
	}
	if position != 7 {
		t.Fatalf("reader cursor moved to %d, want 7", position)
	}
}

func TestConcurrentLookupsSynchronizeInitialParse(t *testing.T) {
	dcf, _ := unparsedGeneric64Fixups(t)
	const goroutines = 48
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			switch index % 3 {
			case 0:
				if got := dcf.LookupByTarget(0x1234); len(got) != 1 {
					t.Errorf("LookupByTarget returned %d fixups", len(got))
				}
			case 1:
				if fixup, ok := dcf.LookupByOffset(0); !ok || fixup == nil {
					t.Errorf("LookupByOffset returned %#v, %v", fixup, ok)
				}
			case 2:
				if auth, ok := dcf.GetAuthRebase(0x1234); ok || auth != nil {
					t.Errorf("GetAuthRebase returned %#v, %v", auth, ok)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestParseStartsRejectsSharedCacheSlidePseudoFormatsOnDisk(t *testing.T) {
	for _, format := range []DCPtrKind{0, DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3, DYLD_CHAINED_PTR_SHARED_CACHE_V2} {
		t.Run(format.String(), func(t *testing.T) {
			payload := chainedStartsPayload(t, format)
			dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
			if err := dcf.ParseStarts(); err == nil || !strings.Contains(err.Error(), "unsupported chained pointer format") {
				t.Fatalf("ParseStarts format %d error = %v", format, err)
			}
		})
	}
	for _, format := range []DCPtrKind{DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_SEGMENTED} {
		t.Run(format.String(), func(t *testing.T) {
			payload := chainedStartsPayload(t, format)
			dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
			if err := dcf.ParseStarts(); err != nil {
				t.Fatalf("ParseStarts legal format %d: %v", format, err)
			}
		})
	}
}

func TestParseStartsValidatesPageMetadata(t *testing.T) {
	t.Run("page size", func(t *testing.T) {
		payload := chainedStartsPayloadWithPageMetadata(t, DYLD_CHAINED_PTR_64, 0x2000, []DCPtrStart{DYLD_CHAINED_PTR_START_NONE}, nil)
		dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
		if err := dcf.ParseStarts(); err == nil || !strings.Contains(err.Error(), "page size") {
			t.Fatalf("ParseStarts invalid page size error = %v", err)
		}
	})

	t.Run("descending multi starts", func(t *testing.T) {
		payload := chainedStartsPayloadWithPageMetadata(t, DYLD_CHAINED_PTR_32, 0x1000,
			[]DCPtrStart{DYLD_CHAINED_PTR_START_MULTI | 1},
			[]uint16{0x20, uint16(DYLD_CHAINED_PTR_START_LAST | 0x10)})
		dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
		if err := dcf.ParseStarts(); err == nil || !strings.Contains(err.Error(), "not after previous") {
			t.Fatalf("ParseStarts descending multi-start error = %v", err)
		}
	})

	for _, pageSize := range []uint16{0x1000, 0x4000} {
		t.Run(fmt.Sprintf("valid page %#x", pageSize), func(t *testing.T) {
			payload := chainedStartsPayloadWithPageMetadata(t, DYLD_CHAINED_PTR_32, pageSize,
				[]DCPtrStart{DYLD_CHAINED_PTR_START_MULTI | 1},
				[]uint16{0x10, uint16(DYLD_CHAINED_PTR_START_LAST | 0x20)})
			dcf := &DyldChainedFixups{r: bytes.NewReader(payload), bo: binary.LittleEndian}
			if err := dcf.ParseStarts(); err != nil {
				t.Fatalf("ParseStarts valid page metadata: %v", err)
			}
		})
	}
}
