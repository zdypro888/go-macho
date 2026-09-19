package fixupchains

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

// newPageCacheTestFixups builds two views over the same bytes: one served by
// the page cache and one forced through the original link-by-link walker.
func newPageCacheTestFixups(format DCPtrKind, data []byte, segOffset uint64, pageSize, pageCount uint16, pageStarts []DCPtrStart, chainStarts []uint16) (cached, walker *DyldChainedFixups) {
	build := func() *DyldChainedFixups {
		return &DyldChainedFixups{
			PointerFormat: format,
			Starts: []DyldChainedStarts{{
				DyldChainedStartsInSegment: DyldChainedStartsInSegment{
					PageSize:      pageSize,
					PointerFormat: format,
					SegmentOffset: segOffset,
					PageCount:     pageCount,
				},
				PageStarts:  append([]DCPtrStart(nil), pageStarts...),
				ChainStarts: append([]uint16(nil), chainStarts...),
			}},
			Imports:        make([]DcfImport, 7),
			fixups:         make(map[uint64][]Fixup),
			r:              bytes.NewReader(nil),
			sr:             types.NewCustomSectionReader(bytes.NewReader(data), &types.VMAddrConverter{}, 0, int64(len(data))),
			bo:             binary.LittleEndian,
			metadataParsed: true,
			importsParsed:  true,
		}
	}
	cached, walker = build(), build()
	walker.disablePageCache = true
	return cached, walker
}

func compareFixupLookups(t *testing.T, name string, cached, walker *DyldChainedFixups, offsets []uint64) (found int) {
	t.Helper()
	for _, off := range offsets {
		wantFixup, wantErr := walker.GetFixupAtOffset(off)
		gotFixup, gotErr := cached.GetFixupAtOffset(off)
		if !reflect.DeepEqual(gotFixup, wantFixup) {
			t.Fatalf("%s: offset %#x: fixup = %#v, walker = %#v", name, off, gotFixup, wantFixup)
		}
		if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) ||
			(gotErr == ErrNoFixupAtOffset) != (wantErr == ErrNoFixupAtOffset) {
			t.Fatalf("%s: offset %#x: err = %v, walker = %v", name, off, gotErr, wantErr)
		}
		if gotErr == nil {
			found++
		}
	}
	return found
}

// TestPageCacheMatchesWalker feeds random page contents - which produce valid
// chains, chains running out of the segment, short reads at EOF, bad bind
// ordinals and overlapping multi-start chains - to both implementations and
// requires identical fixups and identical errors for every probed offset.
func TestPageCacheMatchesWalker(t *testing.T) {
	formats := []DCPtrKind{
		DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_32, DYLD_CHAINED_PTR_32_CACHE,
		DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_64_KERNEL_CACHE,
		DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_FIRMWARE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE,
		DYLD_CHAINED_PTR_ARM64E_USERLAND24, DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE, DYLD_CHAINED_PTR_32_FIRMWARE,
		DYLD_CHAINED_PTR_ARM64E_SEGMENTED, DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3, DYLD_CHAINED_PTR_SHARED_CACHE_V2,
		DCPtrKind(99),
	}
	const (
		pageSize  = 0x400
		pageCount = 6
		segOffset = 0x800
	)
	rng := rand.New(rand.NewSource(1))
	total := 0
	for _, format := range formats {
		for round := 0; round < 40; round++ {
			// Every third round the file ends inside the segment (short reads).
			size := segOffset + pageSize*pageCount + 64
			if round%3 == 2 {
				size = segOffset + pageSize*(pageCount-1) - rng.Intn(pageSize)
			}
			data := make([]byte, size)
			switch round % 4 {
			case 0: // sparse: small "next" values give long valid chains
				for i := 0; i+8 <= len(data); i += 8 {
					binary.LittleEndian.PutUint64(data[i:], uint64(rng.Intn(4)+1)<<51|uint64(rng.Intn(8)))
					if format == DYLD_CHAINED_PTR_32 || format == DYLD_CHAINED_PTR_32_CACHE || format == DYLD_CHAINED_PTR_32_FIRMWARE {
						binary.LittleEndian.PutUint32(data[i:], uint32(rng.Intn(3)+1)<<26|uint32(rng.Intn(64)))
						binary.LittleEndian.PutUint32(data[i+4:], uint32(rng.Intn(3)+1)<<26|uint32(rng.Intn(64)))
					}
				}
			default:
				rng.Read(data)
			}

			pageStarts := make([]DCPtrStart, pageCount)
			var chainStarts []uint16
			for p := range pageStarts {
				switch rng.Intn(6) {
				case 0:
					pageStarts[p] = DYLD_CHAINED_PTR_START_NONE
				case 1: // multi-start (only legal for 32-bit formats)
					pageStarts[p] = DYLD_CHAINED_PTR_START_MULTI | DCPtrStart(pageCount+len(chainStarts))
					n := rng.Intn(3) + 1
					at := rng.Intn(64) * 4
					for c := 0; c < n; c++ {
						entry := uint16(at)
						if c == n-1 && rng.Intn(8) != 0 {
							entry |= uint16(DYLD_CHAINED_PTR_START_LAST)
						}
						chainStarts = append(chainStarts, entry)
						at += rng.Intn(40)*4 - 8
						if at < 0 {
							at = 0
						}
					}
				case 2:
					pageStarts[p] = DCPtrStart(rng.Intn(pageSize + 16))
				default:
					pageStarts[p] = DCPtrStart(rng.Intn(pageSize/4) * 4)
				}
			}

			cached, walker := newPageCacheTestFixups(format, data, segOffset, pageSize, pageCount, pageStarts, chainStarts)
			offsets := make([]uint64, 0, pageSize*pageCount/2)
			for off := uint64(segOffset - 8); off < segOffset+pageSize*pageCount+8; off++ {
				if off%4 == 0 || rng.Intn(16) == 0 {
					offsets = append(offsets, off)
				}
			}
			rng.Shuffle(len(offsets), func(i, j int) { offsets[i], offsets[j] = offsets[j], offsets[i] })
			total += compareFixupLookups(t, format.String(), cached, walker, offsets)

			// Starts is exported and mutable: a changed page start must not be
			// answered from a stale entry.
			for p := range pageStarts {
				if pageStarts[p] != DYLD_CHAINED_PTR_START_NONE && pageStarts[p]&DYLD_CHAINED_PTR_START_MULTI == 0 {
					moved := DCPtrStart(rng.Intn(pageSize/8) * 8)
					cached.Starts[0].PageStarts[p] = moved
					walker.Starts[0].PageStarts[p] = moved
				}
			}
			total += compareFixupLookups(t, format.String()+" (moved starts)", cached, walker, offsets)
		}
	}
	if total < 10000 {
		t.Fatalf("only %d successful lookups: the test data no longer exercises valid chains", total)
	}
}

func BenchmarkGetFixupAtOffsetLongChain(b *testing.B) {
	const pageSize = 0x4000
	data := make([]byte, pageSize*4)
	for i := 0; i+8 <= len(data); i += 8 {
		binary.LittleEndian.PutUint64(data[i:], 1<<51) // arm64e rebase, next = 1 stride (8 bytes)
	}
	run := func(b *testing.B, disable bool) {
		dcf, _ := newPageCacheTestFixups(DYLD_CHAINED_PTR_ARM64E, data, 0, pageSize, 4, []DCPtrStart{0, 0, 0, 0}, nil)
		dcf.disablePageCache = disable
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			off := uint64(i*8) % uint64(len(data)-8) &^ 7
			if _, err := dcf.GetFixupAtOffset(off); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("cached", func(b *testing.B) { run(b, false) })
	b.Run("walker", func(b *testing.B) { run(b, true) })
}

// TestPageCacheConcurrentLookups is meaningful under -race: lookups may build
// and publish the same page concurrently.
func TestPageCacheConcurrentLookups(t *testing.T) {
	const pageSize = 0x1000
	data := make([]byte, pageSize*8)
	for i := 0; i+8 <= len(data); i += 8 {
		binary.LittleEndian.PutUint64(data[i:], 1<<51)
	}
	cached, walker := newPageCacheTestFixups(DYLD_CHAINED_PTR_ARM64E, data, 0, pageSize, 8, make([]DCPtrStart, 8), nil)
	done := make(chan error, 8)
	for g := 0; g < cap(done); g++ {
		go func(g int) {
			for i := 0; i < 4000; i++ {
				off := uint64((i*37+g*101)%(len(data)/4)) * 4
				want, wantErr := walker.GetFixupAtOffset(off)
				got, gotErr := cached.GetFixupAtOffset(off)
				if !reflect.DeepEqual(got, want) || (gotErr == nil) != (wantErr == nil) {
					done <- fmt.Errorf("offset %#x: got %v, %v; walker %v, %v", off, got, gotErr, want, wantErr)
					return
				}
			}
			done <- nil
		}(g)
	}
	for g := 0; g < cap(done); g++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
