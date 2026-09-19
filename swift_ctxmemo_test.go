package macho

import (
	"encoding/binary"
	"io"
	"math/rand"
	"reflect"
	"testing"

	"github.com/zdypro888/go-macho/types/swift"
)

// randomContextImage lays out n 12-byte context descriptors followed by a name
// pool. Parents are random: valid ones, self references, cycles, null, indirect
// (GOT-style, low bit set) and pointers outside the image.
func randomContextImage(rng *rand.Rand, n int) (data []byte, descs []uint64, base uint64) {
	base = 0x100000000
	const descSize = 12
	gotOff := descSize * n
	namesOff := gotOff + 8*n
	data = make([]byte, namesOff+4*n+16)
	kinds := []swift.ContextDescriptorKind{
		swift.CDKindModule, swift.CDKindExtension, swift.CDKindAnonymous,
		swift.CDKindProtocol, swift.CDKindClass, swift.CDKindStruct, swift.CDKindEnum,
	}
	for i := 0; i < n; i++ {
		off := descSize * i
		binary.LittleEndian.PutUint32(data[off:], uint32(kinds[rng.Intn(len(kinds))]))
		var parent int
		switch rng.Intn(10) {
		case 0:
			parent = -1 // none
		case 1:
			parent = off // itself
		case 2:
			parent = len(data) + 64 + 4*rng.Intn(8) // outside the image
		case 3:
			// indirect through a GOT slot holding the address of another descriptor (or 0)
			slot := gotOff + 8*i
			if rng.Intn(4) != 0 {
				binary.LittleEndian.PutUint64(data[slot:], base+uint64(descSize*rng.Intn(n)))
			}
			parent = slot | 1
		case 4:
			parent = descSize * rng.Intn(n) // anywhere: cycles welcome
		default:
			if i == 0 {
				parent = -1
			} else {
				parent = descSize * rng.Intn(i) // earlier one: acyclic
			}
		}
		if parent >= 0 {
			binary.LittleEndian.PutUint32(data[off+4:], uint32(int32(parent-(off+4))))
		}
		if rng.Intn(5) != 0 {
			name := namesOff + 4*i
			copy(data[name:], []byte{byte('A' + i%26), byte('a' + rng.Intn(26)), 0})
			binary.LittleEndian.PutUint32(data[off+8:], uint32(int32(name-(off+8))))
		}
		descs = append(descs, base+uint64(off))
	}
	return data, descs, base
}

func TestGetContextDescMemoIsInvisible(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	var hits, errs, oks int
	for iter := 0; iter < 60; iter++ {
		n := 2 + rng.Intn(60)
		data, descs, base := randomContextImage(rng, n)
		got := newSwiftFixtureFile(t, base, data)
		want := newSwiftFixtureFile(t, base, data)
		queries := append([]uint64{}, descs...)
		queries = append(queries, 0, base+uint64(len(data))+8, base+uint64(len(data))-4, (base+uint64(12*n))|1)
		for scope := 0; scope < 3; scope++ {
			end := got.swiftContextScope()
			inner := got.swiftContextScope() // nested scopes share the memo
			for i := 0; i < 6*n; i++ {
				if i == 3*n {
					inner()
				}
				addr := queries[rng.Intn(len(queries))]
				start := int64(rng.Intn(len(data)))
				got.cr.Seek(start, io.SeekStart)
				want.cr.Seek(start, io.SeekStart)
				if _, ok := got.swiftCtx.entries[addr]; ok {
					hits++
				}
				gotCtx, gotErr := got.getContextDesc(got.cr, addr)
				wantCtx, wantErr := want.getContextDescUncached(want.cr, addr)
				if !reflect.DeepEqual(gotCtx, wantCtx) || errString(gotErr) != errString(wantErr) {
					t.Fatalf("iter %d: getContextDesc(%#x) = %+v, %s; uncached = %+v, %s",
						iter, addr, gotCtx, errString(gotErr), wantCtx, errString(wantErr))
				}
				gotPos, _ := got.cr.Seek(0, io.SeekCurrent)
				wantPos, _ := want.cr.Seek(0, io.SeekCurrent)
				if gotPos != wantPos {
					t.Fatalf("iter %d: getContextDesc(%#x) from %#x left the reader at %#x, uncached at %#x",
						iter, addr, start, gotPos, wantPos)
				}
				if gotErr != nil {
					errs++
				} else {
					oks++
					// callers own what they get back
					gotCtx.Name, gotCtx.Parent = "clobbered", "clobbered"
					gotCtx.Flags = 0xffffffff
				}
			}
			end()
			if got.swiftCtx.depth != 0 || got.swiftCtx.entries != nil {
				t.Fatalf("memo survived its scope: %+v", got.swiftCtx)
			}
		}
		// outside a scope nothing is remembered
		if _, err := got.getContextDesc(got.cr, descs[0]); err == nil && got.swiftCtx.entries != nil {
			t.Fatal("memo used outside a scope")
		}
	}
	if hits == 0 || errs == 0 || oks == 0 {
		t.Fatalf("weak test data: hits=%d errs=%d oks=%d", hits, errs, oks)
	}
}

// Every entry point into a parent cycle reports the cycle at its own address,
// memo or not.
func TestGetContextDescMemoCycleErrors(t *testing.T) {
	const base uint64 = 0x100000000
	data := make([]byte, 64)
	put := func(off int, parent int) {
		binary.LittleEndian.PutUint32(data[off:], uint32(swift.CDKindClass))
		binary.LittleEndian.PutUint32(data[off+4:], uint32(int32(parent-(off+4))))
	}
	put(0, 12)  // A -> B
	put(12, 24) // B -> C
	put(24, 0)  // C -> A
	put(36, 12) // D -> B (enters the cycle from outside)
	got := newSwiftFixtureFile(t, base, data)
	want := newSwiftFixtureFile(t, base, data)
	defer got.swiftContextScope()()
	for round := 0; round < 3; round++ {
		for _, off := range []uint64{0, 12, 24, 36, 36, 24, 12, 0} {
			_, gotErr := got.getContextDesc(got.cr, base+off)
			_, wantErr := want.getContextDescUncached(want.cr, base+off)
			if gotErr == nil || errString(gotErr) != errString(wantErr) {
				t.Fatalf("entry %#x: got %v, want %v", off, gotErr, wantErr)
			}
		}
	}
}

func TestGetContextDescMemoDisabledWithCallerCode(t *testing.T) {
	const base uint64 = 0x100000000
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[12:], uint32(swift.CDKindModule))
	for name, configure := range map[string]func(*File){
		"pointer resolver": func(f *File) {
			f.pointerResolver = func(uint64, uint64) (uint64, bool, error) { return 0, false, nil }
		},
		"custom vm converter": func(f *File) { f.customVMAddrConverter = true },
	} {
		f := newSwiftFixtureFile(t, base, data)
		configure(f)
		end := f.swiftContextScope()
		for i := 0; i < 3; i++ {
			if _, err := f.getContextDesc(f.cr, base+12); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if f.swiftCtx.entries != nil {
			t.Errorf("%s: lookups were remembered", name)
		}
		end()
	}
}

func BenchmarkGetContextDesc(b *testing.B) {
	const base uint64 = 0x100000000
	data := make([]byte, 128)
	put := func(off int, kind swift.ContextDescriptorKind, parent, name int) {
		binary.LittleEndian.PutUint32(data[off:], uint32(kind))
		if parent >= 0 {
			binary.LittleEndian.PutUint32(data[off+4:], uint32(int32(parent-(off+4))))
		}
		binary.LittleEndian.PutUint32(data[off+8:], uint32(int32(name-(off+8))))
	}
	put(12, swift.CDKindModule, -1, 64)
	put(24, swift.CDKindClass, 12, 68)
	put(36, swift.CDKindStruct, 24, 74)
	put(48, swift.CDKindEnum, 36, 80)
	copy(data[64:], "Mod\x00Outer\x00Inner\x00Leaf\x00")
	f := &testing.T{}
	file := newSwiftFixtureFile(f, base, data)
	b.Run("uncached", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			file.cr.SeekToAddr(base + 48) // as the parsers do
			file.getContextDescUncached(file.cr, base+48)
		}
	})
	b.Run("memo", func(b *testing.B) {
		defer file.swiftContextScope()()
		for i := 0; i < b.N; i++ {
			file.cr.SeekToAddr(base + 48)
			file.getContextDesc(file.cr, base+48)
		}
	})
}
