package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zdypro888/go-macho/types"
	"github.com/zdypro888/go-macho/types/swift"
)

// These tests pin down inputs that used to take the process down (OOM, fatal
// stack overflow, nil dereference) and must now come back as ordinary errors
// quickly and without allocating what the corrupt size field asked for.

const (
	robustnessAllocBound = 64 << 20
	robustnessTimeBound  = 10 * time.Second
)

// bounded runs fn and fails the test if it allocates or takes too much.
func bounded(t *testing.T, fn func()) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(robustnessTimeBound):
		t.Fatalf("did not finish within %v", robustnessTimeBound)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > robustnessAllocBound {
		t.Fatalf("allocated %d MiB (bound %d MiB) in %v", alloc>>20, robustnessAllocBound>>20, time.Since(start))
	}
}

// seekOnlyReader hides Len() so that checkReadCount has to take the
// io.ReaderAt probing path that the File's MachoReader takes.
type seekOnlyReader struct{ r *bytes.Reader }

func (s seekOnlyReader) Read(p []byte) (int, error)            { return s.r.Read(p) }
func (s seekOnlyReader) Seek(o int64, w int) (int64, error)    { return s.r.Seek(o, w) }
func (s seekOnlyReader) ReadAt(p []byte, o int64) (int, error) { return s.r.ReadAt(p, o) }
func newSeekOnlyReader(data []byte, pos int64) seekOnlyReader {
	r := bytes.NewReader(data)
	r.Seek(pos, io.SeekStart)
	return seekOnlyReader{r}
}

func TestCheckReadCount(t *testing.T) {
	big := make([]byte, 3<<20)
	tests := []struct {
		name     string
		r        any
		count    uint64
		elemSize uint64
		wantErr  error
	}{
		{"zero count", bytes.NewReader(nil), 0, 12, nil},
		{"exact fit", bytes.NewReader(make([]byte, 24)), 2, 12, nil},
		{"one byte short", bytes.NewReader(make([]byte, 23)), 2, 12, io.ErrUnexpectedEOF},
		{"empty reader", bytes.NewReader(nil), 1, 4, io.EOF},
		{"huge count", bytes.NewReader(make([]byte, 64)), 0xfff80000, 12, io.ErrUnexpectedEOF},
		{"multiplication overflow", bytes.NewReader(make([]byte, 64)), 1 << 62, 12, io.ErrUnexpectedEOF},
		{"probe: small totals are not probed", newSeekOnlyReader(make([]byte, 8), 0), 1000, 4, nil},
		{"probe: large total that exists", newSeekOnlyReader(big, 16), (3<<20 - 16) / 4, 4, nil},
		{"probe: large total past EOF", newSeekOnlyReader(big, 17), (3<<20 - 16) / 4, 4, io.ErrUnexpectedEOF},
		{"probe: huge count", newSeekOnlyReader(big, 0), 0x6d000000, 4, io.ErrUnexpectedEOF},
		{"probe: offset overflow", newSeekOnlyReader(big, 8), (1<<63 - 1) / 4, 4, io.ErrUnexpectedEOF},
		{"unknown reader is let through", strings.NewReplacer(), 1 << 40, 4, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkReadCount(tt.r, tt.count, tt.elemSize)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestReadDataHelpersMatchMakeAndRead(t *testing.T) {
	src := make([]byte, safeAllocChunk+4096)
	for i := range src {
		src[i] = byte(i * 7)
	}
	vma := &types.VMAddrConverter{
		Converter:    func(a uint64) uint64 { return a },
		VMAddr2Offet: func(a uint64) (uint64, error) { return a - 0x1000, nil },
		Offet2VMAddr: func(o uint64) (uint64, error) { return o + 0x1000, nil },
	}
	for _, n := range []uint64{0, 1, 4096, safeAllocChunk - 1, safeAllocChunk, safeAllocChunk + 100} {
		const off = 3
		want := make([]byte, n)
		if _, err := bytes.NewReader(src).ReadAt(want, off); err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(src)
		r.Seek(off, io.SeekStart)
		var got []byte
		if err := readDataFrom(r, n, &got); err != nil {
			t.Fatalf("readDataFrom(%d): %v", n, err)
		}
		if pos, _ := r.Seek(0, io.SeekCurrent); pos != off+int64(n) {
			t.Fatalf("readDataFrom(%d) left the reader at %d", n, pos)
		}
		gotAt, err := readDataAt(bytes.NewReader(src), n, off)
		if err != nil {
			t.Fatalf("readDataAt(%d): %v", n, err)
		}
		cr := types.NewCustomSectionReader(bytes.NewReader(src), vma, 0, 1<<63-1)
		gotAddr, err := readDataAtAddr(cr, n, 0x1000+off)
		if err != nil {
			t.Fatalf("readDataAtAddr(%d): %v", n, err)
		}
		for name, b := range map[string][]byte{"readDataFrom": got, "readDataAt": gotAt, "readDataAtAddr": gotAddr} {
			if !bytes.Equal(b, want) || b == nil {
				t.Fatalf("%s(%d) returned different bytes", name, n)
			}
			if cap(b) != len(b) {
				t.Fatalf("%s(%d): cap %d != len %d (GetCStrings relies on bytes.Buffer.Cap)", name, n, cap(b), len(b))
			}
		}
	}

	// A size the input cannot back is an error, not an allocation.
	for _, n := range []uint64{1 << 32, 1 << 40, 1<<64 - 16} {
		bounded(t, func() {
			var dat []byte
			if err := readDataFrom(bytes.NewReader(src[:100]), n, &dat); err == nil {
				t.Errorf("readDataFrom(%#x) succeeded on a 100 byte input", n)
			}
			if _, err := readDataAt(bytes.NewReader(src[:100]), n, 0); err == nil {
				t.Errorf("readDataAt(%#x) succeeded on a 100 byte input", n)
			}
			cr := types.NewCustomSectionReader(bytes.NewReader(src[:100]), vma, 0, 1<<63-1)
			if _, err := readDataAtAddr(cr, n, 0x1000); err == nil {
				t.Errorf("readDataAtAddr(%#x) succeeded on a 100 byte input", n)
			}
		})
	}
}

func TestSwiftCountsFromImageAreBounded(t *testing.T) {
	const base uint64 = 0x100000000

	t.Run("field descriptor NumFields", func(t *testing.T) {
		data := make([]byte, 64)
		binary.LittleEndian.PutUint16(data[8:], 0)           // Kind
		binary.LittleEndian.PutUint16(data[10:], 12)         // FieldRecordSize
		binary.LittleEndian.PutUint32(data[12:], 0xfff80000) // NumFields
		for name, r := range map[string]io.ReadSeeker{
			"section bytes": bytes.NewReader(data),
			"image reader":  newSwiftFixtureFile(t, base, data).cr,
		} {
			t.Run(name, func(t *testing.T) {
				file := newSwiftFixtureFile(t, base, data)
				file.swift = make(map[uint64]any)
				bounded(t, func() {
					if field, err := file.readField(file.cr, r, base); err == nil {
						t.Errorf("readField accepted NumFields=%#x: %v", field.NumFields, field)
					}
				})
			})
		}
	})

	t.Run("protocol NumRequirementsInSignature", func(t *testing.T) {
		data := make([]byte, 64)
		binary.LittleEndian.PutUint32(data[0:], uint32(swift.CDKindProtocol))
		binary.LittleEndian.PutUint32(data[12:], 0x6d000000) // NumRequirementsInSignature
		file := newSwiftFixtureFile(t, base, data)
		file.swift = make(map[uint64]any)
		bounded(t, func() {
			if _, err := file.parseProtocol(file.cr, file.cr, &swift.Type{Address: base}); err == nil {
				t.Error("parseProtocol accepted NumRequirementsInSignature=0x6d000000")
			}
		})
	})

	t.Run("valid field descriptor is unchanged", func(t *testing.T) {
		data := make([]byte, 64)
		binary.LittleEndian.PutUint16(data[10:], 12)
		binary.LittleEndian.PutUint32(data[12:], 2) // NumFields
		// record 0 @16, record 1 @28; names @48 and @52
		binary.LittleEndian.PutUint32(data[16:], 2)
		binary.LittleEndian.PutUint32(data[24:], uint32(48-24))
		binary.LittleEndian.PutUint32(data[36:], uint32(52-36))
		copy(data[48:], "ab\x00")
		copy(data[52:], "cde\x00")
		file := newSwiftFixtureFile(t, base, data)
		file.swift = make(map[uint64]any)
		field, err := file.readField(file.cr, bytes.NewReader(data), base)
		if err != nil {
			t.Fatalf("readField: %v", err)
		}
		if len(field.Records) != 2 || cap(field.Records) != 2 ||
			field.Records[0].Name != "ab" || field.Records[1].Name != "cde" || field.Records[0].Flags != 2 {
			t.Fatalf("unexpected records: %+v", field.Records)
		}
	})
}

func TestGetContextDescParentChain(t *testing.T) {
	const base uint64 = 0x100000000

	put := func(data []byte, off int, kind swift.ContextDescriptorKind, parent, name int) {
		binary.LittleEndian.PutUint32(data[off:], uint32(kind))
		if parent >= 0 {
			binary.LittleEndian.PutUint32(data[off+4:], uint32(int32(parent-(off+4))))
		}
		if name >= 0 {
			binary.LittleEndian.PutUint32(data[off+8:], uint32(int32(name-(off+8))))
		}
	}

	t.Run("self parent", func(t *testing.T) {
		data := make([]byte, 64)
		put(data, 16, swift.CDKindClass, 16, -1)
		file := newSwiftFixtureFile(t, base, data)
		bounded(t, func() {
			if ctx, err := file.getContextDesc(file.cr, base+16); err == nil {
				t.Errorf("cyclic parent chain was accepted: %#v", ctx)
			} else if !strings.Contains(err.Error(), "cycle") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	})

	t.Run("two descriptor cycle", func(t *testing.T) {
		data := make([]byte, 64)
		put(data, 0, swift.CDKindStruct, 16, -1)
		put(data, 16, swift.CDKindClass, 0, -1)
		file := newSwiftFixtureFile(t, base, data)
		bounded(t, func() {
			if ctx, err := file.getContextDesc(file.cr, base); err == nil {
				t.Errorf("cyclic parent chain was accepted: %#v", ctx)
			}
		})
	})

	t.Run("acyclic chain deeper than the cap", func(t *testing.T) {
		n := maxSwiftContextDepth + 8
		data := make([]byte, 12*n+16)
		for i := 1; i < n; i++ {
			put(data, 12*i, swift.CDKindAnonymous, 12*(i+1), -1)
		}
		file := newSwiftFixtureFile(t, base, data)
		bounded(t, func() {
			if _, err := file.getContextDesc(file.cr, base+12); err == nil {
				t.Error("absurdly deep parent chain was accepted")
			}
		})
	})

	t.Run("valid nesting is unchanged", func(t *testing.T) {
		data := make([]byte, 96)
		put(data, 12, swift.CDKindModule, -1, 64) // Mod
		put(data, 24, swift.CDKindClass, 12, 68)  // Mod.Outer
		put(data, 36, swift.CDKindStruct, 24, 74) // Mod.Outer.Inner
		put(data, 48, swift.CDKindEnum, 36, 80)   // Mod.Outer.Inner.Leaf
		copy(data[64:], "Mod\x00")
		copy(data[68:], "Outer\x00")
		copy(data[74:], "Inner\x00")
		copy(data[80:], "Leaf\x00")
		file := newSwiftFixtureFile(t, base, data)
		ctx, err := file.getContextDesc(file.cr, base+48)
		if err != nil {
			t.Fatalf("getContextDesc: %v", err)
		}
		if ctx.Name != "Leaf" || ctx.Parent != "Mod.Outer.Inner" {
			t.Fatalf("got Parent=%q Name=%q, want Mod.Outer.Inner / Leaf", ctx.Parent, ctx.Name)
		}
	})
}

func TestConvertToVMAddrOldArm64eFallbackDoesNotPanic(t *testing.T) {
	file := newSwiftFixtureFile(t, 0x100000000, make([]byte, 16))
	file.CPU = types.CPUArm64
	file.SubCPU = types.CPUSubtypeArm64E
	tests := []struct {
		name  string
		value uint64
	}{
		{"bind", 1 << 62},
		{"auth bind", 1<<63 | 1<<62 | 0x21039},
		{"bind with ordinal", 1<<62 | 0x2000008},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The zero DyldChainedFixups{} used by the fallback has no imports,
			// so a bind can never be resolved: the raw value comes back.
			if got := file.convertToVMAddr(tt.value); got != tt.value {
				t.Fatalf("convertToVMAddr(%#x) = %#x, want the raw value", tt.value, got)
			}
		})
	}
}

// thinSystemBinary returns one thin Mach-O slice of a small system binary.
func thinSystemBinary(t *testing.T) []byte {
	t.Helper()
	const path = "/bin/ls"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s is not available: %v", path, err)
	}
	if fat, err := NewFatFile(bytes.NewReader(data)); err == nil {
		defer fat.Close()
		if len(fat.Arches) == 0 {
			t.Skipf("%s has no slices", path)
		}
		arch := fat.Arches[len(fat.Arches)-1]
		if uint64(arch.Offset)+uint64(arch.Size) > uint64(len(data)) {
			t.Skipf("%s has a malformed fat header", path)
		}
		data = data[arch.Offset : arch.Offset+arch.Size]
	}
	if f, err := NewFile(bytes.NewReader(data)); err != nil {
		t.Skipf("%s does not parse: %v", path, err)
	} else {
		f.Close()
	}
	return data
}

func findLoadCommand(data []byte, want types.LoadCmd) int {
	if len(data) < 32 || binary.LittleEndian.Uint32(data) != uint32(types.Magic64) {
		return -1
	}
	ncmds := binary.LittleEndian.Uint32(data[16:])
	off := 32
	for i := uint32(0); i < ncmds && off+8 <= len(data); i++ {
		if types.LoadCmd(binary.LittleEndian.Uint32(data[off:])) == want {
			return off
		}
		off += int(binary.LittleEndian.Uint32(data[off+4:]))
	}
	return -1
}

func TestNewFileBoundsLoadCommandAllocations(t *testing.T) {
	src := thinSystemBinary(t)
	le := binary.LittleEndian

	tests := []struct {
		name   string
		victim types.LoadCmd
		mutate func(cmd []byte)
	}{
		{"LC_CODE_SIGNATURE datasize", types.LC_CODE_SIGNATURE, func(c []byte) {
			le.PutUint32(c[12:], 0xfffffff0)
		}},
		{"LC_SEGMENT_SPLIT_INFO datasize", types.LC_FUNCTION_STARTS, func(c []byte) {
			le.PutUint32(c[0:], uint32(types.LC_SEGMENT_SPLIT_INFO))
			le.PutUint32(c[12:], 0xfffffff0)
		}},
		{"LC_DATA_IN_CODE datasize", types.LC_DATA_IN_CODE, func(c []byte) {
			le.PutUint32(c[12:], 0xfffffff0)
		}},
		{"LC_TWOLEVEL_HINTS nhints", types.LC_SOURCE_VERSION, func(c []byte) {
			le.PutUint32(c[0:], uint32(types.LC_TWOLEVEL_HINTS))
			le.PutUint32(c[8:], 0)
			le.PutUint32(c[12:], 0x3fffffff)
		}},
		{"LC_UNIXTHREAD count", types.LC_SOURCE_VERSION, func(c []byte) {
			le.PutUint32(c[0:], uint32(types.LC_UNIXTHREAD))
			le.PutUint32(c[8:], 1)
			le.PutUint32(c[12:], 0x3ffffffc)
		}},
		{"LC_THREAD count", types.LC_SOURCE_VERSION, func(c []byte) {
			le.PutUint32(c[0:], uint32(types.LC_THREAD))
			le.PutUint32(c[8:], 1)
			le.PutUint32(c[12:], 0x3ffffffc)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Clone(src)
			off := findLoadCommand(data, tt.victim)
			if off < 0 {
				t.Skipf("no %s in the seed binary", tt.victim)
			}
			tt.mutate(data[off:])
			bounded(t, func() {
				f, err := NewFile(bytes.NewReader(data))
				if err == nil {
					f.Close()
					t.Error("NewFile accepted a load command whose size exceeds the file")
				}
			})
		})
	}

	t.Run("thread count uint32 wrap is preserved", func(t *testing.T) {
		// Count*4 wraps to 8 in uint32: that parsed before and must keep
		// parsing to the same value.
		data := bytes.Clone(src)
		off := findLoadCommand(data, types.LC_UUID) // 24 bytes: flavor, count, 8 bytes of state
		if off < 0 {
			t.Skip("no LC_UUID in the seed binary")
		}
		le.PutUint32(data[off:], uint32(types.LC_THREAD))
		le.PutUint32(data[off+8:], 1)
		le.PutUint32(data[off+12:], 0x40000002)
		le.PutUint64(data[off+16:], 0x1122334455667788)
		f, err := NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("NewFile: %v", err)
		}
		defer f.Close()
		for _, l := range f.Loads {
			if th, ok := l.(*Thread); ok {
				if len(th.Threads) != 1 || th.Threads[0].Count != 0x40000002 ||
					!bytes.Equal(th.Threads[0].Data, data[off+16:off+24]) {
					t.Fatalf("unexpected thread state: %+v", th.Threads)
				}
				return
			}
		}
		t.Fatal("LC_THREAD was not parsed")
	})
}

func TestGetCStringsBoundsSectionSize(t *testing.T) {
	src := thinSystemBinary(t)
	f, err := NewFile(bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want, err := f.GetCStrings()
	if err != nil {
		t.Fatalf("GetCStrings on the pristine binary: %v", err)
	}
	if len(want) == 0 {
		t.Skip("seed binary has no cstring sections")
	}

	g, err := NewFile(bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, sec := range g.Sections {
		if sec.Flags.IsCstringLiterals() {
			sec.Size = 1 << 40
		}
	}
	bounded(t, func() {
		if _, err := g.GetCStrings(); err == nil {
			t.Error("GetCStrings accepted a 1 TiB cstring section")
		}
	})
}
