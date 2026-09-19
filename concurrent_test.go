package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/zdypro888/go-macho/types"
	"github.com/zdypro888/go-macho/types/swift"
)

// The parsers below all read sequentially through a cursor. Before every
// public call got a cursor of its own they shared one, so two of them running
// at the same time moved each other's position and returned wrong data. These
// tests run them concurrently on one *File over real binaries, under -race,
// and check that every call returns exactly what it returns alone.

// concurrencyTestBinaries are opened when present; the first one is required
// on macOS, the rest are skipped silently when they are missing or unreadable.
var concurrencyTestBinaries = []struct {
	path     string
	required bool
	rounds   int
}{
	{"/usr/bin/shortcuts", true, 40},
	{"/System/Library/Frameworks/Foundation.framework/Foundation", false, 3},
	{"/System/Applications/Calculator.app/Contents/MacOS/Calculator", false, 3},
}

// openRealBinaryForConcurrency opens the arm64(e) slice of a universal
// binary, or the file itself when it is thin, into memory.
func openRealBinaryForConcurrency(t *testing.T, path string) *File {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s: %v", path, err)
	}
	if ff, err := NewFatFile(bytes.NewReader(data)); err == nil {
		var pick *FatArch
		for i := range ff.Arches {
			a := &ff.Arches[i]
			if a.CPU == types.CPUArm64 {
				pick = a
				if a.SubCPU&types.CpuSubtypeMask == types.CPUSubtypeArm64E {
					break
				}
			}
		}
		if pick == nil {
			pick = &ff.Arches[0]
		}
		f, err := NewFile(bytes.NewReader(data[pick.Offset : pick.Offset+pick.Size]))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return f
	}
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Skipf("%s: not a Mach-O: %v", path, err)
	}
	return f
}

// concurrencyProbe is one public parsing call. run returns the call's result
// in a form that reflect.DeepEqual can compare between runs.
type concurrencyProbe struct {
	name string
	run  func(f *File) any
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var concurrencyProbes = []concurrencyProbe{
	{"GetObjCClasses", func(f *File) any {
		v, err := f.GetObjCClasses()
		return []any{v, errText(err)}
	}},
	{"GetObjCCategories", func(f *File) any {
		v, err := f.GetObjCCategories()
		return []any{v, errText(err)}
	}},
	{"GetObjCProtocols", func(f *File) any {
		v, err := f.GetObjCProtocols()
		return []any{v, errText(err)}
	}},
	{"GetObjCMethodLists", func(f *File) any {
		v, err := f.GetObjCMethodLists()
		return []any{v, errText(err)}
	}},
	{"GetObjCSelectorReferences", func(f *File) any {
		v, err := f.GetObjCSelectorReferences()
		return []any{v, errText(err)}
	}},
	{"GetSwiftTypes", func(f *File) any {
		v, err := f.GetSwiftTypes()
		return []any{v, errText(err)}
	}},
	{"GetSwiftProtocolConformances", func(f *File) any {
		v, err := f.GetSwiftProtocolConformances()
		return []any{v, errText(err)}
	}},
	{"GetSwiftProtocols", func(f *File) any {
		v, err := f.GetSwiftProtocols()
		return []any{v, errText(err)}
	}},
	{"GetSwiftFields", func(f *File) any {
		v, err := f.GetSwiftFields()
		return []any{v, errText(err)}
	}},
	{"GetSwiftAssociatedTypes", func(f *File) any {
		v, err := f.GetSwiftAssociatedTypes()
		return []any{v, errText(err)}
	}},
	{"GetSwiftTypeRefs", func(f *File) any {
		v, err := f.GetSwiftTypeRefs()
		return []any{v, errText(err)}
	}},
	{"GetSwiftBuiltinTypes", func(f *File) any {
		v, err := f.GetSwiftBuiltinTypes()
		return []any{v, errText(err)}
	}},
	{"GetSwiftClosures", func(f *File) any {
		v, err := f.GetSwiftClosures()
		return []any{v, errText(err)}
	}},
	{"GetSwiftAccessibleFunctions", func(f *File) any {
		v, err := f.GetSwiftAccessibleFunctions()
		return []any{v, errText(err)}
	}},
	{"DyldExports", func(f *File) any {
		v, err := f.DyldExports()
		return []any{v, errText(err)}
	}},
	{"GetExports", func(f *File) any {
		v, err := f.GetExports()
		return []any{v, errText(err)}
	}},
	{"GetDyldInfo", func(f *File) any {
		v, err := f.GetDyldInfo()
		return []any{v, errText(err)}
	}},
	{"GetBindInfo", func(f *File) any {
		v, err := f.GetBindInfo()
		return []any{v, errText(err)}
	}},
	{"GetCStrings", func(f *File) any {
		v, err := f.GetCStrings()
		return []any{v, errText(err)}
	}},
	{"GetFunctions", func(f *File) any {
		return f.GetFunctions()
	}},
	{"GetObjCImageInfo+HasSwift", func(f *File) any {
		v, err := f.GetObjCImageInfo()
		return []any{v, errText(err), f.HasSwift(), f.HasObjC()}
	}},
	{"FindSymbolAddress", func(f *File) any {
		var out []any
		for _, n := range []string{"_main", "__mh_execute_header", "_objc_msgSend", "_nope"} {
			a, err := f.FindSymbolAddress(n)
			out = append(out, a, errText(err))
		}
		return out
	}},
}

// equalParseResults is reflect.DeepEqual except that swift.Type.Size is
// ignored. Size is computed from the cursor position after a descriptor's
// out-of-line references were followed, and a reference whose target is
// already in the Swift cache is not followed; Size therefore already depends
// on the order of calls on one File in single-threaded use (GetSwiftFields or
// GetSwiftProtocolConformances before GetSwiftTypes changes it). Everything
// else must match exactly.
func equalParseResults(a, b any) bool {
	return equalValues(reflect.ValueOf(a), reflect.ValueOf(b), 0)
}

var swiftTypeType = reflect.TypeOf(swift.Type{})

func equalValues(a, b reflect.Value, depth int) bool {
	if depth > 200 {
		return true
	}
	if a.IsValid() != b.IsValid() {
		return false
	}
	if !a.IsValid() {
		return true
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Ptr, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return equalValues(a.Elem(), b.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if a.Type() == swiftTypeType && a.Type().Field(i).Name == "Size" {
				continue
			}
			if !equalValues(a.Field(i), b.Field(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if a.IsNil() != b.IsNil() {
			return false
		}
		fallthrough
	case reflect.Array:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !equalValues(a.Index(i), b.Index(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return false
		}
		iter := a.MapRange()
		for iter.Next() {
			bv := b.MapIndex(iter.Key())
			if !bv.IsValid() || !equalValues(iter.Value(), bv, depth+1) {
				return false
			}
		}
		return true
	case reflect.Func:
		return a.IsNil() == b.IsNil()
	default:
		if a.CanInterface() {
			return reflect.DeepEqual(a.Interface(), b.Interface())
		}
		return fmt.Sprint(a) == fmt.Sprint(b)
	}
}

// TestConcurrentParsersMatchSequential runs every probe concurrently on one
// File, many rounds, and compares each result with the one a fresh,
// single-threaded File produced.
func TestConcurrentParsersMatchSequential(t *testing.T) {
	for _, bin := range concurrencyTestBinaries {
		bin := bin
		t.Run(bin.path, func(t *testing.T) {
			if _, err := os.Stat(bin.path); err != nil {
				if bin.required {
					t.Fatalf("required test binary: %v", err)
				}
				t.Skip(err)
			}
			if !bin.required && testing.Short() {
				t.Skip("-short")
			}

			// The reference: one call each, on a File nobody else touches.
			ref := openRealBinaryForConcurrency(t, bin.path)
			want := make(map[string]any, len(concurrencyProbes))
			for _, p := range concurrencyProbes {
				want[p.name] = p.run(ref)
			}
			ref.Close()

			shared := openRealBinaryForConcurrency(t, bin.path)
			defer shared.Close()

			rounds := bin.rounds
			if testing.Short() {
				rounds = 3
			}
			for round := 0; round < rounds; round++ {
				var wg sync.WaitGroup
				errs := make(chan error, len(concurrencyProbes)*2)
				for _, p := range concurrencyProbes {
					// Every probe twice at once: the same call racing with itself
					// (shared caches) and with every other call (shared cursor).
					for dup := 0; dup < 2; dup++ {
						p := p
						wg.Add(1)
						go func() {
							defer wg.Done()
							got := p.run(shared)
							if !equalParseResults(got, want[p.name]) {
								errs <- fmt.Errorf("round %d: %s differs from the single-threaded result", round, p.name)
							}
						}()
					}
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Error(err)
				}
				if t.Failed() {
					return
				}
			}
		})
	}
}

// TestConcurrentSameCallRepeatedly hammers the two parsers that used to race
// most visibly (the ObjC and Swift walkers both seek through the whole image)
// against each other only, with many goroutines per call.
func TestConcurrentSameCallRepeatedly(t *testing.T) {
	const path = "/usr/bin/shortcuts"
	if _, err := os.Stat(path); err != nil {
		t.Skip(err)
	}
	ref := openRealBinaryForConcurrency(t, path)
	wantClasses, wantClassesErr := ref.GetObjCClasses()
	wantTypes, wantTypesErr := ref.GetSwiftTypes()
	wantConfs, wantConfsErr := ref.GetSwiftProtocolConformances()
	ref.Close()

	f := openRealBinaryForConcurrency(t, path)
	defer f.Close()

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	fail := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	for w := 0; w < workers; w++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				got, err := f.GetObjCClasses()
				if errText(err) != errText(wantClassesErr) || !equalParseResults(got, wantClasses) {
					fail("GetObjCClasses differs (err %v)", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				got, err := f.GetSwiftTypes()
				if errText(err) != errText(wantTypesErr) || !equalParseResults(got, wantTypes) {
					fail("GetSwiftTypes differs (err %v)", err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				got, err := f.GetSwiftProtocolConformances()
				if errText(err) != errText(wantConfsErr) || !equalParseResults(got, wantConfs) {
					fail("GetSwiftProtocolConformances differs (err %v)", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	for _, s := range failures {
		t.Error(s)
	}
}

// TestNewReaderIsIndependentCursor checks the cursor contract directly: two
// cursors from one File do not see each other's seeks, and a reader that
// cannot be cloned is handed out as it is.
func TestNewReaderIsIndependentCursor(t *testing.T) {
	data := make([]byte, 0x100)
	for i := range data {
		data[i] = byte(i)
	}
	const base uint64 = 0x100000000
	f := newSwiftFixtureFile(t, base, data)

	a, b := f.newReader(), f.newReader()
	if a == b || a == f.cr {
		t.Fatal("newReader returned the shared reader")
	}
	if err := a.SeekToAddr(base + 0x10); err != nil {
		t.Fatal(err)
	}
	if err := b.SeekToAddr(base + 0x80); err != nil {
		t.Fatal(err)
	}
	var x, y [1]byte
	if _, err := a.Read(x[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(y[:]); err != nil {
		t.Fatal(err)
	}
	if x[0] != 0x10 || y[0] != 0x80 {
		t.Fatalf("cursors interfere: read %#x and %#x, want 0x10 and 0x80", x[0], y[0])
	}

	// A reader without Clone is shared (and documented as not concurrent-safe).
	uncloneable := &fixedMachoReader{MachoReader: f.cr}
	g := &File{cr: uncloneable}
	if g.newReader() != types.MachoReader(uncloneable) {
		t.Fatal("an uncloneable reader must be handed out unchanged")
	}
}

// fixedMachoReader hides the Clone method of the embedded reader.
type fixedMachoReader struct {
	types.MachoReader
}

var _ types.ReaderCloner = (*types.CustomSectionReader)(nil)

// TestFileSetChildrenDoNotShareHeaderCursor: GetFileSetFileByName hands the
// parent's SectionReader to every child, whose NewFile then reads the header
// through it. That read must not move the parent's reader.
func TestFileSetChildrenDoNotShareHeaderCursor(t *testing.T) {
	data := make([]byte, 0x100)
	const childOffset = 0x40
	// A 64-bit header with no load commands at both places NewFile looks.
	binary.LittleEndian.PutUint32(data[0:], types.Magic64.Int())
	binary.LittleEndian.PutUint32(data[childOffset:], types.Magic64.Int())
	const base uint64 = 0x100000000
	parent := newSwiftFixtureFile(t, base, data)
	cr := parent.cr.(*types.CustomSectionReader)
	before, _ := cr.Seek(0, io.SeekCurrent)
	child, err := NewFile(bytes.NewReader(data), FileConfig{SectionReader: parent.sr, Offset: childOffset})
	if err != nil {
		t.Fatal(err)
	}
	if child.Magic != types.Magic64 {
		t.Fatalf("child header was not read from offset %#x", childOffset)
	}
	after, _ := cr.Seek(0, io.SeekCurrent)
	if after != before {
		t.Fatalf("child NewFile moved the parent's reader from %#x to %#x", before, after)
	}
}
