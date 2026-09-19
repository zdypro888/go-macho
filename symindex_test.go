package macho

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/zdypro888/go-macho/types"
)

// getBindNameLinear is the classic-dyld-info branch of GetBindName as it was
// before the bind index, verbatim.
func (f *File) getBindNameLinear(pointer uint64) (string, error) {
	binds, err := f.GetBindInfo()
	if err != nil {
		return "", fmt.Errorf("failed to parse classic dyld bind info: %v", err)
	}
	for _, bind := range binds {
		if (bind.Start + bind.SegOffset) == pointer {
			return bind.Name, nil
		}
	}
	return "", fmt.Errorf("pointer %#x is not a bind", pointer)
}

// ---------------------------------------------------------------- foldKey

func TestFoldKeyMatchesEqualFoldForEveryRune(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		s := string(r)
		key := foldKey(s)
		if !strings.EqualFold(s, key) {
			t.Fatalf("%U: key %q is not EqualFold to the rune", r, key)
		}
		for o := unicode.SimpleFold(r); o != r; o = unicode.SimpleFold(o) {
			if foldKey(string(o)) != key {
				t.Fatalf("%U and %U are in one fold orbit but have keys %q and %q", r, o, key, foldKey(string(o)))
			}
		}
	}
	// distinct orbits must have distinct keys: a key is a member of its own
	// orbit (checked above), so two orbits sharing a key would be one orbit.
}

var foldAlphabet = []string{
	"a", "A", "b", "B", "k", "K", "\u212a", "s", "S", "\u017f", "_", "1", "$", ".",
	"\u01c4", "\u01c5", "\u01c6", "\u00e9", "\u00c9", "\u03c3", "\u03c2", "\u03a3",
	"\xff", "\xc0", "\xe2\x82", "\ufffd", "\u4e2d", "\U0001f600", "\U00010400", "\U00010428",
}

func randomFoldString(rng *rand.Rand, maxLen int) string {
	var b strings.Builder
	for n := rng.Intn(maxLen + 1); n > 0; n-- {
		b.WriteString(foldAlphabet[rng.Intn(len(foldAlphabet))])
	}
	return b.String()
}

func TestFoldKeyMatchesEqualFoldOnStrings(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var pool []string
	for i := 0; i < 700; i++ {
		pool = append(pool, randomFoldString(rng, 3))
	}
	equal := 0
	for _, a := range pool {
		for _, b := range pool {
			want := strings.EqualFold(a, b)
			if got := foldKey(a) == foldKey(b); got != want {
				t.Fatalf("%q vs %q: EqualFold=%v, foldKey equality=%v", a, b, want, got)
			}
			if want && a != b {
				equal++
			}
		}
	}
	if equal == 0 {
		t.Fatal("test data contains no case-colliding pairs")
	}
}

func TestBuildAddrOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for iter := 0; iter < 200; iter++ {
		values := make([]uint64, rng.Intn(3000))
		mask := ^uint64(0) >> uint(rng.Intn(64))
		for i := range values {
			values[i] = rng.Uint64() & mask
			if rng.Intn(3) == 0 && i > 0 {
				values[i] = values[rng.Intn(i)]
			}
		}
		want := make([]int32, len(values))
		for i := range want {
			want[i] = int32(i)
		}
		sort.SliceStable(want, func(a, b int) bool { return values[want[a]] < values[want[b]] })
		got := buildAddrOrder(len(values), func(i int) uint64 { return values[i] })
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iter %d: radix order differs from a stable sort", iter)
		}
	}
}

// ---------------------------------------------------------------- fixtures

type trieEntry struct {
	name string
	addr uint64
}

func paddedUleb(x uint64, width int) []byte {
	out := make([]byte, width)
	for i := 0; i < width; i++ {
		out[i] = byte(x & 0x7f)
		x >>= 7
		if i != width-1 {
			out[i] |= 0x80
		}
	}
	return out
}

// buildTrie encodes entries (in order, duplicates and empty names allowed) as
// root -> groups of up to 200 -> leaves.
func buildTrie(entries []trieEntry) []byte {
	const group = 200
	var groups [][]trieEntry
	for i := 0; i < len(entries); i += group {
		groups = append(groups, entries[i:min(i+group, len(entries))])
	}
	if len(groups) > 255 {
		panic("too many entries")
	}
	const leafSize = 1 + 1 + 10 + 1 // terminalSize, flags, address, no children
	rootSize := 1 + 1 + len(groups)*(1+4)
	groupOff := make([]int, len(groups))
	off := rootSize
	for i, g := range groups {
		groupOff[i] = off
		off += 1 + 1
		for _, e := range g {
			off += len(e.name) + 1 + 4
		}
	}
	leafOff := off
	var out bytes.Buffer
	out.WriteByte(0)
	out.WriteByte(byte(len(groups)))
	for i := range groups {
		out.WriteByte(0) // empty edge
		out.Write(paddedUleb(uint64(groupOff[i]), 4))
	}
	leaf := 0
	for _, g := range groups {
		out.WriteByte(0)
		out.WriteByte(byte(len(g)))
		for _, e := range g {
			out.WriteString(e.name)
			out.WriteByte(0)
			out.Write(paddedUleb(uint64(leafOff+leaf*leafSize), 4))
			leaf++
		}
	}
	for _, e := range entries {
		out.WriteByte(11)
		out.WriteByte(0) // EXPORT_SYMBOL_FLAGS_KIND_REGULAR
		out.Write(paddedUleb(e.addr, 10))
		out.WriteByte(0)
	}
	return out.Bytes()
}

var symbolAlphabet = []string{"a", "A", "b", "B", "k", "K", "\u212a", "_", "s", "\u017f", "\xff", "\ufffd"}

func randomSymbolName(rng *rand.Rand) string {
	var b strings.Builder
	for n := rng.Intn(4); n > 0; n-- { // 0 => empty name
		b.WriteString(symbolAlphabet[rng.Intn(len(symbolAlphabet))])
	}
	return b.String()
}

func randomSyms(rng *rand.Rand, n int) []Symbol {
	syms := make([]Symbol, n)
	for i := range syms {
		syms[i] = Symbol{
			Name:  randomSymbolName(rng),
			Value: uint64(rng.Intn(n/3 + 2)), // plenty of duplicate addresses
			Type:  types.NType(rng.Intn(256)),
			Sect:  uint8(rng.Intn(4)),
			Desc:  types.NDescType(rng.Intn(16)),
		}
	}
	return syms
}

func randomTrieEntries(rng *rand.Rand, n int) []trieEntry {
	entries := make([]trieEntry, n)
	for i := range entries {
		name := randomSymbolName(rng)
		for strings.ContainsRune(name, 0) {
			name = randomSymbolName(rng)
		}
		entries[i] = trieEntry{name, uint64(rng.Intn(n/3 + 2))}
	}
	return entries
}

type exportLayout int

const (
	layoutNoExports exportLayout = iota
	layoutClassicOnly
	layoutClassic
	layoutModern
	layoutClassicAndModern
	layoutModernEmpty
	layoutClassicBroken
	layoutModernBroken
	layoutCount
)

// symFixture describes a hand-made File; build returns a fresh, independent
// File for it every time so the indexed and the reference lookups never share
// lazily-filled state.
type symFixture struct {
	syms    []Symbol
	noSyms  bool
	layout  exportLayout
	classic []byte
	modern  []byte
}

func (fx *symFixture) build() *File {
	data := append(append([]byte{}, fx.classic...), fx.modern...)
	f := &File{}
	f.cr = types.NewCustomSectionReader(bytes.NewReader(data), &types.VMAddrConverter{}, 0, 1<<63-1)
	f.sr = f.cr
	if !fx.noSyms {
		f.Symtab = &Symtab{Syms: fx.syms}
	}
	classicCmd := types.DyldInfoCmd{ExportOff: 0, ExportSize: uint32(len(fx.classic))}
	modernCmd := types.LinkEditDataCmd{Offset: uint32(len(fx.classic)), Size: uint32(len(fx.modern))}
	switch fx.layout {
	case layoutClassicOnly:
		f.Loads = append(f.Loads, &DyldInfoOnly{DyldInfo{DyldInfoCmd: classicCmd}})
	case layoutClassic:
		f.Loads = append(f.Loads, &DyldInfo{DyldInfoCmd: classicCmd})
	case layoutModern:
		f.Loads = append(f.Loads, &DyldExportsTrie{LinkEditData{LinkEditDataCmd: modernCmd}})
	case layoutClassicAndModern:
		f.Loads = append(f.Loads, &DyldInfoOnly{DyldInfo{DyldInfoCmd: classicCmd}},
			&DyldExportsTrie{LinkEditData{LinkEditDataCmd: modernCmd}})
	case layoutModernEmpty:
		modernCmd.Size = 0
		f.Loads = append(f.Loads, &DyldExportsTrie{LinkEditData{LinkEditDataCmd: modernCmd}})
	case layoutClassicBroken:
		classicCmd.ExportOff = uint32(len(data)) + 100
		classicCmd.ExportSize = 64
		f.Loads = append(f.Loads, &DyldInfoOnly{DyldInfo{DyldInfoCmd: classicCmd}})
	case layoutModernBroken:
		modernCmd.Offset = uint32(len(data)) + 100
		modernCmd.Size = 64
		f.Loads = append(f.Loads, &DyldExportsTrie{LinkEditData{LinkEditDataCmd: modernCmd}})
	}
	return f
}

func randomFixture(rng *rand.Rand, layout exportLayout) *symFixture {
	fx := &symFixture{layout: layout}
	switch rng.Intn(8) {
	case 0:
		fx.syms = nil
	case 1:
		fx.syms = randomSyms(rng, 1)
	default:
		fx.syms = randomSyms(rng, 1+rng.Intn(400))
	}
	fx.classic = buildTrie(randomTrieEntries(rng, rng.Intn(300)))
	fx.modern = buildTrie(randomTrieEntries(rng, rng.Intn(300)))
	return fx
}

func swapCase(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsUpper(r) {
			return unicode.ToLower(r)
		}
		return unicode.ToUpper(r)
	}, s)
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T:%v", err, err)
}

// ---------------------------------------------------------------- equivalence

// checkSymbolLookups compares the indexed lookups on got with the verbatim
// linear scans on want, for every name/address that can possibly matter.
func checkSymbolLookups(t *testing.T, rng *rand.Rand, label string, got, want *File, rounds int) {
	t.Helper()
	var names []string
	var addrs []uint64
	if got.Symtab != nil {
		for _, s := range got.Symtab.Syms {
			names = append(names, s.Name, swapCase(s.Name), strings.ToUpper(s.Name), strings.ToLower(s.Name))
			addrs = append(addrs, s.Value)
		}
	}
	if exports, err := want.GetExports(); err == nil {
		for _, e := range exports {
			names = append(names, e.Name, swapCase(e.Name))
			addrs = append(addrs, e.Address)
		}
	}
	names = append(names, "", "_missing", "\u212a", "k", "K", "\xff", "\ufffd")
	addrs = append(addrs, 0, 1, ^uint64(0))
	for i := 0; i < rounds; i++ {
		var name string
		if rng.Intn(4) == 0 {
			name = randomSymbolName(rng)
		} else {
			name = names[rng.Intn(len(names))]
		}
		gotAddr, gotErr := got.FindSymbolAddress(name)
		wantAddr, wantErr := want.findSymbolAddressLinear(name)
		if gotAddr != wantAddr || errString(gotErr) != errString(wantErr) {
			t.Fatalf("%s: FindSymbolAddress(%q) #%d = %#x, %s; linear scan = %#x, %s",
				label, name, i, gotAddr, errString(gotErr), wantAddr, errString(wantErr))
		}

		addr := addrs[rng.Intn(len(addrs))]
		gotSyms, gotErr := got.FindAddressSymbols(addr)
		wantSyms, wantErr := want.findAddressSymbolsLinear(addr)
		if !reflect.DeepEqual(gotSyms, wantSyms) || cap(gotSyms) != cap(wantSyms) || errString(gotErr) != errString(wantErr) {
			t.Fatalf("%s: FindAddressSymbols(%#x) #%d = %v, %s; linear scan = %v, %s",
				label, addr, i, gotSyms, errString(gotErr), wantSyms, errString(wantErr))
		}
	}
}

func TestSymbolIndexesMatchLinearScans(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 160; iter++ {
		layout := exportLayout(iter % int(layoutCount))
		fx := randomFixture(rng, layout)
		got, want := fx.build(), fx.build()
		label := fmt.Sprintf("iter %d layout %d", iter, layout)
		// well past lookupIndexThreshold: the first lookups are scans, the rest indexed
		checkSymbolLookups(t, rng, label, got, want, 2*lookupIndexThreshold+100)
		if len(fx.syms) > 0 && !(got.symIdx.symNames.built && got.symIdx.symAddrs.built) {
			t.Fatalf("%s: symbol indexes were never built", label)
		}

		// replace the symbol table: same length, different content
		fx.syms = randomSyms(rng, len(fx.syms))
		got.Symtab.Syms, want.Symtab.Syms = fx.syms, fx.syms
		checkSymbolLookups(t, rng, label+" new syms", got, want, 2*lookupIndexThreshold+40)

		// shrink it without moving it
		if n := len(fx.syms); n > 1 {
			got.Symtab.Syms, want.Symtab.Syms = fx.syms[:n/2], fx.syms[:n/2]
			checkSymbolLookups(t, rng, label+" shorter syms", got, want, 2*lookupIndexThreshold+40)
			got.Symtab.Syms, want.Symtab.Syms = fx.syms[1:], fx.syms[1:]
			checkSymbolLookups(t, rng, label+" shifted syms", got, want, 2*lookupIndexThreshold+40)
		}

		// replace the Symtab itself
		st := &Symtab{Syms: randomSyms(rng, 1+rng.Intn(50))}
		got.Symtab, want.Symtab = st, st
		checkSymbolLookups(t, rng, label+" new symtab", got, want, 2*lookupIndexThreshold+40)

		// change the load commands the exports come from (AddLoad / RemoveLoad)
		extra := &DyldExportsTrie{LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{
			Offset: uint32(len(fx.classic)), Size: uint32(len(fx.modern))}}}
		got.Loads, want.Loads = append(got.Loads, extra), append(want.Loads, extra)
		checkSymbolLookups(t, rng, label+" added load", got, want, 2*lookupIndexThreshold+40)
		got.Loads, want.Loads = got.Loads[:0:0], want.Loads[:0:0]
		checkSymbolLookups(t, rng, label+" no loads", got, want, 2*lookupIndexThreshold+40)
		got.Loads, want.Loads = []Load{extra}, []Load{extra}
		got.exp, want.exp = nil, nil
		extra.Size = 0 // in-place edit of a load command
		checkSymbolLookups(t, rng, label+" emptied load", got, want, 2*lookupIndexThreshold+40)

		// no symbol table at all
		got.Symtab, want.Symtab = nil, nil
		checkSymbolLookups(t, rng, label+" nil symtab", got, want, 4)
	}
}

// An element edited in place is outside what the indexes promise, but a hit is
// always verified against the live table, so it can never return a stale one.
func TestSymbolIndexHitsAreVerified(t *testing.T) {
	syms := []Symbol{{Name: "_a", Value: 1}, {Name: "_b", Value: 2}, {Name: "_c", Value: 3}}
	f := &File{Symtab: &Symtab{Syms: syms}}
	for i := 0; i <= lookupIndexThreshold; i++ {
		if v, err := f.FindSymbolAddress("_b"); v != 2 || err != nil {
			t.Fatalf("got %#x, %v", v, err)
		}
	}
	if !f.symIdx.symNames.built {
		t.Fatal("index not built")
	}
	syms[1].Name = "_z"
	syms[0].Value = 7
	for _, name := range []string{"_b", "_B", "_a", "_z", "_c"} {
		got, gotErr := f.FindSymbolAddress(name)
		want, wantErr := f.findSymbolAddressLinear(name)
		if got != want || errString(gotErr) != errString(wantErr) {
			t.Errorf("%q: got %#x, %v; want %#x, %v", name, got, gotErr, want, wantErr)
		}
	}
}

func bindFixture(rng *rand.Rand, n int) *File {
	f := &File{}
	f.Loads = []Load{&DyldInfoOnly{}}
	binds := make(types.Binds, n)
	for i := range binds {
		binds[i] = types.Bind{
			Name:      randomSymbolName(rng),
			Start:     uint64(0x1000 * rng.Intn(3)),
			SegOffset: uint64(8 * rng.Intn(n/2+1)),
		}
	}
	if n > 2 {
		// an address that only exists through wrap-around
		binds[n-1].Start, binds[n-1].SegOffset = ^uint64(0), 0x11
	}
	f.binds, f.bindsDone = binds, true
	return f
}

func TestGetBindNameMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 60; iter++ {
		f := bindFixture(rng, rng.Intn(300))
		check := func(label string) {
			for i := 0; i < 2*lookupIndexThreshold+100; i++ {
				ptr := uint64(0x1000*rng.Intn(4)) + uint64(8*rng.Intn(160))
				if i%7 == 0 {
					ptr = 0x10
				}
				got, gotErr := f.GetBindName(ptr)
				want, wantErr := f.getBindNameLinear(ptr)
				if got != want || errString(gotErr) != errString(wantErr) {
					t.Fatalf("iter %d %s: GetBindName(%#x) = %q, %s; linear scan = %q, %s",
						iter, label, ptr, got, errString(gotErr), want, errString(wantErr))
				}
			}
		}
		check("initial")
		if !f.bindNameIdx.built {
			t.Fatalf("iter %d: bind index was never built", iter)
		}
		f.ResetFixupsCache()
		if f.bindNameIdx.built || f.symIdx.symNames.built {
			t.Fatalf("iter %d: ResetFixupsCache kept a lookup index", iter)
		}
		f.binds, f.bindsDone = bindFixture(rng, 1+rng.Intn(100)).binds, true
		check("after reset")
		f.fixupsMu.Lock()
		f.binds = bindFixture(rng, len(f.binds)).binds // replaced behind the index's back
		f.fixupsMu.Unlock()
		check("replaced")
	}
}

func TestSymbolIndexesConcurrentLookups(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	fx := randomFixture(rng, layoutClassicOnly) // GetExports only ReadAt()s here
	fx.syms = randomSyms(rng, 500)
	f, ref := fx.build(), fx.build()
	bf := bindFixture(rng, 200)
	type query struct {
		name string
		addr uint64
	}
	queries := make([]query, 400)
	for i := range queries {
		s := fx.syms[rng.Intn(len(fx.syms))]
		queries[i] = query{s.Name, s.Value}
		if i%3 == 0 {
			queries[i].name = swapCase(s.Name)
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, q := range queries {
				f.FindSymbolAddress(q.name)
				f.FindAddressSymbols(q.addr)
				bf.GetBindName(q.addr * 8)
			}
		}()
	}
	wg.Wait()
	for _, q := range queries {
		got, gotErr := f.FindSymbolAddress(q.name)
		want, wantErr := ref.findSymbolAddressLinear(q.name)
		if got != want || errString(gotErr) != errString(wantErr) {
			t.Fatalf("%q: got %#x, %v; want %#x, %v", q.name, got, gotErr, want, wantErr)
		}
	}
}

// ---------------------------------------------------------------- benchmarks

func benchFixture(n int) (*symFixture, []string) {
	rng := rand.New(rand.NewSource(11))
	fx := &symFixture{layout: layoutClassicOnly}
	fx.syms = make([]Symbol, n)
	names := make([]string, n)
	for i := range fx.syms {
		names[i] = fmt.Sprintf("_$s%dModule%dTypeV%dmethodyyF", i%97, i, rng.Intn(1000))
		fx.syms[i] = Symbol{Name: names[i], Value: 0x100000000 + uint64(rng.Intn(n/2))*4}
	}
	entries := make([]trieEntry, n/10)
	for i := range entries {
		entries[i] = trieEntry{fmt.Sprintf("_export%d", i), uint64(i) * 8}
	}
	fx.classic = buildTrie(entries)
	return fx, names
}

func BenchmarkFindSymbolAddress(b *testing.B) {
	const n = 100000
	fx, names := benchFixture(n)
	run := func(b *testing.B, find func(*File, string) (uint64, error), name func(i int) string) {
		f := fx.build()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			find(f, name(i))
		}
	}
	hit := func(i int) string { return names[(i*7919)%n] }
	export := func(i int) string { return fmt.Sprintf("_export%d", (i*7919)%(n/10)) }
	miss := func(i int) string { return "_not_there" }
	b.Run("hit/linear", func(b *testing.B) { run(b, (*File).findSymbolAddressLinear, hit) })
	b.Run("hit/indexed", func(b *testing.B) { run(b, (*File).FindSymbolAddress, hit) })
	b.Run("export/linear", func(b *testing.B) { run(b, (*File).findSymbolAddressLinear, export) })
	b.Run("export/indexed", func(b *testing.B) { run(b, (*File).FindSymbolAddress, export) })
	b.Run("miss/linear", func(b *testing.B) { run(b, (*File).findSymbolAddressLinear, miss) })
	b.Run("miss/indexed", func(b *testing.B) { run(b, (*File).FindSymbolAddress, miss) })
}

func BenchmarkFindAddressSymbols(b *testing.B) {
	const n = 100000
	fx, _ := benchFixture(n)
	run := func(b *testing.B, find func(*File, uint64) ([]Symbol, error)) {
		f := fx.build()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			find(f, fx.syms[(i*7919)%n].Value)
		}
	}
	b.Run("linear", func(b *testing.B) { run(b, (*File).findAddressSymbolsLinear) })
	b.Run("indexed", func(b *testing.B) { run(b, (*File).FindAddressSymbols) })
}

func BenchmarkGetBindName(b *testing.B) {
	const n = 50000
	f := &File{Loads: []Load{&DyldInfoOnly{}}}
	binds := make(types.Binds, n)
	for i := range binds {
		binds[i] = types.Bind{Name: fmt.Sprintf("_import%d", i), Start: 0x100008000, SegOffset: uint64(i) * 8}
	}
	f.binds, f.bindsDone = binds, true
	b.Run("linear", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			f.getBindNameLinear(0x100008000 + uint64((i*7919)%n)*8)
		}
	})
	b.Run("indexed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			f.GetBindName(0x100008000 + uint64((i*7919)%n)*8)
		}
	})
}

// BenchmarkSymbolIndexBuild is the one-off cost the lookup threshold amortises.
func BenchmarkSymbolIndexBuild(b *testing.B) {
	fx, _ := benchFixture(100000)
	b.Run("names", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buildNameIndex(len(fx.syms), func(i int) string { return fx.syms[i].Name })
		}
	})
	b.Run("addrs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buildAddrOrder(len(fx.syms), func(i int) uint64 { return fx.syms[i].Value })
		}
	})
}
