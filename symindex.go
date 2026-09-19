package macho

import (
	"math"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/zdypro888/go-macho/pkg/trie"
	"github.com/zdypro888/go-macho/types"
)

// Lookup indexes for FindSymbolAddress, FindAddressSymbols and GetBindName.
//
// They are pure accelerators: every lookup returns exactly what the linear
// scans in symindex_ref.go return. The rules that keep them honest:
//
//   - An index is tied to the identity of the slice it was built from (address
//     of the first element + length). f.Symtab, f.Symtab.Syms, the export list
//     and the bind list can all be replaced at any time (Export, AddLoad,
//     RemoveLoad, tests that assemble a File by hand); a replaced slice never
//     matches the recorded identity, so the index is rebuilt instead of reused.
//     The index keeps a pointer into the old backing array, so that address
//     cannot be recycled for a different slice while the index is alive.
//   - A hit is re-checked against the live element before it is returned. If
//     somebody edited an element in place the check fails, the indexes are
//     dropped and the linear reference scan answers instead.
//   - Building an index costs as much as a number of linear scans of the same
//     table (roughly 8 for names, 25 for addresses, 60 for binds; see
//     BenchmarkSymbolIndexBuild), so that many lookups against a table are
//     plain scans first: one-off callers never pay for an index, and nobody
//     pays more than about twice the scans they replaced.
//   - Index state is guarded by symIndexMu (a leaf lock: nothing is called while
//     it is held) or, for binds, by the fixupsMu that already guards f.binds.
//     Published indexes are immutable.
const (
	nameIndexAfterLookups = 8
	addrIndexAfterLookups = 32
	bindIndexAfterLookups = 64

	// lookupIndexThreshold is the largest of the above: after that many
	// lookups against one table every index is in use.
	lookupIndexThreshold = bindIndexAfterLookups
)

// sliceID identifies a slice by backing array position and length.
type sliceID[T any] struct {
	first *T
	n     int
}

func idOf[T any](s []T) sliceID[T] {
	if len(s) == 0 {
		// every empty slice has the same (empty) content
		return sliceID[T]{}
	}
	return sliceID[T]{first: &s[0], n: len(s)}
}

// nameIndex maps a name to the FIRST position that carries it, exactly
// (exact) and under strings.EqualFold (fold, keyed by foldKey). The fold map
// is only needed when there is no exact match anywhere, so it is built on
// first use.
type nameIndex struct {
	n     int
	name  func(i int) string
	exact map[string]int32

	foldOnce sync.Once
	fold     map[string]int32
}

func buildNameIndex(n int, name func(i int) string) *nameIndex {
	ix := &nameIndex{n: n, name: name, exact: make(map[string]int32, n)}
	for i := 0; i < n; i++ {
		s := name(i)
		if _, ok := ix.exact[s]; !ok {
			ix.exact[s] = int32(i)
		}
	}
	return ix
}

// foldFirst returns the first position whose name is EqualFold to symbol.
func (ix *nameIndex) foldFirst(symbol string) (int, bool) {
	ix.foldOnce.Do(func() {
		fold := make(map[string]int32, len(ix.exact))
		for i := 0; i < ix.n; i++ {
			k := foldKey(ix.name(i))
			if _, ok := fold[k]; !ok {
				fold[k] = int32(i)
			}
		}
		ix.fold = fold
	})
	i, ok := ix.fold[foldKey(symbol)]
	return int(i), ok
}

// foldKey returns a canonical form such that
//
//	foldKey(a) == foldKey(b)  <=>  strings.EqualFold(a, b)
//
// EqualFold compares rune by rune (invalid UTF-8 decodes to U+FFFD, one byte at
// a time) and treats two runes as equal when they are in the same
// unicode.SimpleFold orbit. The key therefore replaces every rune by the
// smallest member of its orbit. For ASCII that is the upper-case letter.
func foldKey(s string) string {
	hasLower := false
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			break
		}
		if 'a' <= c && c <= 'z' {
			hasLower = true
		}
	}
	if i == len(s) {
		if !hasLower {
			return s
		}
		b := []byte(s)
		for j, c := range b {
			if 'a' <= c && c <= 'z' {
				b[j] = c - ('a' - 'A')
			}
		}
		return string(b)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(minFoldRune(r))
	}
	return b.String()
}

func minFoldRune(r rune) rune {
	m := r
	for c := unicode.SimpleFold(r); c != r; c = unicode.SimpleFold(c) {
		if c < m {
			m = c
		}
	}
	return m
}

// buildAddrOrder returns the positions 0..n-1 ordered by (value, position), so
// the positions sharing one value are contiguous and in their original order.
// It is a byte-wise LSD radix sort: stable, so ties keep their position order,
// and several times cheaper than a comparison sort on a large symbol table.
func buildAddrOrder(n int, value func(i int) uint64) []int32 {
	keys, keysTmp := make([]uint64, n), make([]uint64, n)
	order, orderTmp := make([]int32, n), make([]int32, n)
	for i := range order {
		keys[i], order[i] = value(i), int32(i)
	}
	for shift := uint(0); n > 1 && shift < 64; shift += 8 {
		var count [256]int
		for _, k := range keys {
			count[byte(k>>shift)]++
		}
		if count[byte(keys[0]>>shift)] == n {
			continue // every key has the same byte here
		}
		sum := 0
		for b, c := range count {
			count[b], sum = sum, sum+c
		}
		for i, k := range keys {
			b := byte(k >> shift)
			keysTmp[count[b]], orderTmp[count[b]] = k, order[i]
			count[b]++
		}
		keys, keysTmp, order, orderTmp = keysTmp, keys, orderTmp, order
	}
	return order
}

// lazyIndex counts lookups against one slice identity and builds the index
// after the given number of them.
type lazyIndex[T any, I any] struct {
	id      sliceID[T]
	lookups int
	built   bool
	index   I
}

// get must be called with the guarding lock held.
func (l *lazyIndex[T, I]) get(s []T, after int, build func() I) (index I, ok bool) {
	if len(s) > math.MaxInt32 {
		return index, false
	}
	if id := idOf(s); l.id != id {
		*l = lazyIndex[T, I]{id: id}
	}
	if !l.built {
		if l.lookups < after {
			l.lookups++
			return index, false
		}
		l.index = build()
		l.built = true
	}
	return l.index, true
}

// exportsSource is everything GetExports derives its result from, besides the
// (immutable) file contents.
type exportsSource struct {
	dyldInfo          *DyldInfo
	dyldInfoOff       uint32
	dyldInfoSize      uint32
	dyldInfoOnly      *DyldInfoOnly
	dyldInfoOnlyOff   uint32
	dyldInfoOnlySize  uint32
	exportsTrie       *DyldExportsTrie
	exportsTrieOff    uint32
	exportsTrieSize   uint32
	parsedExportsTrie sliceID[trie.TrieExport] // f.exp, which DyldExports prefers over the file
	base              uint64
	initialized       bool
}

func (f *File) exportsSource() exportsSource {
	src := exportsSource{
		parsedExportsTrie: idOf(f.parsedDyldExports()),
		base:              f.GetBaseAddress(),
		initialized:       true,
	}
	if d := f.DyldInfo(); d != nil {
		src.dyldInfo, src.dyldInfoOff, src.dyldInfoSize = d, d.ExportOff, d.ExportSize
	}
	if d := f.DyldInfoOnly(); d != nil {
		src.dyldInfoOnly, src.dyldInfoOnlyOff, src.dyldInfoOnlySize = d, d.ExportOff, d.ExportSize
	}
	if d := f.DyldExportsTrie(); d != nil {
		src.exportsTrie, src.exportsTrieOff, src.exportsTrieSize = d, d.Offset, d.Size
	}
	return src
}

// symbolIndexes is the File's lookup-index state.
type symbolIndexes struct {
	symNames lazyIndex[Symbol, *nameIndex]
	symAddrs lazyIndex[Symbol, []int32]

	// exports is a private copy of a successful GetExports result; it is never
	// handed out, so it cannot be modified behind the index's back.
	exportsSrc   exportsSource
	exports      []trie.TrieExport
	exportNames  lazyIndex[trie.TrieExport, *nameIndex]
	dyldExpAddrs lazyIndex[trie.TrieExport, []int32]
}

// resetSymbolIndexes drops every symbol lookup index.
func (f *File) resetSymbolIndexes() {
	f.symIndexMu.Lock()
	f.symIdx = symbolIndexes{}
	f.symIndexMu.Unlock()
}

func (f *File) symtabNameIndex(syms []Symbol) (*nameIndex, bool) {
	f.symIndexMu.Lock()
	defer f.symIndexMu.Unlock()
	return f.symIdx.symNames.get(syms, nameIndexAfterLookups, func() *nameIndex {
		return buildNameIndex(len(syms), func(i int) string { return syms[i].Name })
	})
}

func (f *File) symtabAddrIndex(syms []Symbol) ([]int32, bool) {
	f.symIndexMu.Lock()
	defer f.symIndexMu.Unlock()
	return f.symIdx.symAddrs.get(syms, addrIndexAfterLookups, func() []int32 {
		return buildAddrOrder(len(syms), func(i int) uint64 { return syms[i].Value })
	})
}

func (f *File) dyldExportsAddrIndex(exports []trie.TrieExport) ([]int32, bool) {
	f.symIndexMu.Lock()
	defer f.symIndexMu.Unlock()
	return f.symIdx.dyldExpAddrs.get(exports, addrIndexAfterLookups, func() []int32 {
		return buildAddrOrder(len(exports), func(i int) uint64 { return exports[i].Address })
	})
}

// cachedExports is GetExports without re-reading and re-parsing the export
// tries on every call. Only successful results are kept: a failing GetExports
// is simply called again, so its errors (and its side effects) are those of
// the uncached code. The returned slice must not be modified or handed out.
func (f *File) cachedExports() ([]trie.TrieExport, error) {
	src := f.exportsSource()
	f.symIndexMu.Lock()
	if f.symIdx.exportsSrc.initialized && f.symIdx.exportsSrc == src {
		exports := f.symIdx.exports
		f.symIndexMu.Unlock()
		return exports, nil
	}
	f.symIndexMu.Unlock()

	exports, err := f.GetExports()
	if err != nil {
		return nil, err
	}
	// GetExports may just have parsed LC_DYLD_EXPORTS_TRIE into f.exp; the
	// result is the one every later call in that state produces too.
	src = f.exportsSource()
	f.symIndexMu.Lock()
	f.symIdx.exportsSrc = src
	f.symIdx.exports = exports
	f.symIdx.exportNames = lazyIndex[trie.TrieExport, *nameIndex]{}
	f.symIndexMu.Unlock()
	return exports, nil
}

func (f *File) exportsNameIndex(exports []trie.TrieExport) (*nameIndex, bool) {
	f.symIndexMu.Lock()
	defer f.symIndexMu.Unlock()
	return f.symIdx.exportNames.get(exports, nameIndexAfterLookups, func() *nameIndex {
		return buildNameIndex(len(exports), func(i int) string { return exports[i].Name })
	})
}

// valueRange returns the sub-slice of order whose positions carry value.
func valueRange(order []int32, value func(i int) uint64, addr uint64) []int32 {
	lo := sort.Search(len(order), func(j int) bool { return value(int(order[j])) >= addr })
	hi := lo
	for hi < len(order) && value(int(order[hi])) == addr {
		hi++
	}
	return order[lo:hi]
}

// bindNameIndex maps a bind's slot address (Start+SegOffset) to the FIRST bind
// at that address. Guarded by fixupsMu, like the f.binds it is built from.
type bindNameIndex = lazyIndex[types.Bind, map[uint64]int32]

// bindAtLocked returns the first bind whose slot address is pointer. It must be
// called with fixupsMu held.
func (f *File) bindAtLocked(binds types.Binds, pointer uint64) (string, bool) {
	index, ok := f.bindNameIdx.get(binds, bindIndexAfterLookups, func() map[uint64]int32 {
		m := make(map[uint64]int32, len(binds))
		for i := range binds {
			addr := binds[i].Start + binds[i].SegOffset
			if _, ok := m[addr]; !ok {
				m[addr] = int32(i)
			}
		}
		return m
	})
	if ok {
		if i, ok := index[pointer]; ok {
			if b := &binds[i]; b.Start+b.SegOffset == pointer {
				return b.Name, true
			}
			// edited in place: forget the index and scan
			f.bindNameIdx = bindNameIndex{}
		} else {
			return "", false
		}
	}
	for i := range binds {
		if binds[i].Start+binds[i].SegOffset == pointer {
			return binds[i].Name, true
		}
	}
	return "", false
}
