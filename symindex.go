package macho

import (
	"math"
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
//   - Name snapshots are checked against every live name before reuse. Address
//     orders are checked before binary search. Hit-only checks cannot detect an
//     earlier duplicate or a new match. Public in-place edits require O(n)
//     validation; there is no writer-controlled generation counter here.
//   - Only names are indexed. Address and bind lookups are plain scans: with
//     tables that callers may edit in place, validating an index costs more
//     than scanning.
//   - Building an index costs as much as about 8 linear scans of the same
//     table (see BenchmarkSymbolIndexBuild), so that many lookups against a table are
//     plain scans first: one-off callers never pay for an index, and nobody
//     pays more than about twice the scans they replaced.
//   - Index state is guarded by symIndexMu (a leaf lock: nothing is called while
//     it is held) or, for binds, by the fixupsMu that already guards f.binds.
//     Published indexes are immutable.
const (
	nameIndexAfterLookups = 8

	// lookupIndexThreshold: after that many lookups against one table every
	// index is in use.
	lookupIndexThreshold = nameIndexAfterLookups
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
	names []string // immutable snapshot: callers may edit exported symbols in place
	exact map[string]int32

	foldOnce sync.Once
	fold     map[string]int32
}

func buildNameIndex(n int, name func(i int) string) *nameIndex {
	ix := &nameIndex{n: n, name: name, names: make([]string, n), exact: make(map[string]int32, n)}
	for i := 0; i < n; i++ {
		s := name(i)
		ix.names[i] = s
		if _, ok := ix.exact[s]; !ok {
			ix.exact[s] = int32(i)
		}
	}
	return ix
}

// A hit-only check misses renamed symbols and earlier duplicates. With public
// mutable slices, exact invalidation requires checking every indexed name.
func (ix *nameIndex) matchesNames() bool {
	for i, name := range ix.names {
		if ix.name(i) != name {
			return false
		}
	}
	return true
}

// foldFirst returns the first position whose name is EqualFold to symbol.
func (ix *nameIndex) foldFirst(symbol string) (int, bool) {
	ix.foldOnce.Do(func() {
		fold := make(map[string]int32, len(ix.exact))
		for i := 0; i < ix.n; i++ {
			k := foldKey(ix.names[i])
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

	// exports is a private copy of a successful GetExports result; it is never
	// handed out, so it cannot be modified behind the index's back.
	exportsSrc  exportsSource
	exports     []trie.TrieExport
	exportNames lazyIndex[trie.TrieExport, *nameIndex]
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
	ix, ok := f.symIdx.symNames.get(syms, nameIndexAfterLookups, func() *nameIndex {
		return buildNameIndex(len(syms), func(i int) string { return syms[i].Name })
	})
	if ok && !ix.matchesNames() {
		f.symIdx.symNames = lazyIndex[Symbol, *nameIndex]{}
		return nil, false
	}
	return ix, ok
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
	ix, ok := f.symIdx.exportNames.get(exports, nameIndexAfterLookups, func() *nameIndex {
		return buildNameIndex(len(exports), func(i int) string { return exports[i].Name })
	})
	if ok && !ix.matchesNames() {
		f.symIdx.exportNames = lazyIndex[trie.TrieExport, *nameIndex]{}
		return nil, false
	}
	return ix, ok
}

// bindAtLocked returns the first bind whose slot address is pointer. It must be
// called with fixupsMu held. The bind table returned by GetBindInfo is public
// and may be edited in place, so an index would have to be validated against
// every entry per call, which is slower than this scan (measured 63 us vs 34 us).
func (f *File) bindAtLocked(binds types.Binds, pointer uint64) (string, bool) {
	for i := range binds {
		if binds[i].Start+binds[i].SegOffset == pointer {
			return binds[i].Name, true
		}
	}
	return "", false
}
