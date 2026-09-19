package macho

import (
	"io"

	"github.com/zdypro888/go-macho/types"
	"github.com/zdypro888/go-macho/types/swift"
)

// swiftContextMemo remembers the context descriptors getContextDesc resolved
// during one public Swift parsing call. Every type, protocol and conformance
// of a module asks for the same few parent contexts, and each request used to
// re-read the whole parent chain.
//
// getContextDescUncached stays the definition of the result. The memo only
// replays it, under conditions in which a replay is indistinguishable:
//
//   - It lives only while a parsing call is open (see swiftContextScope);
//     with concurrent callers, until the last of them closes its scope.
//     Everything the result depends on besides the file bytes - Symtab, load
//     commands, fixup caches, shared-cache bases - can be changed by the
//     caller between calls, never during one (File's documented contract).
//   - Only top-level requests are remembered and answered, never the parents
//     looked up along the way: the cycle and depth errors depend on the chain
//     of children a lookup came through.
//   - Only successes are remembered. A failing lookup runs again in full, so
//     every entry point into a parent cycle still reports its own error.
//   - getContextDesc leaves the caller's cursor wherever its last descriptor
//     read ended, and callers that ignore a failed SeekToAddr go on reading
//     from there. A replay therefore restores that position too. That is only
//     possible for the library's own reader, and only meaningful when the
//     lookup moved the reader to a position of its own choosing (pos != the
//     position it started from); other lookups are not remembered. The
//     position a lookup ends at does not depend on where it started, so an
//     entry recorded through one cursor replays correctly on any other.
//   - No caller-supplied code may run inside the lookup: no PointerResolver and
//     no custom VMAddrConverter.
//   - A fresh copy is returned every time, as before.
type swiftContextMemo struct {
	depth   int
	entries map[uint64]swiftContextMemoEntry
}

type swiftContextMemoEntry struct {
	ctx swift.TargetModuleContext
	pos int64 // cursor position after the lookup
}

// swiftContextScope opens a parsing call that may share context descriptor
// lookups; the returned function closes it. Scopes nest; the memo is dropped
// when the outermost one closes.
func (f *File) swiftContextScope() (end func()) {
	f.swiftCtxMu.Lock()
	f.swiftCtx.depth++
	f.swiftCtxMu.Unlock()
	return func() {
		f.swiftCtxMu.Lock()
		if f.swiftCtx.depth--; f.swiftCtx.depth == 0 {
			f.swiftCtx.entries = nil
		}
		f.swiftCtxMu.Unlock()
	}
}

// swiftContextMemoUsable reports whether lookups through cr may be
// remembered: cr must be the library's own reader, whose Seek positions a
// replay can restore, and no caller code may run inside the lookup.
func (f *File) swiftContextMemoUsable(cr types.MachoReader) bool {
	if f.pointerResolver != nil || f.customVMAddrConverter {
		return false
	}
	_, ok := cr.(*types.CustomSectionReader)
	return ok
}

// getContextDesc resolves the context descriptor at addr through cr, the
// calling public method's cursor (see File.newReader). The memo is shared by
// every scope open on the File, including scopes of concurrent calls: an
// entry only depends on the file bytes and the position it leaves cr at, and
// both are the same for every cursor.
func (f *File) getContextDesc(cr types.MachoReader, addr uint64) (*swift.TargetModuleContext, error) {
	if !f.swiftContextMemoUsable(cr) {
		return f.getContextDescUncached(cr, addr)
	}
	f.swiftCtxMu.Lock()
	active := f.swiftCtx.depth > 0
	entry, hit := f.swiftCtx.entries[addr]
	f.swiftCtxMu.Unlock()
	if !active {
		return f.getContextDescUncached(cr, addr)
	}
	if hit {
		if _, err := cr.Seek(entry.pos, io.SeekStart); err == nil {
			ctx := entry.ctx
			return &ctx, nil
		}
		return f.getContextDescUncached(cr, addr)
	}

	before, errBefore := cr.Seek(0, io.SeekCurrent)
	ctx, err := f.getContextDescUncached(cr, addr)
	if err != nil || ctx == nil || errBefore != nil {
		return ctx, err
	}
	after, errAfter := cr.Seek(0, io.SeekCurrent)
	if errAfter != nil || after == before {
		return ctx, err
	}
	f.swiftCtxMu.Lock()
	if f.swiftCtx.depth > 0 {
		if f.swiftCtx.entries == nil {
			f.swiftCtx.entries = make(map[uint64]swiftContextMemoEntry)
		}
		f.swiftCtx.entries[addr] = swiftContextMemoEntry{ctx: *ctx, pos: after}
	}
	f.swiftCtxMu.Unlock()
	return ctx, nil
}
