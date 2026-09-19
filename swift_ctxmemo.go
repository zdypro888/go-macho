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
//   - It lives for the duration of the outermost parsing call only (see
//     swiftContextScope). Everything the result depends on besides the file
//     bytes - Symtab, load commands, fixup caches, shared-cache bases - can be
//     changed by the caller between calls, never during one.
//   - Only top-level requests are remembered and answered, never the parents
//     looked up along the way: the cycle and depth errors depend on the chain
//     of children a lookup came through.
//   - Only successes are remembered. A failing lookup runs again in full, so
//     every entry point into a parent cycle still reports its own error.
//   - getContextDesc leaves the shared reader f.cr wherever its last descriptor
//     read ended, and callers that ignore a failed SeekToAddr go on reading
//     from there. A replay therefore restores that position too. That is only
//     possible for the library's own reader, and only meaningful when the
//     lookup moved the reader to a position of its own choosing (pos != the
//     position it started from); other lookups are not remembered.
//   - No caller-supplied code may run inside the lookup: no PointerResolver and
//     no custom VMAddrConverter.
//   - A fresh copy is returned every time, as before.
type swiftContextMemo struct {
	depth   int
	entries map[uint64]swiftContextMemoEntry
}

type swiftContextMemoEntry struct {
	ctx swift.TargetModuleContext
	pos int64 // f.cr position after the lookup
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

// swiftContextMemoReader returns the reader whose position a replay has to
// restore, or false when lookups must not be remembered.
func (f *File) swiftContextMemoReader() (*types.CustomSectionReader, bool) {
	if f.pointerResolver != nil || f.customVMAddrConverter {
		return nil, false
	}
	cr, ok := f.cr.(*types.CustomSectionReader)
	return cr, ok
}

func (f *File) getContextDesc(addr uint64) (*swift.TargetModuleContext, error) {
	cr, ok := f.swiftContextMemoReader()
	if !ok {
		return f.getContextDescUncached(addr)
	}
	f.swiftCtxMu.Lock()
	active := f.swiftCtx.depth > 0
	entry, hit := f.swiftCtx.entries[addr]
	f.swiftCtxMu.Unlock()
	if !active {
		return f.getContextDescUncached(addr)
	}
	if hit {
		if _, err := cr.Seek(entry.pos, io.SeekStart); err == nil {
			ctx := entry.ctx
			return &ctx, nil
		}
		return f.getContextDescUncached(addr)
	}

	before, errBefore := cr.Seek(0, io.SeekCurrent)
	ctx, err := f.getContextDescUncached(addr)
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
