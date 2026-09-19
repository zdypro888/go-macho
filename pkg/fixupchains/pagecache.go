package fixupchains

import (
	"io"
	"math"
	"slices"
	"sort"
)

// chainPage is the immutable result of walking every chain of one page once.
//
// GetFixupAtOffset used to re-walk the page's chain from its start, with one
// ReadAt per link, for every single lookup. A page is instead read and walked
// once and the (offset, raw pointer) pairs are kept, so later lookups in the
// same page are a binary search followed by the usual decode.
//
// The walk visits links in exactly the order of the original link-by-link
// walker and stops at the first anomaly - a short read, a location outside the
// segment, an unsupported format, an implausible number of links. Links seen
// before that point are what the original walker also reaches successfully, so
// they are served from here. Everything else about such a page (!complete),
// i.e. every error value and all malformed input, is left to the original
// walker, which therefore remains the single source of truth for errors.
type chainPage struct {
	// Inputs the walk depends on. Starts is an exported, caller-mutable field,
	// so an entry is only reused while these still match.
	format      DCPtrKind
	pageSize    uint16
	pageCount   uint16
	segOffset   uint64
	pageStart   DCPtrStart
	chainStarts []DCPtrStart // only for DYLD_CHAINED_PTR_START_MULTI pages

	complete bool     // the whole page was walked without any anomaly
	offsets  []uint32 // offsets in page, ascending and unique
	raws     []uint64 // raw pointer bits, parallel to offsets
}

func (p *chainPage) matches(start *DyldChainedStarts, pageStart DCPtrStart, chainStarts []DCPtrStart) bool {
	return p.format == start.PointerFormat &&
		p.pageSize == start.PageSize &&
		p.pageCount == start.PageCount &&
		p.segOffset == start.SegmentOffset &&
		p.pageStart == pageStart &&
		slices.Equal(p.chainStarts, chainStarts)
}

// cachedFixupInPage answers GetFixupAtOffset for one page from the page cache.
// handled is false when the page cannot be served from the cache; the caller
// must then run the original walker.
func (dcf *DyldChainedFixups) cachedFixupInPage(start *DyldChainedStarts, pageStart DCPtrStart, pageContentStart, offsetInPage uint64) (fixup Fixup, err error, handled bool) {
	if dcf.sr == nil || dcf.disablePageCache {
		return nil, nil, false
	}

	var multi []DCPtrStart
	if pageStart&DYLD_CHAINED_PTR_START_MULTI != 0 {
		// Rare (32-bit formats only); errors are reported by the original path.
		if multi, err = chainStartsForPage(start, pageStart); err != nil {
			return nil, nil, false
		}
	} else if uint64(pageStart) > uint64(start.PageSize) {
		return nil, nil, false
	}

	dcf.pageCacheMu.RLock()
	page := dcf.pageCache[pageContentStart]
	dcf.pageCacheMu.RUnlock()

	if page == nil || !page.matches(start, pageStart, multi) {
		// Built without holding the lock: concurrent builders of the same page
		// produce identical immutable values, so the last store simply wins.
		page = dcf.buildChainPage(start, pageStart, multi, pageContentStart)
		dcf.pageCacheMu.Lock()
		if dcf.pageCache == nil {
			dcf.pageCache = make(map[uint64]*chainPage)
		}
		dcf.pageCache[pageContentStart] = page
		dcf.pageCacheMu.Unlock()
	}

	i := sort.Search(len(page.offsets), func(i int) bool { return uint64(page.offsets[i]) >= offsetInPage })
	if i == len(page.offsets) || uint64(page.offsets[i]) != offsetInPage {
		// Not a link: only a completely walked page proves there is no fixup;
		// otherwise the original walker reports the page's error.
		return nil, ErrNoFixupAtOffset, page.complete
	}
	fixup, err = dcf.decodeFixup(start.PointerFormat, page.raws[i], pageContentStart+offsetInPage)
	return fixup, err, true
}

func (dcf *DyldChainedFixups) buildChainPage(start *DyldChainedStarts, pageStart DCPtrStart, multi []DCPtrStart, pageContentStart uint64) *chainPage {
	page := &chainPage{
		format:      start.PointerFormat,
		pageSize:    start.PageSize,
		pageCount:   start.PageCount,
		segOffset:   start.SegmentOffset,
		pageStart:   pageStart,
		chainStarts: slices.Clone(multi),
	}

	ptrSize := uint64(pointerSize(page.format))
	strideVal, strideOK := stride(page.format)
	pageSize := uint64(page.pageSize)
	if (ptrSize != 4 && ptrSize != 8) || !strideOK || strideVal == 0 || pageSize == 0 {
		return page
	}
	// A chain link may start anywhere in [0, pageSize], so the last pointer can
	// extend up to ptrSize bytes beyond the page.
	span := pageSize + ptrSize
	if pageContentStart > math.MaxInt64-span {
		return page
	}
	buf := make([]byte, span)
	n, err := dcf.sr.ReadAt(buf, int64(pageContentStart))
	if err != nil && err != io.EOF {
		return page
	}
	avail := uint64(n)

	// Links of well-formed chains are distinct stride-aligned locations.
	maxLinks := pageSize/strideVal + 2

	chainStarts := multi
	if chainStarts == nil {
		chainStarts = []DCPtrStart{pageStart}
	}
	offsets := make([]uint32, 0, 64)
	raws := make([]uint64, 0, 64)
	complete := true
walk:
	for _, chainStart := range chainStarts {
		cur := uint64(chainStart)
		for {
			if _, err := checkedChainFixupLocation(start, pageContentStart, cur); err != nil {
				complete = false
				break walk
			}
			if cur+ptrSize > avail || uint64(len(offsets)) >= maxLinks {
				complete = false
				break walk
			}
			var raw uint64
			if ptrSize == 4 {
				raw = uint64(dcf.bo.Uint32(buf[cur : cur+4]))
			} else {
				raw = dcf.bo.Uint64(buf[cur : cur+8])
			}
			offsets = append(offsets, uint32(cur))
			raws = append(raws, raw)

			next, ok := chainNext(page.format, raw)
			if !ok {
				complete = false
				break walk
			}
			if next == 0 {
				break
			}
			step := next * strideVal
			if cur > ^uint64(0)-step {
				complete = false
				break walk
			}
			cur += step
			if cur > pageSize {
				break
			}
		}
	}

	// A single chain only moves forward; several chains may interleave or overlap.
	if len(chainStarts) > 1 && !strictlyIncreasing(offsets) {
		offsets, raws = sortChainLinks(offsets, raws)
	}
	page.offsets = slices.Clip(offsets)
	page.raws = slices.Clip(raws)
	page.complete = complete
	return page
}

func strictlyIncreasing(offsets []uint32) bool {
	for i := 1; i < len(offsets); i++ {
		if offsets[i] <= offsets[i-1] {
			return false
		}
	}
	return true
}

// sortChainLinks orders the links of overlapping multi-start chains by offset
// and drops repeated locations. A location always holds the same bytes, so
// which duplicate survives is irrelevant.
func sortChainLinks(offsets []uint32, raws []uint64) ([]uint32, []uint64) {
	idx := make([]int, len(offsets))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return offsets[idx[a]] < offsets[idx[b]] })
	outOffsets := make([]uint32, 0, len(offsets))
	outRaws := make([]uint64, 0, len(raws))
	for _, i := range idx {
		if n := len(outOffsets); n > 0 && outOffsets[n-1] == offsets[i] {
			continue
		}
		outOffsets = append(outOffsets, offsets[i])
		outRaws = append(outRaws, raws[i])
	}
	return outOffsets, outRaws
}
