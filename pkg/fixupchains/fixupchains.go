package fixupchains

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ianlancetaylor/demangle"
	"github.com/zdypro888/go-macho/types"
)

// ErrNoFixupAtOffset is returned when no fixup exists at the specified file offset.
var ErrNoFixupAtOffset = errors.New("no fixup found at offset")

// NewChainedFixups creates a new DyldChainedFixups instance
func NewChainedFixups(lcdat *bytes.Reader, sr *types.MachoReader, bo binary.ByteOrder) *DyldChainedFixups {
	return &DyldChainedFixups{
		r:      lcdat,
		sr:     *sr,
		bo:     bo,
		fixups: make(map[uint64][]Fixup),
	}
}

func (dcf *DyldChainedFixups) addTargetFixup(target uint64, fixup Fixup) {
	dcf.fixups[target] = append(dcf.fixups[target], fixup)
}

// Parse parses a LC_DYLD_CHAINED_FIXUPS load command
func (dcf *DyldChainedFixups) Parse() (*DyldChainedFixups, error) {
	dcf.parseMu.Lock()
	defer dcf.parseMu.Unlock()
	return dcf.parseLocked()
}

func (dcf *DyldChainedFixups) parseLocked() (*DyldChainedFixups, error) {
	if err := dcf.parseStartsLocked(); err != nil {
		return nil, err
	}

	if err := dcf.ensureImportsLocked(); err != nil {
		return nil, fmt.Errorf("failed to parse imports: %v", err)
	}

	if dcf.chainsParsed {
		return dcf, nil
	}

	if dcf.fixups == nil {
		dcf.fixups = make(map[uint64][]Fixup)
	} else {
		for k := range dcf.fixups {
			delete(dcf.fixups, k)
		}
	}
	for idx := range dcf.Starts {
		if len(dcf.Starts[idx].Fixups) > 0 {
			dcf.Starts[idx].Fixups = dcf.Starts[idx].Fixups[:0]
		}
	}

	for segIdx, start := range dcf.Starts {
		if start.PageStarts == nil || start.PageCount == 0 {
			continue
		}

		for pageIndex := uint16(0); pageIndex < start.PageCount; pageIndex++ {
			chainStarts, err := chainStartsForPage(&start, start.PageStarts[pageIndex])
			if err != nil {
				return nil, fmt.Errorf("segment %d page %d: %w", segIdx, pageIndex, err)
			}
			if len(chainStarts) == 0 {
				continue
			}
			for _, offsetInPage := range chainStarts {
				if err := dcf.walkDcFixupChain(segIdx, pageIndex, offsetInPage); err != nil {
					return nil, err
				}
			}
		}
	}

	dcf.chainsParsed = true

	return dcf, nil
}

func (dcf *DyldChainedFixups) ensureChainsParsed() error {
	dcf.parseMu.Lock()
	defer dcf.parseMu.Unlock()
	if dcf.chainsParsed {
		return nil
	}
	_, err := dcf.parseLocked()
	return err
}

// ParseStarts parses the DyldChainedStartsInSegment(s)
func (dcf *DyldChainedFixups) ParseStarts() error {
	dcf.parseMu.Lock()
	defer dcf.parseMu.Unlock()
	return dcf.parseStartsLocked()
}

func (dcf *DyldChainedFixups) parseStartsLocked() error {
	if dcf.metadataParsed {
		return nil
	}
	if dcf.r == nil {
		// e.g. a zero DyldChainedFixups{} used only for its PointerFormat
		return fmt.Errorf("chained-fixups payload reader is nil")
	}

	if _, err := dcf.r.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to chained-fixups header: %w", err)
	}
	if err := binary.Read(dcf.r, dcf.bo, &dcf.DyldChainedFixupsHeader); err != nil {
		return err
	}
	if dcf.FixupsVersion != 0 {
		return fmt.Errorf("unsupported chained-fixups version %d", dcf.FixupsVersion)
	}
	if dcf.StartsOffset < uint32(binary.Size(DyldChainedFixupsHeader{})) {
		return fmt.Errorf("starts offset %#x overlaps chained-fixups header", dcf.StartsOffset)
	}
	if uint64(dcf.StartsOffset)+4 > uint64(dcf.r.Size()) {
		return fmt.Errorf("starts offset %#x exceeds chained-fixups payload size %#x", dcf.StartsOffset, dcf.r.Size())
	}

	if _, err := dcf.r.Seek(int64(dcf.StartsOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to starts offset %d: %v", dcf.StartsOffset, err)
	}

	var segCount uint32
	if err := binary.Read(dcf.r, dcf.bo, &segCount); err != nil {
		return err
	}
	if uint64(segCount) > (uint64(dcf.r.Size())-uint64(dcf.StartsOffset)-4)/4 {
		return fmt.Errorf("segment count %d exceeds starts table bounds", segCount)
	}
	startsTableSize := uint64(4) + uint64(segCount)*4
	startsMetadataEnd := uint64(dcf.StartsOffset) + startsTableSize
	if uint64(dcf.ImportsOffset) < startsMetadataEnd {
		return fmt.Errorf("imports table at %#x overlaps starts metadata ending at %#x", dcf.ImportsOffset, startsMetadataEnd)
	}

	dcf.Starts = make([]DyldChainedStarts, segCount)
	segInfoOffsets := make([]uint32, segCount)
	if err := binary.Read(dcf.r, dcf.bo, &segInfoOffsets); err != nil {
		return err
	}
	var maxValidPointer uint32

	for segIdx, segInfoOffset := range segInfoOffsets {
		if segInfoOffset == 0 {
			continue
		}
		if uint64(segInfoOffset) < startsTableSize {
			return fmt.Errorf("segment %d starts offset %#x overlaps starts-in-image table ending at %#x", segIdx, segInfoOffset, startsTableSize)
		}

		segmentRecordOffset := uint64(dcf.StartsOffset) + uint64(segInfoOffset)
		if segmentRecordOffset+uint64(binary.Size(DyldChainedStartsInSegment{})) > uint64(dcf.r.Size()) {
			return fmt.Errorf("segment %d starts record at %#x exceeds payload bounds", segIdx, segmentRecordOffset)
		}
		if _, err := dcf.r.Seek(int64(segmentRecordOffset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to starts offset %d: %v", dcf.StartsOffset+segInfoOffset, err)
		}
		if err := binary.Read(dcf.r, dcf.bo, &dcf.Starts[segIdx].DyldChainedStartsInSegment); err != nil {
			return err
		}
		// Values 15 and 16 below are internal pseudo-formats used to reuse the
		// resolver for dyld shared-cache slide-info. They are not legal values
		// of dyld_chained_starts_in_segment.pointer_format on disk.
		pointerFormat := dcf.Starts[segIdx].PointerFormat
		if pointerFormat < DYLD_CHAINED_PTR_ARM64E || pointerFormat > DYLD_CHAINED_PTR_ARM64E_SEGMENTED {
			return fmt.Errorf("segment %d has unsupported chained pointer format %d", segIdx, pointerFormat)
		}
		if pageSize := dcf.Starts[segIdx].PageSize; pageSize != 0x1000 && pageSize != 0x4000 {
			return fmt.Errorf("segment %d has unsupported chained-fixup page size %#x", segIdx, pageSize)
		}
		dcf.Starts[segIdx].SegmentVMOffset = dcf.Starts[segIdx].SegmentOffset

		fixedSize := uint32(binary.Size(DyldChainedStartsInSegment{}))
		minimumSize := fixedSize + uint32(dcf.Starts[segIdx].PageCount)*2
		if dcf.Starts[segIdx].Size < minimumSize {
			return fmt.Errorf("segment %d starts size %d is smaller than page-start table size %d", segIdx, dcf.Starts[segIdx].Size, minimumSize)
		}
		if (dcf.Starts[segIdx].Size-minimumSize)%2 != 0 {
			return fmt.Errorf("segment %d starts size %d has a partial chain-start entry", segIdx, dcf.Starts[segIdx].Size)
		}
		if segmentRecordOffset+uint64(dcf.Starts[segIdx].Size) > uint64(dcf.r.Size()) {
			return fmt.Errorf("segment %d starts record size %d exceeds payload bounds", segIdx, dcf.Starts[segIdx].Size)
		}
		if dcf.ImportsOffset != 0 && segmentRecordOffset+uint64(dcf.Starts[segIdx].Size) > uint64(dcf.ImportsOffset) {
			return fmt.Errorf("segment %d starts record overlaps imports table at %#x", segIdx, dcf.ImportsOffset)
		}

		dcf.Starts[segIdx].PageStarts = make([]DCPtrStart, dcf.Starts[segIdx].PageCount)
		if err := binary.Read(dcf.r, dcf.bo, &dcf.Starts[segIdx].PageStarts); err != nil {
			return err
		}
		extraCount := (dcf.Starts[segIdx].Size - minimumSize) / 2
		if extraCount != 0 {
			dcf.Starts[segIdx].ChainStarts = make([]uint16, extraCount)
			if err := binary.Read(dcf.r, dcf.bo, &dcf.Starts[segIdx].ChainStarts); err != nil {
				return err
			}
		}
		for pageIdx, pageStart := range dcf.Starts[segIdx].PageStarts {
			if _, err := chainStartsForPage(&dcf.Starts[segIdx], pageStart); err != nil {
				return fmt.Errorf("segment %d page %d: %w", segIdx, pageIdx, err)
			}
		}

		if dcf.PointerFormat == 0 {
			dcf.PointerFormat = dcf.Starts[segIdx].PointerFormat
		} else if dcf.PointerFormat != dcf.Starts[segIdx].PointerFormat {
			return fmt.Errorf("segment %d pointer format %d differs from format %d used by prior segments", segIdx, dcf.Starts[segIdx].PointerFormat, dcf.PointerFormat)
		}
		if value := dcf.Starts[segIdx].MaxValidPointer; value != 0 {
			if maxValidPointer == 0 {
				maxValidPointer = value
			} else if maxValidPointer != value {
				return fmt.Errorf("segment %d max_valid_pointer %#x differs from %#x used by prior segments", segIdx, value, maxValidPointer)
			}
		}
	}

	dcf.metadataParsed = true
	dcf.segmentIndex = buildSegmentIndex(dcf.Starts)

	return nil
}

func chainStartsForPage(start *DyldChainedStarts, pageStart DCPtrStart) ([]DCPtrStart, error) {
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return nil, nil
	}
	if pageStart&DYLD_CHAINED_PTR_START_MULTI == 0 {
		// page_start and next describe the location of the chained pointer's
		// first byte.  In particular, format 11 permits an unaligned 8-byte
		// pointer to begin near the end of a page and finish in the next page.
		// Apple validates the start against page_size and the complete encoded
		// pointer against the segment, not against the current page.
		if uint64(pageStart) > uint64(start.PageSize) {
			return nil, fmt.Errorf("chain start %#x exceeds page size %#x", pageStart, start.PageSize)
		}
		return []DCPtrStart{pageStart}, nil
	}
	if start.PointerFormat != DYLD_CHAINED_PTR_32 && start.PointerFormat != DYLD_CHAINED_PTR_32_CACHE && start.PointerFormat != DYLD_CHAINED_PTR_32_FIRMWARE {
		return nil, fmt.Errorf("multi-start chains are invalid for 64-bit pointer format %d", start.PointerFormat)
	}

	combinedIndex := int(pageStart &^ DYLD_CHAINED_PTR_START_MULTI)
	chainIndex := combinedIndex - len(start.PageStarts)
	if chainIndex < 0 || chainIndex >= len(start.ChainStarts) {
		return nil, fmt.Errorf("chain-start index %d is outside trailing table [%d,%d)", combinedIndex, len(start.PageStarts), len(start.PageStarts)+len(start.ChainStarts))
	}

	result := make([]DCPtrStart, 0, 2)
	var previous DCPtrStart
	for chainIndex < len(start.ChainStarts) {
		entry := DCPtrStart(start.ChainStarts[chainIndex])
		offset := entry &^ DYLD_CHAINED_PTR_START_LAST
		if uint64(offset) > uint64(start.PageSize) {
			return nil, fmt.Errorf("chain start %#x exceeds page size %#x", offset, start.PageSize)
		}
		if previous != 0 && offset <= previous {
			return nil, fmt.Errorf("chain start %#x is not after previous start %#x", offset, previous)
		}
		result = append(result, offset)
		previous = offset
		if entry&DYLD_CHAINED_PTR_START_LAST != 0 {
			return result, nil
		}
		chainIndex++
	}
	return nil, fmt.Errorf("multi-start chain has no LAST terminator")
}

// checkedChainFixupLocation applies dyld's page semantics while still requiring
// the complete encoded pointer to remain inside the segment described by the
// starts record.  The underlying reader supplies the final file/read boundary.
func checkedChainFixupLocation(start *DyldChainedStarts, pageContentStart, offsetInPage uint64) (uint64, error) {
	pageSize := uint64(start.PageSize)
	if pageSize == 0 {
		return 0, errors.New("chained-fixup page size is zero")
	}
	if offsetInPage > pageSize {
		return 0, fmt.Errorf("chain offset %#x exceeds page size %#x", offsetInPage, pageSize)
	}
	if pageContentStart > ^uint64(0)-offsetInPage {
		return 0, fmt.Errorf("chain location %#x+%#x overflows", pageContentStart, offsetInPage)
	}
	location := pageContentStart + offsetInPage
	pointerBytes := uint64(pointerSize(start.PointerFormat))
	if pointerBytes == 0 {
		return 0, fmt.Errorf("unsupported pointer size for format %d", start.PointerFormat)
	}
	segmentBytes := uint64(start.PageCount) * pageSize
	if segmentBytes < pointerBytes || start.SegmentOffset > ^uint64(0)-segmentBytes {
		return 0, fmt.Errorf("segment range %#x+%#x cannot contain a %d-byte chained pointer", start.SegmentOffset, segmentBytes, pointerBytes)
	}
	if location < start.SegmentOffset || location-start.SegmentOffset > segmentBytes-pointerBytes {
		return 0, fmt.Errorf("fixup at %#x (%d bytes) exceeds segment [%#x,%#x)", location, pointerBytes, start.SegmentOffset, start.SegmentOffset+segmentBytes)
	}
	return location, nil
}

// ResetSegmentIndex rebuilds the segment lookup index after a caller changes Starts.
// Rebuilding here keeps subsequent lookup methods read-only.
func (dcf *DyldChainedFixups) ResetSegmentIndex() {
	dcf.parseMu.Lock()
	defer dcf.parseMu.Unlock()
	dcf.segmentIndex = buildSegmentIndex(dcf.Starts)
}

// SetKernelCacheBaseAddress supplies one of the runtime basePointers entries
// required by formats 8 and 11. The address must already include that kernel
// collection's own slide; it is not adjusted by the slide of the image whose
// fixup is being decoded. Configure it before publishing dcf to concurrent
// readers.
func (dcf *DyldChainedFixups) SetKernelCacheBaseAddress(level uint8, address uint64) error {
	if level >= uint8(len(dcf.kernelCacheBases)) {
		return fmt.Errorf("kernel cache base level %d is outside [0,%d)", level, len(dcf.kernelCacheBases))
	}
	dcf.kernelCacheBases[level] = address
	dcf.kernelCacheBaseSet[level] = true
	return nil
}

// KernelCacheBaseAddress reports a configured runtime basePointers entry.
func (dcf *DyldChainedFixups) KernelCacheBaseAddress(level uint8) (uint64, bool) {
	if level >= uint8(len(dcf.kernelCacheBases)) {
		return 0, false
	}
	return dcf.kernelCacheBases[level], dcf.kernelCacheBaseSet[level]
}

// SetKernelCacheLevelZeroSegmentAddress supplies the lowest unslid LC_SEGMENT
// vmaddr of a standalone kernel collection. ResolveRebaseVMAddress adds its
// slide argument to this layout address. An explicit runtime basePointers[0]
// supplied through SetKernelCacheBaseAddress takes precedence.
func (dcf *DyldChainedFixups) SetKernelCacheLevelZeroSegmentAddress(address uint64) {
	dcf.kernelCacheLevelZeroSegment = address
	dcf.kernelCacheLevelZeroSegmentSet = true
}

// SetSharedCacheBaseAddress supplies the unslid base address used by shared-cache
// pointer formats 13, 15, and 16. It must be called before decoding or resolving
// those formats, and before publishing dcf to concurrent readers.
func (dcf *DyldChainedFixups) SetSharedCacheBaseAddress(address uint64) {
	dcf.sharedCacheBase = address
	dcf.sharedCacheBaseSet = true
}

// SharedCacheBaseAddress reports the explicitly configured unslid shared-cache base.
func (dcf *DyldChainedFixups) SharedCacheBaseAddress() (uint64, bool) {
	return dcf.sharedCacheBase, dcf.sharedCacheBaseSet
}

func buildSegmentIndex(starts []DyldChainedStarts) []segmentRange {
	index := make([]segmentRange, 0, len(starts))
	for idx := range starts {
		start := &starts[idx]
		if start.PageCount == 0 || start.PageSize == 0 || start.PageStarts == nil {
			continue
		}
		segStart := start.SegmentOffset
		segEnd := segStart + uint64(start.PageCount)*uint64(start.PageSize)
		if segEnd <= segStart {
			continue
		}
		index = append(index, segmentRange{start: segStart, end: segEnd, index: idx})
	}
	sort.Slice(index, func(i, j int) bool {
		if index[i].start == index[j].start {
			return index[i].end < index[j].end
		}
		return index[i].start < index[j].start
	})
	return index
}

func (dcf *DyldChainedFixups) findSegmentForOffset(offset uint64) *DyldChainedStarts {
	// Parsed metadata installs an immutable index. Directly constructed values
	// may not have one; build a local index instead of mutating from a read path.
	index := dcf.segmentIndex
	if index == nil {
		index = buildSegmentIndex(dcf.Starts)
	}
	if len(index) == 0 {
		return nil
	}
	i := sort.Search(len(index), func(i int) bool {
		return index[i].start > offset
	})
	if i == 0 {
		cover := index[0]
		if offset >= cover.start && offset < cover.end {
			return &dcf.Starts[cover.index]
		}
		return nil
	}
	cover := index[i-1]
	if offset >= cover.start && offset < cover.end {
		return &dcf.Starts[cover.index]
	}
	if i < len(index) {
		next := index[i]
		if offset >= next.start && offset < next.end {
			return &dcf.Starts[next.index]
		}
	}
	return nil
}

// EnsureImports lazily parses the imports table for chained fixups.
func (dcf *DyldChainedFixups) EnsureImports() error {
	dcf.parseMu.Lock()
	defer dcf.parseMu.Unlock()
	return dcf.ensureImportsLocked()
}

func (dcf *DyldChainedFixups) ensureImportsLocked() error {
	if dcf.importsParsed {
		return nil
	}
	if !dcf.metadataParsed {
		if err := dcf.parseStartsLocked(); err != nil {
			return fmt.Errorf("failed to parse starts before imports: %w", err)
		}
	}
	if err := dcf.validateImportCount(); err != nil {
		return err
	}
	if _, err := dcf.validateImportsLayout(); err != nil {
		return err
	}
	if dcf.ImportsCount == 0 {
		dcf.Imports = dcf.Imports[:0]
		dcf.importsParsed = true
		return nil
	}
	if err := dcf.parseImports(); err != nil {
		return err
	}
	dcf.importsParsed = true
	return nil
}

func (dcf *DyldChainedFixups) validateImportCount() error {
	if dcf.ImportsCount == 0 {
		return nil
	}
	var maxOrdinal uint32
	switch dcf.PointerFormat {
	case DYLD_CHAINED_PTR_ARM64E,
		DYLD_CHAINED_PTR_ARM64E_KERNEL,
		DYLD_CHAINED_PTR_ARM64E_USERLAND,
		DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		maxOrdinal = 0x0000ffff
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24,
		DYLD_CHAINED_PTR_64,
		DYLD_CHAINED_PTR_64_OFFSET:
		maxOrdinal = 0x00ffffff
	case DYLD_CHAINED_PTR_32:
		maxOrdinal = 0x000fffff
	default:
		return fmt.Errorf("chained pointer format %d does not support %d imports", dcf.PointerFormat, dcf.ImportsCount)
	}
	if dcf.ImportsCount >= maxOrdinal {
		return fmt.Errorf("chained imports count %d exceeds pointer format %d maximum %d", dcf.ImportsCount, dcf.PointerFormat, maxOrdinal)
	}
	return nil
}

// validateImportsLayout validates the chained header fields which remain
// meaningful even when imports_count is zero. Entry decoding is intentionally
// separate so the zero-count fast path cannot hide a malformed wire format.
func (dcf *DyldChainedFixups) validateImportsLayout() (uint64, error) {
	var importSize uint64
	switch dcf.ImportsFormat {
	case DC_IMPORT:
		importSize = uint64(binary.Size(DyldChainedImport(0)))
	case DC_IMPORT_ADDEND:
		importSize = uint64(binary.Size(DyldChainedImportAddend{}))
	case DC_IMPORT_ADDEND64:
		importSize = uint64(binary.Size(DyldChainedImportAddend64{}))
	default:
		return 0, fmt.Errorf("unknown chained imports format %d", dcf.ImportsFormat)
	}
	if dcf.SymbolsFormat != DC_SFORMAT_UNCOMPRESSED {
		return 0, fmt.Errorf("unknown chained symbols format %d", dcf.SymbolsFormat)
	}

	importsOffset := uint64(dcf.ImportsOffset)
	symbolsOffset := uint64(dcf.SymbolsOffset)
	payloadSize := uint64(dcf.r.Size())
	if importsOffset > symbolsOffset || symbolsOffset > payloadSize ||
		uint64(dcf.ImportsCount) > (symbolsOffset-importsOffset)/importSize {
		importsEnd := importsOffset + uint64(dcf.ImportsCount)*importSize
		return 0, fmt.Errorf("chained imports [%#x,%#x) and symbols offset %#x exceed payload size %#x", dcf.ImportsOffset, importsEnd, dcf.SymbolsOffset, dcf.r.Size())
	}
	return importSize, nil
}

// Rebase returns the rebased target encoded at the given file offset if the location contains
// a chained rebase pointer. The offset must be a file offset matching the coordinate system used
// by dyld chained fixups metadata. The result matches the semantics of IsRebase (runtime offset).
func (dcf *DyldChainedFixups) Rebase(offset uint64, preferredLoadAddress uint64) (uint64, error) {
	rebase, format, err := dcf.rebaseAtOffset(offset)
	if err != nil {
		return 0, err
	}
	return dcf.decodeRebaseTarget(format, offset, rebase.Raw(), preferredLoadAddress)
}

// RebaseRaw decodes a chained rebase pointer given the file offset and raw pointer bits.
// preferredLoadAddress is used to produce the runtime offset consistent with IsRebase.
func (dcf *DyldChainedFixups) RebaseRaw(offset uint64, raw uint64, preferredLoadAddress uint64) (uint64, error) {
	_, format, err := dcf.rebaseAtOffset(offset)
	if err != nil {
		return 0, err
	}
	return dcf.decodeRebaseTarget(format, offset, raw, preferredLoadAddress)
}

func (dcf *DyldChainedFixups) rebaseAtOffset(offset uint64) (Rebase, DCPtrKind, error) {
	fixup, err := dcf.GetFixupAtOffset(offset)
	if err != nil {
		return nil, 0, fmt.Errorf("offset %#x is not a chained rebase: %w", offset, err)
	}
	rebase, ok := fixup.(Rebase)
	if !ok {
		return nil, 0, fmt.Errorf("offset %#x contains a chained bind, not a rebase", offset)
	}
	start := dcf.findSegmentForOffset(offset)
	if start == nil {
		return nil, 0, fmt.Errorf("offset %#x has no chained-fixup segment", offset)
	}
	return rebase, start.PointerFormat, nil
}

// PointerFormatForOffset reports the chained pointer format that applies to the given file offset.
func (dcf *DyldChainedFixups) PointerFormatForOffset(offset uint64) (DCPtrKind, error) {
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		return 0, err
	}
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return 0, fmt.Errorf("offset %#x is not covered by chained fixups", offset)
	}
	return start.PointerFormat, nil
}

func (dcf *DyldChainedFixups) locateStartForOffset(offset uint64) (*DyldChainedStarts, DCPtrStart, error) {
	if err := dcf.ParseStarts(); err != nil {
		return nil, 0, err
	}

	start := dcf.findSegmentForOffset(offset)
	if start == nil {
		return nil, 0, fmt.Errorf("offset %#x is not covered by chained rebase fixups", offset)
	}

	if start.PageSize == 0 {
		return nil, 0, fmt.Errorf("invalid page size for chained fixups segment covering offset %#x", offset)
	}

	pageSize := uint64(start.PageSize)
	segStart := start.SegmentOffset
	if offset < segStart {
		return nil, 0, fmt.Errorf("offset %#x precedes segment start %#x", offset, segStart)
	}
	pageIndex := (offset - segStart) / pageSize
	if pageIndex >= uint64(len(start.PageStarts)) {
		return nil, 0, fmt.Errorf("offset %#x exceeds page array bounds", offset)
	}

	return start, start.PageStarts[pageIndex], nil
}

func (dcf *DyldChainedFixups) decodeRebaseTarget(format DCPtrKind, offset uint64, raw uint64, preferredLoadAddress uint64) (uint64, error) {
	switch format {
	case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24,
		DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if DcpArm64eIsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		if DcpArm64eIsAuth(raw) {
			rebase := DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: offset}
			return rebase.Target(), nil
		}
		rebase := DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: offset}
		if format == DYLD_CHAINED_PTR_ARM64E || format == DYLD_CHAINED_PTR_ARM64E_FIRMWARE {
			if rebase.Target() < preferredLoadAddress {
				return 0, fmt.Errorf("offset %#x encodes vmaddr %#x below preferred load address %#x", offset, rebase.Target(), preferredLoadAddress)
			}
			return rebase.High8()<<56 | (rebase.Target() - preferredLoadAddress), nil
		}
		return rebase.UnpackTarget(), nil
	case DYLD_CHAINED_PTR_64:
		if Generic64IsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		rebase := DyldChainedPtr64Rebase{Pointer: raw, Fixup: offset}
		if rebase.Target() < preferredLoadAddress {
			return 0, fmt.Errorf("offset %#x encodes vmaddr %#x below preferred load address %#x", offset, rebase.Target(), preferredLoadAddress)
		}
		return rebase.High8()<<56 | (rebase.Target() - preferredLoadAddress), nil
	case DYLD_CHAINED_PTR_64_OFFSET:
		if Generic64IsBind(raw) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		rebase := DyldChainedPtr64RebaseOffset{Pointer: raw, Fixup: offset}
		return rebase.UnpackedTarget(), nil
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		rebase := DyldChainedPtr64KernelCacheRebase{Pointer: raw, Fixup: offset}
		absoluteTarget, err := dcf.resolveKernelCacheTarget(rebase, preferredLoadAddress, 0)
		if err != nil {
			return 0, fmt.Errorf("kernel cache pointer at %#x: %w", offset, err)
		}
		// RebaseRaw and IsRebase retain their historical preferred-relative
		// contract. Modular subtraction also represents a SystemKC reference
		// whose level-0 primary base is below the current image's __TEXT.
		return absoluteTarget - preferredLoadAddress, nil
	case DYLD_CHAINED_PTR_32:
		ptr32 := uint32(raw)
		if Generic32IsBind(ptr32) {
			return 0, fmt.Errorf("offset %#x encodes a bind pointer, not a rebase", offset)
		}
		if value, ok := dcf.decode32NonPointer(offset, ptr32); ok {
			// Legacy callers add preferredLoadAddress to the returned runtime
			// offset. Use modular subtraction so they reconstruct the scalar.
			return value - preferredLoadAddress, nil
		}
		rebase := DyldChainedPtr32Rebase{Pointer: ptr32, Fixup: offset}
		target := rebase.Target()
		if target < preferredLoadAddress {
			return 0, fmt.Errorf("offset %#x encodes vmaddr %#x below preferred load address %#x", offset, target, preferredLoadAddress)
		}
		return target - preferredLoadAddress, nil
	case DYLD_CHAINED_PTR_32_CACHE:
		rebase := DyldChainedPtr32CacheRebase{Pointer: uint32(raw), Fixup: offset}
		return rebase.Target(), nil
	case DYLD_CHAINED_PTR_32_FIRMWARE:
		rebase := DyldChainedPtr32FirmwareRebase{Pointer: uint32(raw), Fixup: offset}
		if rebase.Target() < preferredLoadAddress {
			return 0, fmt.Errorf("offset %#x encodes vmaddr %#x below preferred load address %#x", offset, rebase.Target(), preferredLoadAddress)
		}
		return rebase.Target() - preferredLoadAddress, nil
	case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
		if _, err := dcf.requireSharedCacheBase(format); err != nil {
			return 0, err
		}
		if raw>>63 != 0 {
			return DyldChainedPtrArm64eSharedCacheAuthRebase{Pointer: raw, Fixup: offset}.Target(), nil
		}
		rebase := DyldChainedPtrArm64eSharedCacheRebase{Pointer: raw, Fixup: offset}
		return rebase.UnpackedTarget(), nil
	case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
		var segmentIndex, segmentOffset uint64
		if raw>>63 != 0 {
			rebase := DyldChainedPtrArm64eAuthSegmentedRebase{Pointer: raw, Fixup: offset}
			segmentIndex, segmentOffset = rebase.SegIndex(), rebase.Target()
		} else {
			rebase := DyldChainedPtrArm64eSegmentedRebase{Pointer: raw, Fixup: offset}
			segmentIndex, segmentOffset = rebase.SegIndex(), rebase.Target()
		}
		if segmentIndex >= uint64(len(dcf.Starts)) {
			return 0, fmt.Errorf("offset %#x encodes segment index %d, but only %d segment starts exist", offset, segmentIndex, len(dcf.Starts))
		}
		segmentBase := dcf.Starts[segmentIndex].SegmentVMOffset
		// Directly-constructed metadata from older callers has no preserved
		// value. Parsed payloads always initialize SegmentVMOffset.
		if segmentBase == 0 && dcf.Starts[segmentIndex].SegmentOffset != 0 {
			segmentBase = dcf.Starts[segmentIndex].SegmentOffset
		}
		if segmentOffset > ^uint64(0)-segmentBase {
			return 0, fmt.Errorf("segmented pointer at %#x base %#x plus offset %#x overflows", offset, segmentBase, segmentOffset)
		}
		return segmentBase + segmentOffset, nil
	case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3:
		sharedCacheBase, err := dcf.requireSharedCacheBase(format)
		if err != nil {
			return 0, err
		}
		if raw>>63 != 0 {
			return DyldChainedPtrArm64eSharedCacheV3AuthRebase{Pointer: raw, Fixup: offset}.Target(), nil
		}
		rebase := DyldChainedPtrArm64eSharedCacheV3Rebase{Pointer: raw, Fixup: offset}
		target := rebase.UnpackedTarget()
		if target < sharedCacheBase {
			return 0, fmt.Errorf("shared-cache-v3 pointer at %#x encodes vmaddr %#x below shared-cache base %#x", offset, target, sharedCacheBase)
		}
		return target - sharedCacheBase, nil
	case DYLD_CHAINED_PTR_SHARED_CACHE_V2:
		if _, err := dcf.requireSharedCacheBase(format); err != nil {
			return 0, err
		}
		return DyldChainedPtrSharedCacheV2Rebase{Pointer: raw, Fixup: offset}.UnpackedTarget(), nil
	default:
		return 0, fmt.Errorf("pointer format %d not supported for rebase lookups", format)
	}
}

// resolveKernelCacheTarget implements XNU's fixup_value calculation for
// formats 8 and 11: basePointers[cacheLevel] + target. Explicit bases are
// runtime addresses and therefore never consume currentImageSlide. The
// preferred+slide fallback only exists for a low-level level-0 decoder which
// has not been given its containing KC's segment layout; File and the iunios
// loader configure level zero from the lowest LC_SEGMENT vmaddr.
func (dcf *DyldChainedFixups) resolveKernelCacheTarget(rebase DyldChainedPtr64KernelCacheRebase, preferredLoadAddress, currentImageSlide uint64) (uint64, error) {
	level := rebase.CacheLevel()
	base := preferredLoadAddress
	if dcf.kernelCacheBaseSet[level] {
		base = dcf.kernelCacheBases[level]
	} else {
		if level != 0 {
			return 0, fmt.Errorf("requires basePointers[%d]", level)
		}
		if dcf.kernelCacheLevelZeroSegmentSet {
			base = dcf.kernelCacheLevelZeroSegment
		}
		if base > ^uint64(0)-currentImageSlide {
			return 0, fmt.Errorf("level-0 fallback base %#x plus slide %#x overflows", base, currentImageSlide)
		}
		base += currentImageSlide
	}
	if rebase.Target() > ^uint64(0)-base {
		return 0, fmt.Errorf("basePointers[%d] %#x plus target %#x overflows", level, base, rebase.Target())
	}
	return base + rebase.Target(), nil
}

func isSharedCachePointerFormat(format DCPtrKind) bool {
	switch format {
	case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3,
		DYLD_CHAINED_PTR_SHARED_CACHE_V2:
		return true
	default:
		return false
	}
}

func (dcf *DyldChainedFixups) requireSharedCacheBase(format DCPtrKind) (uint64, error) {
	if !dcf.sharedCacheBaseSet {
		return 0, fmt.Errorf("pointer format %d requires an explicit shared-cache base; call SetSharedCacheBaseAddress before decoding", format)
	}
	return dcf.sharedCacheBase, nil
}

func (dcf *DyldChainedFixups) decode32NonPointer(offset uint64, raw uint32) (uint64, bool) {
	if Generic32IsBind(raw) {
		return 0, false
	}
	var maxValidPointer uint32
	if start := dcf.findSegmentForOffset(offset); start != nil && start.PointerFormat == DYLD_CHAINED_PTR_32 {
		maxValidPointer = start.MaxValidPointer
	}
	if maxValidPointer == 0 {
		// Mach-O validation requires the non-zero max_valid_pointer value to
		// be identical across segments, so the first value is sufficient for
		// location-free IsRebase calls.
		for index := range dcf.Starts {
			if dcf.Starts[index].PointerFormat == DYLD_CHAINED_PTR_32 && dcf.Starts[index].MaxValidPointer != 0 {
				maxValidPointer = dcf.Starts[index].MaxValidPointer
				break
			}
		}
	}
	if maxValidPointer == 0 {
		return 0, false
	}
	target := uint32(DyldChainedPtr32Rebase{Pointer: raw}.Target())
	if target <= maxValidPointer {
		return 0, false
	}
	bias := (uint32(0x04000000) + maxValidPointer) / 2
	return uint64(target - bias), true
}

// IsRebasePointer distinguishes actual pointer rebases from the scalar values
// co-opted into DYLD_CHAINED_PTR_32 chains above max_valid_pointer. Scalar
// entries must be restored in memory but must not be tracked as ASLR pointers.
func (dcf *DyldChainedFixups) IsRebasePointer(rebase Rebase) bool {
	if dcf.PointerFormat != DYLD_CHAINED_PTR_32 {
		return true
	}
	_, isNonPointer := dcf.decode32NonPointer(rebase.Offset(), uint32(rebase.Raw()))
	return !isNonPointer
}

func bindOrdinalForPointer(format DCPtrKind, raw uint64) (uint64, bool) {
	switch format {
	case DYLD_CHAINED_PTR_32:
		if !Generic32IsBind(uint32(raw)) {
			return 0, false
		}
		return DyldChainedPtr32Bind{Pointer: uint32(raw)}.Ordinal(), true
	case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET:
		if !Generic64IsBind(raw) {
			return 0, false
		}
		return DyldChainedPtr64Bind{Pointer: raw}.Ordinal(), true
	case DYLD_CHAINED_PTR_ARM64E,
		DYLD_CHAINED_PTR_ARM64E_KERNEL,
		DYLD_CHAINED_PTR_ARM64E_USERLAND,
		DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if !DcpArm64eIsBind(raw) {
			return 0, false
		}
		return DyldChainedPtrArm64eBind{Pointer: raw}.Ordinal(), true
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		if !DcpArm64eIsBind(raw) {
			return 0, false
		}
		return DyldChainedPtrArm64eBind24{Pointer: raw}.Ordinal(), true
	default:
		return 0, false
	}
}

func (dcf *DyldChainedFixups) validateBindOrdinal(format DCPtrKind, raw, fixupLocation uint64) error {
	ordinal, bind := bindOrdinalForPointer(format, raw)
	if bind && ordinal >= uint64(len(dcf.Imports)) {
		return fmt.Errorf("bind ordinal %d at fixup %#x exceeds imports count %d", ordinal, fixupLocation, len(dcf.Imports))
	}
	return nil
}

func (dcf *DyldChainedFixups) walkDcFixupChain(segIdx int, pageIndex uint16, offsetInPage DCPtrStart) error {

	var dcPtr uint32
	var dcPtr64 uint64
	var next uint64

	chainEnd := false
	start := &dcf.Starts[segIdx]
	segOffset := start.SegmentOffset
	pageSize := uint64(start.PageSize)
	pageOffset := uint64(pageIndex) * pageSize
	if segOffset > ^uint64(0)-pageOffset {
		return fmt.Errorf("segment %#x page %d offset overflows", segOffset, pageIndex)
	}
	pageContentStart := segOffset + pageOffset
	pointerFormat := start.PointerFormat
	step, ok := stride(pointerFormat)
	if !ok {
		return fmt.Errorf("unsupported pointer chain format: %d", pointerFormat)
	}

	for !chainEnd {
		chainOffset := uint64(offsetInPage)
		if chainOffset > ^uint64(0)-next {
			return fmt.Errorf("chain offset %#x+%#x overflows", chainOffset, next)
		}
		chainOffset += next
		fixupLocation, err := checkedChainFixupLocation(start, pageContentStart, chainOffset)
		if err != nil {
			return err
		}
		raw, err := dcf.readRawPointer(pointerFormat, fixupLocation)
		if err != nil {
			return fmt.Errorf("failed to read fixup at %#x: %w", fixupLocation, err)
		}
		dcPtr = uint32(raw)
		dcPtr64 = raw

		switch pointerFormat {
		case DYLD_CHAINED_PTR_32:
			if err := dcf.validateBindOrdinal(pointerFormat, uint64(dcPtr), fixupLocation); err != nil {
				return err
			}
			if Generic32IsBind(dcPtr) {
				bind := DyldChainedPtr32Bind{Pointer: dcPtr, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr32Rebase{
					Pointer: dcPtr,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			}
			if Generic32Next(dcPtr) == 0 {
				chainEnd = true
			}
			next += Generic32Next(dcPtr) * step
		case DYLD_CHAINED_PTR_32_CACHE:
			rebase := DyldChainedPtr32CacheRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.addTargetFixup(rebase.Target(), rebase)
			chainNext := uint64(rebase.Next())
			if chainNext == 0 {
				chainEnd = true
			}
			next += chainNext * step
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			rebase := DyldChainedPtr32FirmwareRebase{
				Pointer: dcPtr,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.addTargetFixup(rebase.Target(), rebase)
			chainNext := uint64(rebase.Next())
			if chainNext == 0 {
				chainEnd = true
			}
			next += chainNext * step
		case DYLD_CHAINED_PTR_64: // target is vmaddr
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			if Generic64IsBind(dcPtr64) {
				bind := DyldChainedPtr64Bind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr64Rebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * step
		case DYLD_CHAINED_PTR_64_OFFSET: // target is vm offset
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			// NOTE: the fixup-chains.h seems to indicate that DYLD_CHAINED_PTR_64_OFFSET is a rebase, but can also be a bind
			if Generic64IsBind(dcPtr64) {
				bind := DyldChainedPtr64Bind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else {
				rebase := DyldChainedPtr64RebaseOffset{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			}
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * step
		case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			rebase := DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.addTargetFixup(rebase.Target(), rebase)
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * step
		case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: // stride 1, x86_64 kernel caches
			rebase := DyldChainedPtr64KernelCacheRebase{
				Pointer: dcPtr64,
				Fixup:   fixupLocation,
			}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.addTargetFixup(rebase.Target(), rebase)
			if Generic64Next(dcPtr64) == 0 {
				chainEnd = true
			}
			next += Generic64Next(dcPtr64) * step
		case DYLD_CHAINED_PTR_ARM64E_KERNEL: // stride 4, unauth target is vm offset
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.addTargetFixup(authRebase.Target(), authRebase)
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * step
		case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: // stride 4, unauth target is vmaddr
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.addTargetFixup(authRebase.Target(), authRebase)
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * step
		case DYLD_CHAINED_PTR_ARM64E: // stride 8, unauth target is vmaddr
			fallthrough
		case DYLD_CHAINED_PTR_ARM64E_USERLAND: // stride 8, unauth target is vm offset
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.addTargetFixup(authRebase.Target(), authRebase)
			} else {
				bind := DyldChainedPtrArm64eAuthBind{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * step
		case DYLD_CHAINED_PTR_ARM64E_USERLAND24: // stride 8, unauth target is vm offset, 24-bit bind
			if err := dcf.validateBindOrdinal(pointerFormat, dcPtr64, fixupLocation); err != nil {
				return err
			}
			if !DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				rebase := DyldChainedPtrArm64eRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
			} else if DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eAuthBind24{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			} else if !DcpArm64eIsBind(dcPtr64) && DcpArm64eIsAuth(dcPtr64) {
				authRebase := DyldChainedPtrArm64eAuthRebase{
					Pointer: dcPtr64,
					Fixup:   fixupLocation,
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, authRebase)
				dcf.addTargetFixup(authRebase.Target(), authRebase)
			} else if DcpArm64eIsBind(dcPtr64) && !DcpArm64eIsAuth(dcPtr64) {
				bind := DyldChainedPtrArm64eBind24{Pointer: dcPtr64, Fixup: fixupLocation}
				if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
					bind.Import = dcf.Imports[ord].Name
					bind.ImportAddend = int64(dcf.Imports[ord].Addend())
				}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, bind)
			}
			if DcpArm64eNext(dcPtr64) == 0 {
				chainEnd = true
			}
			next += DcpArm64eNext(dcPtr64) * step
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
			if dcPtr64>>63 != 0 {
				rebase := DyldChainedPtrArm64eSharedCacheAuthRebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			} else {
				rebase := DyldChainedPtrArm64eSharedCacheRebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			}
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3:
			if dcPtr64>>63 != 0 {
				rebase := DyldChainedPtrArm64eSharedCacheV3AuthRebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			} else {
				rebase := DyldChainedPtrArm64eSharedCacheV3Rebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			}
		case DYLD_CHAINED_PTR_SHARED_CACHE_V2:
			rebase := DyldChainedPtrSharedCacheV2Rebase{Pointer: dcPtr64, Fixup: fixupLocation}
			dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
			dcf.addTargetFixup(rebase.Target(), rebase)
			if rebase.Next() == 0 {
				chainEnd = true
			}
			next += rebase.Next() * step
		case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
			if dcPtr64>>63 != 0 {
				rebase := DyldChainedPtrArm64eAuthSegmentedRebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			} else {
				rebase := DyldChainedPtrArm64eSegmentedRebase{Pointer: dcPtr64, Fixup: fixupLocation}
				dcf.Starts[segIdx].Fixups = append(dcf.Starts[segIdx].Fixups, rebase)
				dcf.addTargetFixup(rebase.Target(), rebase)
				if rebase.Next() == 0 {
					chainEnd = true
				}
				next += rebase.Next() * step
			}
		default:
			return fmt.Errorf("unknown pointer format %#04X", dcf.Starts[segIdx].PointerFormat)
		}

		if !chainEnd {
			if uint64(offsetInPage) > ^uint64(0)-next {
				return fmt.Errorf("chain offset %#x+%#x overflows", offsetInPage, next)
			}
			// The current encoded pointer may straddle a page boundary, but the
			// next pointer's start remains part of this page's chain only through
			// page_end itself. This matches the point walker and Apple dyld.
			if uint64(offsetInPage)+next > pageSize {
				break
			}
		}
	}

	return nil
}

func (dcf *DyldChainedFixups) readRawPointer(format DCPtrKind, offset uint64) (uint64, error) {
	size := pointerSize(format)
	if size != 4 && size != 8 {
		return 0, fmt.Errorf("unsupported pointer size for format %d", format)
	}

	// Check if we have a valid reader
	if dcf.sr == nil {
		return 0, fmt.Errorf("no reader available for reading pointer at %#x", offset)
	}

	var buf [8]byte
	n, err := dcf.sr.ReadAt(buf[:size], int64(offset))
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("failed to read pointer at %#x: %w", offset, err)
	}
	if n != size {
		return 0, fmt.Errorf("short read at %#x", offset)
	}
	if size == 4 {
		return uint64(dcf.bo.Uint32(buf[:4])), nil
	}
	return dcf.bo.Uint64(buf[:8]), nil
}

func (dcf *DyldChainedFixups) parseImports() error {
	importSize, err := dcf.validateImportsLayout()
	if err != nil {
		return err
	}

	importsOffset := uint64(dcf.ImportsOffset)
	symbolsOffset := uint64(dcf.SymbolsOffset)
	importsEnd := importsOffset + uint64(dcf.ImportsCount)*importSize
	if importsEnd > symbolsOffset {
		return fmt.Errorf("chained imports [%#x,%#x) overlap symbols at %#x", dcf.ImportsOffset, importsEnd, dcf.SymbolsOffset)
	}

	imports := make([]Import, 0, int(dcf.ImportsCount))
	parsedImports := make([]DcfImport, 0, int(dcf.ImportsCount))

	if _, err := dcf.r.Seek(int64(dcf.ImportsOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to imports offset %d: %v", dcf.ImportsOffset, err)
	}

	switch dcf.ImportsFormat {
	case DC_IMPORT:
		ii := make([]DyldChainedImport, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND:
		ii := make([]DyldChainedImportAddend, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	case DC_IMPORT_ADDEND64:
		ii := make([]DyldChainedImportAddend64, dcf.ImportsCount)
		if err := binary.Read(dcf.r, dcf.bo, &ii); err != nil {
			return err
		}
		for _, i := range ii {
			imports = append(imports, i)
		}
	default:
		return fmt.Errorf("unknown chained imports format %d", dcf.ImportsFormat)
	}

	symbolReader := io.NewSectionReader(dcf.r, int64(dcf.SymbolsOffset), dcf.r.Size()-int64(dcf.SymbolsOffset))
	symbolsPool, err := io.ReadAll(symbolReader)
	if err != nil {
		return fmt.Errorf("failed to read chained symbol pool: %w", err)
	}

	for _, i := range imports {
		nameOffset := i.NameOffset()
		if nameOffset >= uint64(len(symbolsPool)) {
			return fmt.Errorf("symbol name offset %d exceeds decompressed pool size %d", nameOffset, len(symbolsPool))
		}
		remaining := symbolsPool[nameOffset:]
		terminator := bytes.IndexByte(remaining, 0)
		if terminator < 0 {
			return fmt.Errorf("failed to read string at %d: missing NUL terminator", uint64(dcf.SymbolsOffset)+nameOffset)
		}
		// 处理符号名称：去掉前缀并进行 demangle
		name := string(remaining[:terminator])
		if len(name) > 0 && name[0] == '_' {
			if strings.Contains(name, ".") {
				// Go 符号包含点号，仅去掉前缀
				name = name[1:]
			} else if strings.HasPrefix(name, "_OBJC_CLASS_$_") || strings.HasPrefix(name, "_OBJC_METACLASS_$_") {
				// ObjC class/metaclass 符号，保留原始名不 demangle
			} else {
				// C++/Swift 等符号，进行 demangle
				name = demangle.Filter(name[1:])
			}
		}
		parsedImports = append(parsedImports, DcfImport{
			Name:   name,
			Import: i,
		})
	}

	dcf.Imports = parsedImports
	return nil
}

func (dcf *DyldChainedFixups) IsRebase(addr, preferredLoadAddress uint64) (uint64, bool) {
	targetRuntimeOffset, err := dcf.decodeRebaseTarget(dcf.PointerFormat, 0, addr, preferredLoadAddress)
	return targetRuntimeOffset, err == nil
}

func (dcf *DyldChainedFixups) IsBind(addr uint64) (*DcfImport, int64, bool) {
	if err := dcf.EnsureImports(); err != nil {
		return nil, 0, false
	}
	if len(dcf.Imports) == 0 {
		return nil, 0, false
	}

	switch dcf.PointerFormat {
	case DYLD_CHAINED_PTR_ARM64E:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		fallthrough
	case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if !DcpArm64eIsBind(addr) {
			return nil, 0, false
		}
		if DcpArm64eIsAuth(addr) { // is auth-bind
			if dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
				ord := DyldChainedPtrArm64eAuthBind24{Pointer: addr}.Ordinal()
				if ord > uint64(len(dcf.Imports)-1) {
					return nil, 0, false // OOB
				}
				return &dcf.Imports[ord], int64(dcf.Imports[ord].Addend()), true
			}
			ord := DyldChainedPtrArm64eAuthBind{Pointer: addr}.Ordinal()
			if ord > uint64(len(dcf.Imports)-1) {
				return nil, 0, false // OOB
			}
			return &dcf.Imports[ord], int64(dcf.Imports[ord].Addend()), true
		}
		if dcf.PointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24 {
			ord := DyldChainedPtrArm64eBind24{Pointer: addr}.Ordinal()
			if ord > uint64(len(dcf.Imports)-1) {
				return nil, 0, false // OOB
			}
			bind := DyldChainedPtrArm64eBind24{Pointer: addr, ImportAddend: int64(dcf.Imports[ord].Addend())}
			return &dcf.Imports[ord], bind.SignExtendedAddend(), true
		}
		ord := DyldChainedPtrArm64eBind{Pointer: addr}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		bind := DyldChainedPtrArm64eBind{Pointer: addr, ImportAddend: int64(dcf.Imports[ord].Addend())}
		return &dcf.Imports[ord], bind.SignExtendedAddend(), true
	case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET:
		if !Generic64IsBind(addr) {
			return nil, 0, false
		}
		ord := DyldChainedPtr64Bind{Pointer: addr}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		bind := DyldChainedPtr64Bind{Pointer: addr, ImportAddend: int64(dcf.Imports[ord].Addend())}
		return &dcf.Imports[ord], bind.SignedAddend(), true
	case DYLD_CHAINED_PTR_32:
		if !Generic32IsBind(uint32(addr)) {
			return nil, 0, false
		}
		ord := DyldChainedPtr32Bind{Pointer: uint32(addr)}.Ordinal()
		if ord > uint64(len(dcf.Imports)-1) {
			return nil, 0, false // OOB
		}
		bind := DyldChainedPtr32Bind{Pointer: uint32(addr), ImportAddend: int64(dcf.Imports[ord].Addend())}
		return &dcf.Imports[ord], bind.SignedAddend(), true
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE,
		DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE,
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
		DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3,
		DYLD_CHAINED_PTR_SHARED_CACHE_V2:
		return nil, 0, false
	default:
		return nil, 0, false
	}
}

// LookupByTarget returns all fixups with the given format-specific encoded
// Rebase.Target(). Resolving that target to a VM address requires the format's
// base/slide context and is intentionally a separate operation.
// This only includes rebases (including auth rebases), not binds.
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) LookupByTarget(targetOffset uint64) []Fixup {
	if err := dcf.ensureChainsParsed(); err != nil {
		return nil
	}

	if dcf.fixups == nil {
		return nil
	}

	if fixups := dcf.fixups[targetOffset]; len(fixups) != 0 {
		return append([]Fixup(nil), fixups...)
	}
	return nil
}

// LookupByOffset returns the fixup at the given file offset (where the fixup is located).
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) LookupByOffset(fileOffset uint64) (Fixup, bool) {
	if err := dcf.ensureChainsParsed(); err != nil {
		return nil, false
	}

	if dcf.Starts == nil {
		return nil, false
	}

	// Search through all segments
	for _, seg := range dcf.Starts {
		for _, fixup := range seg.Fixups {
			if fixup.Offset() == fileOffset {
				return fixup, true
			}
		}
	}
	return nil, false
}

// GetAuthRebase returns the auth rebase at the given target, if it exists.
// This is useful for quickly checking if a pointer is authenticated and getting its diversity.
// Note: This requires the chains to be walked first (calls Parse if needed).
func (dcf *DyldChainedFixups) GetAuthRebase(targetOffset uint64) (Auth, bool) {
	if err := dcf.ensureChainsParsed(); err != nil {
		return nil, false
	}

	for _, fixup := range dcf.fixups[targetOffset] {
		if auth, ok := fixup.(Auth); ok {
			if kernelAuth, ok := fixup.(interface{ IsAuth() uint64 }); ok && kernelAuth.IsAuth() == 0 {
				continue
			}
			return auth, true
		}
	}
	return nil, false
}

func (dcf *DyldChainedFixups) GetFixupAtOffset(offset uint64) (Fixup, error) {
	// Ensure metadata is parsed
	if err := dcf.ParseStarts(); err != nil {
		return nil, fmt.Errorf("failed to parse starts: %w", err)
	}

	// Ensure imports are available for bind fixups
	if err := dcf.EnsureImports(); err != nil {
		return nil, fmt.Errorf("failed to ensure imports: %w", err)
	}

	// Find the segment and page start for this offset
	start, pageStart, err := dcf.locateStartForOffset(offset)
	if err != nil {
		if dcf.findSegmentForOffset(offset) == nil {
			return nil, ErrNoFixupAtOffset
		}
		return nil, fmt.Errorf("failed to locate start for offset %#x: %w", offset, err)
	}

	// If page has no fixups, this offset can't contain a fixup
	if pageStart == DYLD_CHAINED_PTR_START_NONE {
		return nil, ErrNoFixupAtOffset
	}

	if pointerSize(start.PointerFormat) == 0 {
		return nil, fmt.Errorf("unsupported pointer format %d", start.PointerFormat)
	}

	// Calculate page boundaries
	pageSize := uint64(start.PageSize)
	segStart := start.SegmentOffset
	pageIndex := (offset - segStart) / pageSize
	pageContentStart := segStart + pageIndex*pageSize
	offsetInPage := offset - pageContentStart

	// Check if this offset could be part of a chain based on stride alignment
	strideVal, ok := stride(start.PointerFormat)
	if !ok {
		return nil, fmt.Errorf("unsupported pointer chain format: %d", start.PointerFormat)
	}
	if offsetInPage%strideVal != 0 {
		return nil, ErrNoFixupAtOffset
	}

	chainStarts, err := chainStartsForPage(start, pageStart)
	if err != nil {
		return nil, err
	}
	for _, chainStart := range chainStarts {
		if found, fixup, err := dcf.checkChainForOffset(start, pageContentStart, uint64(chainStart), offsetInPage); err != nil {
			return nil, err
		} else if found {
			return fixup, nil
		}
	}

	return nil, ErrNoFixupAtOffset
}

// checkChainForOffset walks a single chain to see if it contains the target offset.
// Returns (true, fixup, nil) if found, (false, nil, nil) if not found, or (false, nil, err) on error.
func (dcf *DyldChainedFixups) checkChainForOffset(start *DyldChainedStarts, pageContentStart, chainStartOffset, targetOffsetInPage uint64) (bool, Fixup, error) {
	currentOffset := chainStartOffset
	strideVal, ok := stride(start.PointerFormat)
	if !ok {
		return false, nil, fmt.Errorf("unsupported pointer chain format: %d", start.PointerFormat)
	}

	for {
		fixupLocation, err := checkedChainFixupLocation(start, pageContentStart, currentOffset)
		if err != nil {
			return false, nil, err
		}
		// Check if we've reached our target offset
		if currentOffset == targetOffsetInPage {
			// Read and decode the fixup at this location
			fixup, err := dcf.readAndDecodeFixup(start.PointerFormat, fixupLocation)
			return true, fixup, err
		}

		// Read the current pointer to get the next offset
		raw, err := dcf.readRawPointer(start.PointerFormat, fixupLocation)
		if err != nil {
			return false, nil, fmt.Errorf("failed to read pointer at %#x: %w", fixupLocation, err)
		}

		// Calculate next offset based on pointer format
		var next uint64
		switch start.PointerFormat {
		case DYLD_CHAINED_PTR_32:
			next = Generic32Next(uint32(raw))
		case DYLD_CHAINED_PTR_32_CACHE:
			next = uint64(DyldChainedPtr32CacheRebase{Pointer: uint32(raw)}.Next())
		case DYLD_CHAINED_PTR_32_FIRMWARE:
			next = uint64(DyldChainedPtr32FirmwareRebase{Pointer: uint32(raw)}.Next())
		case DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			next = Generic64Next(raw)
		case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24,
			DYLD_CHAINED_PTR_ARM64E_KERNEL, DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
			next = DcpArm64eNext(raw)
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
			if raw>>63 != 0 {
				next = DyldChainedPtrArm64eSharedCacheAuthRebase{Pointer: raw}.Next()
			} else {
				next = DyldChainedPtrArm64eSharedCacheRebase{Pointer: raw}.Next()
			}
		case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3:
			if raw>>63 != 0 {
				next = DyldChainedPtrArm64eSharedCacheV3AuthRebase{Pointer: raw}.Next()
			} else {
				next = DyldChainedPtrArm64eSharedCacheV3Rebase{Pointer: raw}.Next()
			}
		case DYLD_CHAINED_PTR_SHARED_CACHE_V2:
			next = DyldChainedPtrSharedCacheV2Rebase{Pointer: raw}.Next()
		case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
			if raw>>63 != 0 {
				next = DyldChainedPtrArm64eAuthSegmentedRebase{Pointer: raw}.Next()
			} else {
				next = DyldChainedPtrArm64eSegmentedRebase{Pointer: raw}.Next()
			}
		default:
			return false, nil, fmt.Errorf("unsupported pointer format %d", start.PointerFormat)
		}

		// If next is 0, we've reached the end of the chain
		if next == 0 {
			break
		}

		// Move to next fixup in chain
		step := next * strideVal
		if currentOffset > ^uint64(0)-step {
			return false, nil, errors.New("chained-fixup offset overflows")
		}
		currentOffset += step

		// The encoded pointer may straddle the page; only its start follows
		// page/next semantics.  checkedChainFixupLocation enforces the complete
		// segment range before the next read.
		if currentOffset > uint64(start.PageSize) {
			break
		}
	}

	return false, nil, nil
}

// readAndDecodeFixup reads the raw pointer at the given location and decodes it into the appropriate Fixup type.
func (dcf *DyldChainedFixups) readAndDecodeFixup(format DCPtrKind, fixupLocation uint64) (Fixup, error) {
	raw, err := dcf.readRawPointer(format, fixupLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw pointer: %w", err)
	}
	if err := dcf.validateBindOrdinal(format, raw, fixupLocation); err != nil {
		return nil, err
	}

	// Decode based on pointer format
	switch format {
	case DYLD_CHAINED_PTR_32:
		ptr32 := uint32(raw)
		if Generic32IsBind(ptr32) {
			bind := DyldChainedPtr32Bind{Pointer: ptr32, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}
		return DyldChainedPtr32Rebase{Pointer: ptr32, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_32_CACHE:
		return DyldChainedPtr32CacheRebase{Pointer: uint32(raw), Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_32_FIRMWARE:
		return DyldChainedPtr32FirmwareRebase{Pointer: uint32(raw), Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64:
		if Generic64IsBind(raw) {
			bind := DyldChainedPtr64Bind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}
		return DyldChainedPtr64Rebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64_OFFSET:
		if Generic64IsBind(raw) {
			bind := DyldChainedPtr64Bind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}
		return DyldChainedPtr64RebaseOffset{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		return DyldChainedPtr64KernelCacheRebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_ARM64E_KERNEL:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else {
			bind := DyldChainedPtrArm64eAuthBind{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
		if !DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eAuthBind24{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		} else if !DcpArm64eIsBind(raw) && DcpArm64eIsAuth(raw) {
			return DyldChainedPtrArm64eAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		} else if DcpArm64eIsBind(raw) && !DcpArm64eIsAuth(raw) {
			bind := DyldChainedPtrArm64eBind24{Pointer: raw, Fixup: fixupLocation}
			if ord := bind.Ordinal(); ord < uint64(len(dcf.Imports)) {
				bind.Import = dcf.Imports[ord].Name
				bind.ImportAddend = int64(dcf.Imports[ord].Addend())
			}
			return bind, nil
		}

	case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
		if raw>>63 != 0 {
			return DyldChainedPtrArm64eSharedCacheAuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		}
		return DyldChainedPtrArm64eSharedCacheRebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3:
		if raw>>63 != 0 {
			return DyldChainedPtrArm64eSharedCacheV3AuthRebase{Pointer: raw, Fixup: fixupLocation}, nil
		}
		return DyldChainedPtrArm64eSharedCacheV3Rebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_SHARED_CACHE_V2:
		return DyldChainedPtrSharedCacheV2Rebase{Pointer: raw, Fixup: fixupLocation}, nil

	case DYLD_CHAINED_PTR_ARM64E_SEGMENTED:
		if raw>>63 != 0 {
			return DyldChainedPtrArm64eAuthSegmentedRebase{Pointer: raw, Fixup: fixupLocation}, nil
		}
		return DyldChainedPtrArm64eSegmentedRebase{Pointer: raw, Fixup: fixupLocation}, nil

	default:
		return nil, fmt.Errorf("unsupported pointer format %d for fixup decoding", format)
	}

	return nil, fmt.Errorf("failed to decode fixup for format %d", format)
}

// IsVMOffsetFormat reports whether decodeRebaseTarget produces a runtime
// offset rather than consuming a raw absolute vmaddr. Shared-cache formats
// produce offsets relative to the explicitly configured shared-cache base.
func (dcf *DyldChainedFixups) IsVMOffsetFormat() bool {
	switch dcf.PointerFormat {
	case DYLD_CHAINED_PTR_32_CACHE,
		DYLD_CHAINED_PTR_64_OFFSET,
		DYLD_CHAINED_PTR_ARM64E_KERNEL,
		DYLD_CHAINED_PTR_ARM64E_USERLAND,
		DYLD_CHAINED_PTR_ARM64E_USERLAND24,
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
		DYLD_CHAINED_PTR_ARM64E_SEGMENTED,
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3,
		DYLD_CHAINED_PTR_SHARED_CACHE_V2,
		DYLD_CHAINED_PTR_64_KERNEL_CACHE,
		DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
		return true
	default:
		return false
	}
}

func (dcf *DyldChainedFixups) resolveRawRebaseVMAddress(format DCPtrKind, offset, raw, preferredLoadAddress, slide uint64) (uint64, error) {
	if format == DYLD_CHAINED_PTR_32 {
		if value, ok := dcf.decode32NonPointer(offset, uint32(raw)); ok {
			return value, nil
		}
	}
	if format == DYLD_CHAINED_PTR_64_KERNEL_CACHE || format == DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE {
		kernelRebase := DyldChainedPtr64KernelCacheRebase{Pointer: raw, Fixup: offset}
		return dcf.resolveKernelCacheTarget(kernelRebase, preferredLoadAddress, slide)
	}
	runtimeOffset, err := dcf.decodeRebaseTarget(format, offset, raw, preferredLoadAddress)
	if err != nil {
		return 0, err
	}
	baseAddress := preferredLoadAddress
	if isSharedCachePointerFormat(format) {
		baseAddress, err = dcf.requireSharedCacheBase(format)
		if err != nil {
			return 0, err
		}
		// Slide-info v2 preserves encoded NULL values instead of adding the
		// cache base and slide to them.
		if format == DYLD_CHAINED_PTR_SHARED_CACHE_V2 && runtimeOffset == 0 {
			return 0, nil
		}
	}
	if runtimeOffset > ^uint64(0)-baseAddress {
		return 0, fmt.Errorf("pointer format %d base %#x plus runtime offset %#x overflows", format, baseAddress, runtimeOffset)
	}
	target := baseAddress + runtimeOffset
	if slide > ^uint64(0)-target {
		return 0, fmt.Errorf("pointer format %d target %#x plus slide %#x overflows", format, target, slide)
	}
	return target + slide, nil
}

// ResolveRawRebaseVMAddress returns the final in-memory value represented by
// raw rebase bits using the uniform PointerFormat parsed from the starts table.
// The caller must already have established that the pointer slot is an actual
// chained fixup; location-aware code should use GetFixupAtOffset followed by
// ResolveRebaseVMAddress.
func (dcf *DyldChainedFixups) ResolveRawRebaseVMAddress(raw, preferredLoadAddress, slide uint64) (uint64, error) {
	if dcf.PointerFormat == 0 {
		if err := dcf.ParseStarts(); err != nil {
			return 0, fmt.Errorf("parse chained pointer format: %w", err)
		}
	}
	if dcf.PointerFormat == 0 {
		return 0, errors.New("chained pointer format is unavailable")
	}
	return dcf.resolveRawRebaseVMAddress(dcf.PointerFormat, 0, raw, preferredLoadAddress, slide)
}

// ResolveRebaseVMAddress returns the final in-memory value represented by a
// chained rebase. This is an address for pointer rebases and the restored scalar
// for a co-opted format-3 non-pointer. It uses the raw encoding so high8 and
// authenticated/segmented semantics cannot be lost through Rebase.Target.
func (dcf *DyldChainedFixups) ResolveRebaseVMAddress(rebase Rebase, preferredLoadAddress uint64, slide uint64) (uint64, error) {
	format := dcf.pointerFormatForRebase(rebase)
	return dcf.resolveRawRebaseVMAddress(format, rebase.Offset(), rebase.Raw(), preferredLoadAddress, slide)
}

func (dcf *DyldChainedFixups) pointerFormatForRebase(rebase Rebase) DCPtrKind {
	if start := dcf.findSegmentForOffset(rebase.Offset()); start != nil {
		return start.PointerFormat
	}
	switch rebase.(type) {
	case DyldChainedPtrArm64eSharedCacheRebase, DyldChainedPtrArm64eSharedCacheAuthRebase:
		return DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE
	case DyldChainedPtrArm64eSharedCacheV3Rebase, DyldChainedPtrArm64eSharedCacheV3AuthRebase:
		return DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE_V3
	case DyldChainedPtrSharedCacheV2Rebase:
		return DYLD_CHAINED_PTR_SHARED_CACHE_V2
	default:
		return dcf.PointerFormat
	}
}

// GetRebaseVMAddress is retained for compatibility. New loader code should use
// ResolveRebaseVMAddress so malformed or unsupported encodings are not turned
// into address zero silently.
func (dcf *DyldChainedFixups) GetRebaseVMAddress(rebase Rebase, preferredLoadAddress uint64, slide uint64) uint64 {
	target, _ := dcf.ResolveRebaseVMAddress(rebase, preferredLoadAddress, slide)
	return target
}
