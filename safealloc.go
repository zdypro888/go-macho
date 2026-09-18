package macho

import (
	"encoding/binary"
	"fmt"
	"io"
	"regexp"

	"github.com/zdypro888/go-macho/internal/saferio"
	"github.com/zdypro888/go-macho/types"
)

// Helpers that keep sizes and counts read from an (untrusted) Mach-O from
// turning directly into huge allocations.
//
// The invariant all of them keep: whenever the original "make + read" sequence
// would have succeeded, they return exactly the same bytes/values and leave the
// reader at the same position. They only change what happens when that read was
// going to fail anyway (truncated/corrupt input): the failure is now reported
// before (or without) allocating the attacker controlled amount of memory.

const (
	// safeAllocChunk is the amount of memory we are willing to allocate up
	// front on the word of a size field alone. Below it the historical code
	// path (one make, one read) is used verbatim.
	safeAllocChunk = 10 << 20
	// safeProbeThreshold is the byte total above which checkReadCount
	// verifies, for readers without a known length, that the data exists.
	safeProbeThreshold = 1 << 20
	// maxSwiftContextDepth bounds the parent chain walked by getContextDesc.
	// Cycles are detected exactly; this only stops absurdly long acyclic
	// chains, so it is far above any real lexical nesting depth.
	maxSwiftContextDepth = 1024
)

// readDataFrom replaces
//
//	dat := make([]byte, n)
//	err := binary.Read(r, order, dat)
//
// for a size n taken from the file.
func readDataFrom(r io.Reader, n uint64, dat *[]byte) error {
	if n < safeAllocChunk {
		buf := make([]byte, n)
		*dat = buf
		return binary.Read(r, binary.LittleEndian, buf)
	}
	buf, err := saferio.ReadData(r, n)
	if err != nil {
		return err
	}
	*dat = clipCap(buf)
	return nil
}

// clipCap makes cap(b) == len(b), as it is for a slice that came straight from
// make([]byte, n). GetCStrings derives string addresses from bytes.Buffer.Cap.
func clipCap(b []byte) []byte {
	return b[:len(b):len(b)]
}

// readDataAt replaces
//
//	dat := make([]byte, n)
//	_, err := r.ReadAt(dat, off)
//
// for a size n taken from the file.
func readDataAt(r io.ReaderAt, n uint64, off int64) ([]byte, error) {
	if n < safeAllocChunk {
		buf := make([]byte, n)
		_, err := r.ReadAt(buf, off)
		return buf, err
	}
	buf, err := saferio.ReadDataAt(r, n, off)
	return clipCap(buf), err
}

// readDataAtAddr is readDataAt for MachoReader.ReadAtAddr.
func readDataAtAddr(r types.MachoReader, n uint64, addr uint64) ([]byte, error) {
	if n < safeAllocChunk {
		buf := make([]byte, n)
		_, err := r.ReadAtAddr(buf, addr)
		return buf, err
	}
	buf, err := saferio.ReadDataAt(&addrReaderAt{r: r, addr: addr}, n, 0)
	return clipCap(buf), err
}

// checkReadCount reports an error when count elements, each occupying at least
// elemSize bytes in the file, cannot be read sequentially from r's current
// position. It must be called right before a `make([]T, count)` whose elements
// are then read from r; if it fails, that read was going to hit EOF.
//
// r is inspected dynamically: readers that know their remaining length
// (*bytes.Reader, ...) are checked exactly; seekable io.ReaderAt readers (the
// MachoReader) are probed for the last byte, but only for large totals so the
// common path is untouched; anything else is let through.
func checkReadCount(r any, count uint64, elemSize uint64) error {
	if count == 0 || elemSize == 0 {
		return nil
	}
	if count > (1<<63-1)/elemSize {
		return fmt.Errorf("implausible element count %d: %w", count, io.ErrUnexpectedEOF)
	}
	total := count * elemSize
	if lr, ok := r.(interface{ Len() int }); ok {
		if remaining := uint64(lr.Len()); total > remaining {
			if remaining == 0 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if total <= safeProbeThreshold {
		return nil
	}
	ra, ok := r.(io.ReaderAt)
	if !ok {
		return nil
	}
	sk, ok := r.(io.Seeker)
	if !ok {
		return nil
	}
	cur, err := sk.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil
	}
	if uint64(cur) > (1<<63-1)-total {
		return fmt.Errorf("implausible element count %d: %w", count, io.ErrUnexpectedEOF)
	}
	var b [1]byte
	if n, _ := ra.ReadAt(b[:], cur+int64(total)-1); n != 1 {
		return fmt.Errorf("implausible element count %d: %w", count, io.ErrUnexpectedEOF)
	}
	return nil
}

// Compiled once instead of on every loop iteration in swift.go.
var (
	swiftObjCPrefixRE    = regexp.MustCompile("So[0-9]+")
	swiftLeadingDigitsRE = regexp.MustCompile("^[0-9]+")
)
