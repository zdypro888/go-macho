package cpio

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"testing"
	"time"
)

func odcEntry(name string, mode uint32, body []byte) []byte {
	hdr := fmt.Sprintf("%s%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
		Magic, 1, 2, mode, 0, 0, 1, 0, 0, len(name)+1, len(body))
	return append(append([]byte(hdr+name), 0), body...)
}

// The name size is the only length the reader allocates by. Whatever the six
// header bytes hold and whatever archive size the caller claims, the reader
// has to come back quickly with a small allocation and without panicking.
func TestReaderBoundsHeaderSizes(t *testing.T) {
	good := append(odcEntry("./a", 0100644, []byte("hello")), odcEntry(Trailer, 0, nil)...)
	r, err := NewReader(bytes.NewReader(good), int64(len(good)))
	if err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	if f := r.Files["/a"]; f == nil || f.Size != 5 {
		t.Fatalf("unexpected files: %+v", r.Files)
	}

	// parseOctal of six arbitrary bytes stays below 10 MiB, so that is the most
	// a single hostile header can make the reader allocate.
	const perCallBound = 16 << 20
	start := time.Now()
	parse := func(data []byte, claimed int64) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		NewReader(bytes.NewReader(data), claimed)
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > perCallBound {
			t.Fatalf("allocated %d MiB for a %d byte archive", alloc>>20, len(data))
		}
	}
	for _, claimed := range []int64{int64(len(good)), math.MaxInt64} {
		for off := 0; off < hdrSize; off++ {
			for _, b := range []byte{0x00, '7', '8', 0x2f, 0xff} {
				data := bytes.Clone(good)
				// Fill the header from off to its end so that multi-byte
				// size fields reach their extreme values.
				for i := off; i < hdrSize; i++ {
					data[i] = b
				}
				parse(data, claimed)
			}
		}
		for n := range good {
			parse(good[:n], claimed)
		}
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}
