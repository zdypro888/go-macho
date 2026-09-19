package types

import (
	"strings"
	"testing"
	"time"
)

func derHeader(tag byte, length int) []byte {
	switch {
	case length < 0x80:
		return []byte{tag, byte(length)}
	case length < 1<<8:
		return []byte{tag, 0x81, byte(length)}
	case length < 1<<16:
		return []byte{tag, 0x82, byte(length >> 8), byte(length)}
	case length < 1<<24:
		return []byte{tag, 0x83, byte(length >> 16), byte(length >> 8), byte(length)}
	default:
		return []byte{tag, 0x84, byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
	}
}

// nestedConstraint returns depth launch constraint dictionaries nested inside
// each other: SEQUENCE { "k", [0] { SEQUENCE { "k", [0] { ... TRUE } } } }.
func nestedConstraint(depth int) []byte {
	key := []byte{0x0c, 0x01, 'k'}
	innermost := append(append(derHeader(0x30, len(key)+3), key...), 0x01, 0x01, 0xff)

	// Work out every level's length first so the blob can be emitted front to
	// back instead of being re-copied once per level.
	ctxLen := make([]int, depth+1)
	ctxLen[0] = len(innermost)
	for i := 1; i <= depth; i++ {
		seqLen := len(key) + len(derHeader(0xa0, ctxLen[i-1])) + ctxLen[i-1]
		ctxLen[i] = len(derHeader(0x30, seqLen)) + seqLen
	}
	out := make([]byte, 0, ctxLen[depth])
	for i := depth; i >= 1; i-- {
		seqLen := len(key) + len(derHeader(0xa0, ctxLen[i-1])) + ctxLen[i-1]
		out = append(out, derHeader(0x30, seqLen)...)
		out = append(out, key...)
		out = append(out, derHeader(0xa0, ctxLen[i-1])...)
	}
	return append(out, innermost...)
}

// Every nesting level costs about ten DER bytes and one parseReqs frame; a few
// dozen MiB of constraint data used to run the goroutine into the 1 GB stack
// limit, which is a fatal error that cannot be recovered.
func TestParseReqsBoundsNesting(t *testing.T) {
	ok, err := parseReqs(nestedConstraint(maxLaunchConstraintDepth))
	if err != nil {
		t.Fatalf("nesting at the limit must keep parsing: %v", err)
	}
	for range maxLaunchConstraintDepth {
		next, isMap := ok["k"].(map[string]any)
		if !isMap {
			t.Fatalf("unexpected value %T", ok["k"])
		}
		ok = next
	}
	if ok["k"] != true {
		t.Fatalf("innermost value = %v, want true", ok["k"])
	}

	data := nestedConstraint(4 << 20)
	start := time.Now()
	_, err = parseReqs(data)
	if err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("parseReqs error = %v, want nesting error", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}
