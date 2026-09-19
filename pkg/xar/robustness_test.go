package xar

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	robustnessAllocBound = 64 << 20
	robustnessTimeBound  = 10 * time.Second
)

// bounded runs fn and fails the test if it panics, allocates or takes too much.
func bounded(t *testing.T, fn func()) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		fn()
	}()
	select {
	case <-done:
	case <-time.After(robustnessTimeBound):
		t.Fatalf("did not finish within %v", robustnessTimeBound)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > robustnessAllocBound {
		t.Fatalf("allocated %d MiB (bound %d MiB) in %v", alloc>>20, robustnessAllocBound>>20, time.Since(start))
	}
}

// buildXar returns a SHA-1 checksummed archive with the given TOC. tocLenZlib
// and tocLenPlain override the header fields when non-zero.
func buildXar(t *testing.T, toc string, tocLenZlib, tocLenPlain uint64) []byte {
	t.Helper()
	var ztoc bytes.Buffer
	zw := zlib.NewWriter(&ztoc)
	if _, err := zw.Write([]byte(toc)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if tocLenZlib == 0 {
		tocLenZlib = uint64(ztoc.Len())
	}
	if tocLenPlain == 0 {
		tocLenPlain = uint64(len(toc))
	}
	hdr := make([]byte, xarHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:], xarHeaderMagic)
	binary.BigEndian.PutUint16(hdr[4:], xarHeaderSize)
	binary.BigEndian.PutUint16(hdr[6:], xarVersion)
	binary.BigEndian.PutUint64(hdr[8:], tocLenZlib)
	binary.BigEndian.PutUint64(hdr[16:], tocLenPlain)
	binary.BigEndian.PutUint32(hdr[24:], xarChecksumKindSHA1)
	sum := sha1.Sum(ztoc.Bytes())
	out := append(hdr, ztoc.Bytes()...)
	out = append(out, sum[:]...)
	return append(out, "payload"...)
}

func tocXML(checksumSize string, extra string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><xar><toc>` +
		`<checksum style="sha1"><offset>0</offset><size>` + checksumSize + `</size></checksum>` + extra +
		`<file id="1"><name>a</name><type>file</type><data><length>7</length><offset>20</offset><size>7</size>` +
		`<encoding style="application/octet-stream"/>` +
		`<archived-checksum style="sha1">00</archived-checksum><extracted-checksum style="sha1">00</extracted-checksum>` +
		`</data></file></toc></xar>`
}

func TestNewReaderBoundsSizesFromArchive(t *testing.T) {
	good := buildXar(t, tocXML("20", ""), 0, 0)
	r, err := NewReader(bytes.NewReader(good), int64(len(good)))
	if err != nil {
		t.Fatalf("seed archive does not parse: %v", err)
	}
	if len(r.Files) != 1 || r.Files[1].Name != "a" {
		t.Fatalf("unexpected files: %+v", r.Files)
	}

	sig := func(size string) string {
		return `<signature style="RSA"><offset>20</offset><size>` + size + `</size>` +
			`<KeyInfo><X509Data><X509Certificate>AAAA</X509Certificate></X509Data></KeyInfo></signature>`
	}
	tests := []struct {
		name    string
		archive []byte
		// sigErr is set when the archive itself stays readable and only
		// SignatureError reports the problem, as before.
		sigErr bool
	}{
		{"toc_len_zlib 1 TiB", buildXar(t, tocXML("20", ""), 1<<40, 0), false},
		{"toc_len_zlib 2^63", buildXar(t, tocXML("20", ""), 1<<63, 0), false},
		{"toc_len_zlib 2^64-1", buildXar(t, tocXML("20", ""), 1<<64-1, 0), false},
		{"checksum size 1 TiB", buildXar(t, tocXML(fmt.Sprint(1<<40), ""), 0, 0), false},
		{"checksum size 2^63-1", buildXar(t, tocXML(fmt.Sprint(uint64(1<<63-1)), ""), 0, 0), false},
		{"checksum size negative", buildXar(t, tocXML("-1", ""), 0, 0), false},
		{"signature size 1 TiB", buildXar(t, tocXML("20", sig(fmt.Sprint(1<<40))), 0, 0), true},
		{"signature size 2^63-1", buildXar(t, tocXML("20", sig(fmt.Sprint(uint64(1<<63-1)))), 0, 0), true},
		{"signature size negative", buildXar(t, tocXML("20", sig("-1")), 0, 0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bounded(t, func() {
				r, err := NewReader(bytes.NewReader(tt.archive), int64(len(tt.archive)))
				switch {
				case tt.sigErr && err != nil:
					t.Errorf("NewReader: %v", err)
				case tt.sigErr && r.SignatureError == nil:
					t.Error("SignatureError is nil")
				case !tt.sigErr && err == nil:
					t.Error("NewReader accepted the archive")
				}
			})
		})
	}
}

func TestNewReaderBoundsInflatedTOC(t *testing.T) {
	defer func(old uint64) { maxUncheckedTOC = old }(maxUncheckedTOC)
	maxUncheckedTOC = 1 << 20

	toc := tocXML("20", "")
	bomb := strings.Replace(toc, "<toc>", "<toc>"+strings.Repeat(" ", 8<<20), 1)

	// toc_len_plain tells the truth: parses no matter how large.
	honest := buildXar(t, bomb, 0, 0)
	if _, err := NewReader(bytes.NewReader(honest), int64(len(honest))); err != nil {
		t.Fatalf("honest large TOC: %v", err)
	}
	// toc_len_plain lies, but the TOC is below the unchecked limit: parses.
	small := buildXar(t, toc, 0, 1)
	if _, err := NewReader(bytes.NewReader(small), int64(len(small))); err != nil {
		t.Fatalf("small TOC with wrong toc_len_plain: %v", err)
	}
	// toc_len_plain lies and the TOC inflates past the limit: error.
	lying := buildXar(t, bomb, 0, 1)
	if _, err := NewReader(bytes.NewReader(lying), int64(len(lying))); err == nil {
		t.Fatal("NewReader inflated a TOC far beyond toc_len_plain")
	}
}
