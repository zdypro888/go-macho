package codesign

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zdypro888/go-macho/pkg/codesign/types"
)

const (
	robustnessAllocBound = 256 << 20
	robustnessTimeBound  = 20 * time.Second
)

// bounded runs fn and fails the test if it allocates or takes too much.
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

// sharedRequirementsSignature builds an embedded signature whose requirements
// vector has count index entries that all point at the same inner blob, an
// `identifier "aaa..."` expression with an identLen byte string.
func sharedRequirementsSignature(t *testing.T, count, identLen uint32) []byte {
	t.Helper()
	const (
		superHeader = uint32(12 + 8) // SuperBlob header + one index entry
		vecHeader   = uint32(12)
	)
	innerLen := 12 + 4 + 4 + (identLen+3)&^3
	innerOff := vecHeader + count*8
	vecLen := innerOff + innerLen

	var sig bytes.Buffer
	writeBigEndian(t, &sig, types.SbHeader{Magic: types.MAGIC_EMBEDDED_SIGNATURE, Length: superHeader + vecLen, Count: 1})
	writeBigEndian(t, &sig, types.BlobIndex{Type: types.CSSLOT_REQUIREMENTS, Offset: superHeader})
	writeBigEndian(t, &sig, types.RequirementsBlob{Magic: types.MAGIC_REQUIREMENTS, Length: vecLen, Data: count})
	for range count {
		writeBigEndian(t, &sig, types.Requirements{Type: types.DesignatedRequirementType, Offset: innerOff})
	}
	writeBigEndian(t, &sig, types.RequirementsBlob{Magic: types.MAGIC_REQUIREMENT, Length: innerLen, Data: 1})
	writeBigEndian(t, &sig, uint32(2)) // opIdent
	writeBigEndian(t, &sig, identLen)
	sig.Write(bytes.Repeat([]byte{'a'}, int((identLen+3)&^3)))
	return sig.Bytes()
}

// A 1 MiB signature used to make the parser format the same 1 MiB requirement
// once per index entry and keep every copy: 2000 entries cost several GiB,
// 100000 entries took the machine down.
func TestParseRequirementsSlotBoundsSharedInnerBlobs(t *testing.T) {
	sig := sharedRequirementsSignature(t, 2000, 1<<20)
	bounded(t, func() {
		_, err := ParseCodeSignature(sig)
		if err == nil || !strings.Contains(err.Error(), "parse budget") {
			t.Errorf("ParseCodeSignature error = %v, want parse budget error", err)
		}
	})

	t.Run("sharing below the budget still parses", func(t *testing.T) {
		cs, err := ParseCodeSignature(sharedRequirementsSignature(t, 3, 16))
		if err != nil {
			t.Fatalf("ParseCodeSignature: %v", err)
		}
		if len(cs.Requirements) != 3 {
			t.Fatalf("got %d requirements, want 3", len(cs.Requirements))
		}
		for _, req := range cs.Requirements {
			if req.Detail != `identifier aaaaaaaaaaaaaaaa` {
				t.Fatalf("unexpected detail %q", req.Detail)
			}
		}
	})
}

// Every 32-bit field of a small but complete signature is replaced by hostile
// values. None of them may panic or allocate by the field's value.
func TestParseCodeSignatureSurvivesHostileFields(t *testing.T) {
	cd := makeCodeDirectoryBlob(t, types.CdEarliest{
		Version:  types.EARLIEST_VERSION,
		HashType: types.HASHTYPE_SHA256,
	})
	reqs := makeRequirementsVector(t)
	ent := []byte("<plist/>")
	const superHeader = uint32(12 + 3*8)
	cdOff := superHeader
	reqOff := cdOff + uint32(len(cd))
	entOff := reqOff + uint32(len(reqs))
	total := entOff + 8 + uint32(len(ent))

	var sig bytes.Buffer
	writeBigEndian(t, &sig, types.SbHeader{Magic: types.MAGIC_EMBEDDED_SIGNATURE, Length: total, Count: 3})
	writeBigEndian(t, &sig, []types.BlobIndex{
		{Type: types.CSSLOT_CODEDIRECTORY, Offset: cdOff},
		{Type: types.CSSLOT_REQUIREMENTS, Offset: reqOff},
		{Type: types.CSSLOT_ENTITLEMENTS, Offset: entOff},
	})
	sig.Write(cd)
	sig.Write(reqs)
	writeBigEndian(t, &sig, types.BlobHeader{Magic: types.MAGIC_EMBEDDED_ENTITLEMENTS, Length: 8 + uint32(len(ent))})
	sig.Write(ent)
	seed := sig.Bytes()
	if _, err := ParseCodeSignature(seed); err != nil {
		t.Fatalf("seed signature does not parse: %v", err)
	}

	hostile := []uint32{0xffffffff, 0xfffffff0, 0x80000000, 0x7fffffff, 0x40000000, 0x00ffffff, 0}
	bounded(t, func() {
		for off := 0; off+4 <= len(seed); off++ {
			for _, v := range hostile {
				data := bytes.Clone(seed)
				binary.BigEndian.PutUint32(data[off:], v)
				ParseCodeSignature(data)
			}
		}
		for n := range seed {
			ParseCodeSignature(seed[:n])
		}
	})
}
