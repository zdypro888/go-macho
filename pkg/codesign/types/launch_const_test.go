package types

import (
	"encoding/asn1"
	"testing"
)

func TestParseReqsKeepsSiblingsAfterCompoundValue(t *testing.T) {
	for _, key := range []string{"$in", "$query", "$and-array", "$or-array"} {
		t.Run(key, func(t *testing.T) {
			// Empty arrays exercise every nested-decoder branch without
			// depending on the individual operator's element representation.
			first, err := asn1.Marshal(contraint{Key: key, Val: asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true}})
			if err != nil {
				t.Fatal(err)
			}
			second, err := asn1.Marshal(contraint{Key: "after", Val: asn1.RawValue{Tag: asn1.TagBoolean, Bytes: []byte{0xff}}})
			if err != nil {
				t.Fatal(err)
			}
			reqs, err := parseReqs(append(first, second...))
			if err != nil {
				t.Fatal(err)
			}
			if reqs["after"] != true {
				t.Fatalf("lost sibling after %s: %#v", key, reqs)
			}
		})
	}
}
