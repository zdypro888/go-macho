package swift

import "testing"

func TestFieldRecordFlagsStringKeepsAllFlags(t *testing.T) {
	for flags, want := range map[FieldRecordFlags]string{0: "let", IsVar: "var", IsIndirectCase: "indirect case | let", IsArtificial | IsVar: "artificial | var", IsIndirectCase | IsArtificial | IsVar: "indirect case | artificial | var"} {
		if got := flags.String(); got != want {
			t.Errorf("%d: got %q, want %q", flags, got, want)
		}
	}
}
