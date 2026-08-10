package macho

import (
	"errors"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

func TestSwiftColocatedMetadataFunctionsAreExposedWithoutDescriptorDecoding(t *testing.T) {
	section := &types.Section{SectionHeader: types.SectionHeader{
		Seg:    "__TEXT",
		Name:   "__textg_swiftm",
		Addr:   0x100005000,
		Size:   0x1b4,
		Offset: 0x15b4,
		Flags:  types.Regular | types.PURE_INSTRUCTIONS,
	}}
	file := &File{FileTOC: FileTOC{Sections: []*types.Section{section}}}
	if !file.HasSwift() {
		t.Fatal("__textg_swiftm was not recognized as Swift content")
	}
	got, err := file.GetSwiftColocatedMetadataFunctions()
	if err != nil {
		t.Fatalf("GetSwiftColocatedMetadataFunctions: %v", err)
	}
	if got != section || got.Addr != section.Addr || got.Size != section.Size {
		t.Fatalf("section = %#v, want %#v", got, section)
	}
	if _, err := file.GetSwiftColocateMetadata(); !errors.Is(err, ErrSwiftColocatedMetadataFunctions) {
		t.Fatalf("legacy API error = %v, want ErrSwiftColocatedMetadataFunctions", err)
	}
}
