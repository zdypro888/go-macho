package macho

import (
	"testing"

	"github.com/zdypro888/go-macho/types"
)

func TestConvertPointerWithoutChainedFixupsUsesCustomConverter(t *testing.T) {
	const (
		raw       = uint64(0x1234)
		converted = uint64(0x100001234)
	)

	f := &File{
		vma: &types.VMAddrConverter{
			Converter: func(value uint64) uint64 {
				if value != raw {
					t.Fatalf("converter received %#x, want %#x", value, raw)
				}
				return converted
			},
		},
		customVMAddrConverter: true,
	}

	if got := f.convertPointerWithoutChainedFixups(raw); got != converted {
		t.Fatalf("converted pointer = %#x, want %#x", got, converted)
	}
}
