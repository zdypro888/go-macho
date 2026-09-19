package macho

import "testing"

func TestFindSymbolAddressPrefersExactCase(t *testing.T) {
	f := &File{}
	f.Symtab = &Symtab{Syms: []Symbol{
		{Name: "_value_A", Value: 0x100004000},
		{Name: "_value_a", Value: 0x100004004},
		{Name: "_OnlyUpper", Value: 0x100004008},
	}}
	for _, test := range []struct {
		name string
		want uint64
	}{
		{"_value_A", 0x100004000},
		{"_value_a", 0x100004004}, // used to return _value_A
		// no exact match: the historical case-insensitive lookup still applies
		{"_onlyupper", 0x100004008},
		{"_VALUE_A", 0x100004000},
	} {
		got, err := f.FindSymbolAddress(test.name)
		if err != nil || got != test.want {
			t.Errorf("%s: got %#x err %v, want %#x", test.name, got, err, test.want)
		}
	}
	if _, err := f.FindSymbolAddress("_missing"); err == nil {
		t.Error("missing symbol: expected an error")
	}
}
