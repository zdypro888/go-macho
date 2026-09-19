package macho

import (
	"reflect"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

func TestReviewBindIndexAfterPublicSliceEdit(t *testing.T) {
	for _, target := range []uint64{2, 4} {
		f := &File{Loads: []Load{&DyldInfoOnly{}}, binds: types.Binds{
			{Name: "_first", Start: 1}, {Name: "_second", Start: 2},
		}, bindsDone: true}
		for i := 0; i <= bindIndexAfterLookups; i++ {
			_, _ = f.GetBindName(2)
		}
		binds, err := f.GetBindInfo()
		if err != nil {
			t.Fatal(err)
		}
		binds[0].Start = target
		got, err := f.GetBindName(target)
		if err != nil || got != "_first" {
			t.Errorf("target %d: got %q, %v; want first bind", target, got, err)
		}
	}
}

func TestReviewSymbolIndexesAfterInPlaceEdits(t *testing.T) {
	for _, scenario := range []string{"new name", "earlier duplicate", "address order"} {
		t.Run(scenario, func(t *testing.T) {
			f := &File{Symtab: &Symtab{Syms: []Symbol{{Name: "_a", Value: 1}, {Name: "_b", Value: 2}, {Name: "_c", Value: 3}}}}
			for i := 0; i <= lookupIndexThreshold; i++ {
				_, _ = f.FindSymbolAddress("_b")
				_, _ = f.FindSymbolAddress("_B")
				_, _ = f.FindAddressSymbols(3)
			}
			switch scenario {
			case "new name":
				f.Symtab.Syms[0].Name = "_new"
				got, err := f.FindSymbolAddress("_new")
				if got != 1 || err != nil {
					t.Fatalf("new name: %#x %v", got, err)
				}
			case "earlier duplicate":
				f.Symtab.Syms[0].Name = "_b"
				got, err := f.FindSymbolAddress("_b")
				if got != 1 || err != nil {
					t.Fatalf("first duplicate: %#x %v", got, err)
				}
			case "address order":
				f.Symtab.Syms[0].Value = 3
				got, err := f.FindAddressSymbols(3)
				want, wantErr := f.findAddressSymbolsLinear(3)
				if errString(err) != errString(wantErr) || !reflect.DeepEqual(got, want) {
					t.Fatalf("got %v %v, want %v %v", got, err, want, wantErr)
				}
			}
		})
	}
}
