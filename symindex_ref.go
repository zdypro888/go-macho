package macho

import (
	"fmt"
	"strings"
)

// The linear scans FindSymbolAddress and FindAddressSymbols used before they
// were indexed, kept verbatim. They define the behaviour the indexes in
// symindex.go must reproduce (the equivalence tests compare against them) and
// they answer whenever an index turns out to be stale.

func (f *File) findSymbolAddressLinear(symbol string) (uint64, error) {
	if f.Symtab == nil {
		return 0, &FormatError{0, "missing symbol table", nil}
	}
	// 行为变更说明: Mach-O 符号名区分大小写，以前全部用 strings.EqualFold 比较，
	// 同时存在 _value_A 和 _value_a 时，查 _value_a 会返回排在前面的 _value_A；
	// chained fixup 的 self-bind 靠这个函数解析，指针因此可能指向错误的符号。
	// 现在精确匹配优先（先符号表、再导出表）；完全没有精确匹配时才退回原来的
	// 不区分大小写匹配，且顺序与以前相同，所以以前能解析出来的名字现在仍然能解析。
	var (
		foldAddr  uint64
		foldFound bool
	)
	for _, sym := range f.Symtab.Syms {
		if sym.Name == symbol {
			return sym.Value, nil
		}
		if !foldFound && strings.EqualFold(sym.Name, symbol) {
			foldAddr, foldFound = sym.Value, true
		}
	}
	exports, err := f.GetExports()
	if err != nil {
		if err != ErrMachODyldInfoNotFound {
			if foldFound {
				// the previous code returned the symbol-table match before
				// ever looking at the exports
				return foldAddr, nil
			}
			return 0, fmt.Errorf("failed to get exports: %v", err)
		}
	}
	for _, sym := range exports {
		if sym.Name == symbol {
			return sym.Address, nil
		}
		if !foldFound && strings.EqualFold(sym.Name, symbol) {
			foldAddr, foldFound = sym.Address, true
		}
	}
	if foldFound {
		return foldAddr, nil
	}
	return 0, fmt.Errorf("symbol not found in macho symtab")
}

func (f *File) findAddressSymbolsLinear(addr uint64) ([]Symbol, error) {
	if f.Symtab == nil {
		return nil, &FormatError{0, "missing symbol table", nil}
	}
	var syms []Symbol
	for _, sym := range f.Symtab.Syms {
		if sym.Value == addr {
			syms = append(syms, sym)
		}
	}
	if f.DyldExportsTrie() != nil && f.DyldExportsTrie().Size > 0 {
		exports, err := f.DyldExports()
		if err != nil {
			return nil, fmt.Errorf("failed to get exports: %v", err)
		}
		for _, sym := range exports {
			if sym.Address == addr {
				syms = append(syms, Symbol{Name: sym.Name, Value: sym.Address})
			}
		}
	}
	if len(syms) > 0 {
		return syms, nil
	}
	return nil, fmt.Errorf("symbol(s) not found in macho symtab for addr %#x", addr)
}
