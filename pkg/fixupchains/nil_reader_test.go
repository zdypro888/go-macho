package fixupchains

import "testing"

// A zero DyldChainedFixups (as built by File.convertToVMAddr for the old arm64e
// format) has no payload reader; asking it about binds must not panic.
func TestZeroValueDyldChainedFixupsDoesNotPanic(t *testing.T) {
	for _, format := range []DCPtrKind{DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_32} {
		dcf := DyldChainedFixups{PointerFormat: format}
		if imp, addend, ok := dcf.IsBind(1 << 62); ok || imp != nil || addend != 0 {
			t.Fatalf("format %d: IsBind on a zero value = (%v, %d, %v)", format, imp, addend, ok)
		}
		if err := dcf.ParseStarts(); err == nil {
			t.Fatalf("format %d: ParseStarts succeeded without a reader", format)
		}
		if err := dcf.EnsureImports(); err == nil {
			t.Fatalf("format %d: EnsureImports succeeded without a reader", format)
		}
	}
}
