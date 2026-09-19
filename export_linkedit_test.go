package macho

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A standalone Mach-O whose layout Export does not change must come out byte
// for byte: padding the trailing __LINKEDIT put zeros after the code signature
// and made the result impossible to re-sign.
func TestExportDoesNotPadTrailingLinkedit(t *testing.T) {
	const path = "/bin/ls"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skip(path + " not available")
	}
	fat, err := OpenFat(path)
	if err != nil {
		t.Skipf("OpenFat(%s): %v", path, err)
	}
	defer fat.Close()
	for _, arch := range fat.Arches {
		original := raw[arch.Offset : uint64(arch.Offset)+uint64(arch.Size)]
		out := filepath.Join(t.TempDir(), "ls."+arch.File.CPU.String())
		if err := arch.File.Export(out, nil, arch.File.GetBaseAddress(), nil); err != nil {
			t.Fatalf("%s: Export: %v", arch.File.CPU, err)
		}
		exported, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(exported, original) {
			t.Errorf("%s: exported %d bytes, original slice is %d bytes (or contents differ)", arch.File.CPU, len(exported), len(original))
		}
		reopened, err := Open(out)
		if err != nil {
			t.Fatalf("%s: reopen: %v", arch.File.CPU, err)
		}
		linkedit, sig := reopened.Segment("__LINKEDIT"), reopened.CodeSignature()
		if linkedit != nil && sig != nil {
			if end := uint64(sig.Offset) + uint64(sig.Size); end != linkedit.Offset+linkedit.Filesz || end != uint64(len(exported)) {
				t.Errorf("%s: signature ends at %#x, __LINKEDIT at %#x, file at %#x", arch.File.CPU, end, linkedit.Offset+linkedit.Filesz, len(exported))
			}
		}
		reopened.Close()
	}
}
