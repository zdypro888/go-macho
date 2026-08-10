package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

func newSwiftFixtureFile(t *testing.T, base uint64, data []byte) *File {
	t.Helper()

	vma := &types.VMAddrConverter{
		Converter: func(addr uint64) uint64 { return addr },
		VMAddr2Offet: func(addr uint64) (uint64, error) {
			if addr < base || addr-base >= uint64(len(data)) {
				return 0, fmt.Errorf("address %#x is outside fixture", addr)
			}
			return addr - base, nil
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			if offset >= uint64(len(data)) {
				return 0, fmt.Errorf("offset %#x is outside fixture", offset)
			}
			return base + offset, nil
		},
	}
	reader := types.NewCustomSectionReader(bytes.NewReader(data), vma, 0, int64(len(data)))
	return &File{
		FileTOC: FileTOC{
			FileHeader: types.FileHeader{Magic: types.Magic64},
			ByteOrder:  binary.LittleEndian,
		},
		vma: vma,
		cr:  reader,
		sr:  reader,
	}
}

func TestSwiftObjCProtocolSymbolicReferenceUsesFlatMangledName(t *testing.T) {
	const base uint64 = 0x100000000
	data := make([]byte, 64)

	// Swift's ObjectiveCProtocol target record contains two relative int32
	// fields. The second is relative to itself and points at the flat mangled
	// protocol name.
	binary.LittleEndian.PutUint32(data[4:8], uint32(int32(8)))
	copy(data[12:], "So9NSCopying_p\x00")

	// A symbolic mangled-name reference begins with kind 0x0c and an int32
	// displacement relative to the payload field (base+33 here).
	data[32] = 0x0c
	symbolicFieldAddr := base + 33
	binary.LittleEndian.PutUint32(data[33:37], uint32(int32(int64(base)-int64(symbolicFieldAddr))))
	copy(data[37:], "_p\x00")

	file := newSwiftFixtureFile(t, base, data)

	name, err := file.objcProtocolSymbolicName(base)
	if err != nil {
		t.Fatalf("objcProtocolSymbolicName: %v", err)
	}
	if name != "NSCopying" {
		t.Fatalf("protocol name = %q, want NSCopying", name)
	}

	typeref, err := file.makeSymbolicMangledNameStringRef(base + 32)
	if err != nil {
		t.Fatalf("makeSymbolicMangledNameStringRef: %v", err)
	}
	if typeref != "NSCopying" {
		t.Fatalf("typeref = %q, want NSCopying", typeref)
	}
}

func TestSwiftRelativeOffsetRejectsOverflowAndUnderflow(t *testing.T) {
	if _, err := addSwiftRelativeOffset(^uint64(0), 1); err == nil {
		t.Fatal("positive relative offset overflow was accepted")
	}
	if _, err := addSwiftRelativeOffset(0, -1); err == nil {
		t.Fatal("negative relative offset underflow was accepted")
	}
}

func TestGetContextDescPropagatesImageReadFailures(t *testing.T) {
	const base uint64 = 0x100000000
	data := make([]byte, 64)
	file := newSwiftFixtureFile(t, base, data)

	t.Run("truncated in-range descriptor", func(t *testing.T) {
		const descriptorTail = uint64(60) // only four of the required eight bytes remain
		ctx, err := file.getContextDesc(base + descriptorTail)
		if err == nil {
			t.Fatalf("getContextDesc returned ctx %#v without reporting a truncated descriptor", ctx)
		}
		if !strings.Contains(err.Error(), "failed to read swift context descriptor") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unreadable indirect slot", func(t *testing.T) {
		indirect := (base + uint64(len(data)) + 2) | 1
		ctx, err := file.getContextDesc(indirect)
		if err == nil {
			t.Fatalf("getContextDesc returned ctx %#v without reporting an unreadable indirect slot", ctx)
		}
		if !strings.Contains(err.Error(), "failed to read swift context descriptor pointer") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
