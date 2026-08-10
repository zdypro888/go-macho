package macho

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

func encodeFunctionVariants(t *testing.T, offsets []uint32, tables ...[]byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.LittleEndian, uint32(len(offsets))); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&payload, binary.LittleEndian, offsets); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		payload.Write(table)
	}
	return payload.Bytes()
}

func encodeFunctionVariantTable(t *testing.T, kind types.FuncVarTableKind, entries ...types.FuncVarEntry) []byte {
	t.Helper()
	var table bytes.Buffer
	if err := binary.Write(&table, binary.LittleEndian, uint32(kind)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&table, binary.LittleEndian, uint32(len(entries))); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := binary.Write(&table, binary.LittleEndian, entry.Impl); err != nil {
			t.Fatal(err)
		}
		if _, err := table.Write(entry.FlagBitNums[:]); err != nil {
			t.Fatal(err)
		}
	}
	return table.Bytes()
}

func TestParseFunctionVariantsUsesAdjacentTableBoundaries(t *testing.T) {
	first := encodeFunctionVariantTable(t, types.FuncVarTableKindPerProcess,
		types.FuncVarEntry{Impl: 1, FlagBitNums: [4]uint8{1}},
		types.FuncVarEntry{})
	second := encodeFunctionVariantTable(t, types.FuncVarTableKindSystemWide, types.FuncVarEntry{})
	payload := encodeFunctionVariants(t, []uint32{12, 28}, first, second)

	if _, err := ParseFunctionVariants(payload, binary.LittleEndian); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-table entry count error = %v", err)
	}
}

func TestParseFunctionVariantsValidatesRuntimeTableContract(t *testing.T) {
	valid := encodeFunctionVariantTable(t, types.FuncVarTableKindARM64,
		types.FuncVarEntry{Impl: 0x40, FlagBitNums: [4]uint8{11}},
		types.FuncVarEntry{Impl: 0x20})
	payload := encodeFunctionVariants(t, []uint32{8}, append(valid, make([]byte, 4)...))
	parsed, err := ParseFunctionVariants(payload, binary.LittleEndian)
	if err != nil {
		t.Fatalf("valid table: %v", err)
	}
	if len(parsed.Tables) != 1 || len(parsed.Tables[0].Entries) != 2 {
		t.Fatalf("parsed tables = %#v", parsed.Tables)
	}

	tests := []struct {
		name  string
		kind  types.FuncVarTableKind
		entry []types.FuncVarEntry
	}{
		{name: "unknown kind", kind: 99, entry: []types.FuncVarEntry{{}}},
		{name: "zero entries", kind: types.FuncVarTableKindARM64},
		{name: "missing final default", kind: types.FuncVarTableKindARM64, entry: []types.FuncVarEntry{{FlagBitNums: [4]uint8{1}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := encodeFunctionVariantTable(t, tt.kind, tt.entry...)
			if _, err := ParseFunctionVariants(encodeFunctionVariants(t, []uint32{8}, table), binary.LittleEndian); err == nil {
				t.Fatal("malformed runtime table was accepted")
			}
		})
	}
}

func TestFunctionVariantFlagNamesMatchAppleDefinitions(t *testing.T) {
	if got := types.FuncVarFlagName(types.FuncVarTableKindPerProcess, 2); got != "flag_2" {
		t.Fatalf("per-process bit 2 = %q, want unknown flag_2", got)
	}
	if got := types.FuncVarFlagName(types.FuncVarTableKindARM64, 33); got != "csv3" {
		t.Fatalf("ARM64 bit 33 = %q, want csv3", got)
	}
}

func TestFunctionVariantPayloadSizeFailsBeforeHugeAllocation(t *testing.T) {
	reader := types.NewCustomSectionReader(bytes.NewReader(nil), nil, 0, 0)
	f := &File{
		FileTOC: FileTOC{
			ByteOrder: binary.LittleEndian,
			Loads: loads{
				&FunctionVariants{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{Size: math.MaxUint32}}},
			},
		},
		cr: reader,
	}
	if _, err := f.GetFunctionVariants(); err == nil {
		t.Fatal("huge declared function-variants payload unexpectedly succeeded")
	}

	f.Loads = loads{
		&FunctionVariantFixups{LinkEditData: LinkEditData{LinkEditDataCmd: types.LinkEditDataCmd{Size: math.MaxUint32}}},
	}
	if _, err := f.GetFunctionVariantFixups(); err == nil {
		t.Fatal("huge declared function-variant-fixups payload unexpectedly succeeded")
	}
}
