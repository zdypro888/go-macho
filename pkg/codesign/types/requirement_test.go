package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
)

func TestGetDataRequiresCompletePaddedValue(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "short payload",
			data: append(binary.BigEndian.AppendUint32(nil, 4), 0xaa),
		},
		{
			name: "alignment overflow sentinel",
			data: binary.BigEndian.AppendUint32(nil, math.MaxUint32),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("getData panicked: %v", recovered)
				}
			}()
			if _, err := getData(bytes.NewReader(test.data)); err == nil {
				t.Fatal("getData accepted an incomplete value")
			}
		})
	}

	valid := append(binary.BigEndian.AppendUint32(nil, 3), 'a', 'b', 'c', 0)
	reader := bytes.NewReader(valid)
	got, err := getData(reader)
	if err != nil {
		t.Fatalf("getData(valid): %v", err)
	}
	if string(got) != "abc" || reader.Len() != 0 {
		t.Fatalf("getData(valid) = %q with %d bytes remaining", got, reader.Len())
	}
}

func TestGetMatchNumericComparisonOperators(t *testing.T) {
	tests := []struct {
		name string
		op   matchOp
		want string
	}{
		{name: "less", op: matchLessThan, want: " < \"10\""},
		{name: "greater", op: matchGreaterThan, want: " > \"10\""},
		{name: "less equal", op: matchLessEqual, want: " <= \"10\""},
		{name: "greater equal", op: matchGreaterEqual, want: " >= \"10\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := binary.Write(&encoded, binary.BigEndian, tt.op); err != nil {
				t.Fatalf("encode opcode: %v", err)
			}
			if err := binary.Write(&encoded, binary.BigEndian, uint32(len("10"))); err != nil {
				t.Fatalf("encode data length: %v", err)
			}
			encoded.WriteString("10")
			encoded.Write([]byte{0, 0})

			got, err := getMatch(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatalf("getMatch: %v", err)
			}
			if got != tt.want {
				t.Fatalf("getMatch() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRequirementsCurrentAppleOpcodes(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want string
	}{
		{"notarized", "fade0c00000000100000000100000015", "notarized"},
		{"platform", "fade0c0000000014000000010000001400000001", "platform = 1"},
		{"legacy", "fade0c00000000100000000100000017", "legacy"},
		{"absent", "fade0c000000001c000000010000000a00000003666f6f000000000e", "info[foo] absent"},
		{
			"certificate timestamp",
			"fade0c00000000300000000100000016000000000000000a2a864886f7636406010900000000000d000000002b423800",
			"certificate leaf[timestamp.1.2.840.113635.100.6.1.9] >= <2024-01-01 00:00:00 +0000>",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := hex.DecodeString(test.hex)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			got, err := ParseRequirements(bytes.NewReader(data), Requirements{Type: DesignatedRequirementType, Offset: 12})
			if err != nil {
				t.Fatalf("ParseRequirements: %v", err)
			}
			if got != test.want {
				t.Fatalf("detail = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGetMatchTimestampOperations(t *testing.T) {
	for _, test := range []struct {
		op   matchOp
		want string
	}{
		{matchOn, " = <2024-01-01 00:00:00 +0000>"},
		{matchBefore, " < <2024-01-01 00:00:00 +0000>"},
		{matchAfter, " > <2024-01-01 00:00:00 +0000>"},
		{matchOnOrBefore, " <= <2024-01-01 00:00:00 +0000>"},
		{matchOnOrAfter, " >= <2024-01-01 00:00:00 +0000>"},
	} {
		var encoded bytes.Buffer
		if err := binary.Write(&encoded, binary.BigEndian, test.op); err != nil {
			t.Fatalf("encode opcode: %v", err)
		}
		if err := binary.Write(&encoded, binary.BigEndian, int64(725760000)); err != nil {
			t.Fatalf("encode timestamp: %v", err)
		}
		got, err := getMatch(bytes.NewReader(encoded.Bytes()))
		if err != nil {
			t.Fatalf("getMatch(%s): %v", test.op, err)
		}
		if got != test.want {
			t.Fatalf("getMatch(%s) = %q, want %q", test.op, got, test.want)
		}
	}
}

func TestParseRequirementsRejectsTrailingOrUnknownExpression(t *testing.T) {
	var trailing bytes.Buffer
	binary.Write(&trailing, binary.BigEndian, opTrue)
	binary.Write(&trailing, binary.BigEndian, opFalse)
	if _, err := ParseRequirements(bytes.NewReader(trailing.Bytes()), Requirements{Type: DesignatedRequirementType}); err == nil {
		t.Fatal("accepted a second top-level expression")
	}
	var unknown bytes.Buffer
	binary.Write(&unknown, binary.BigEndian, uint32(0x1234))
	if _, err := ParseRequirements(bytes.NewReader(unknown.Bytes()), Requirements{Type: DesignatedRequirementType}); err == nil {
		t.Fatal("accepted an unknown unflagged opcode")
	}
}

func TestParseRequirementsGenericOpcodeSemantics(t *testing.T) {
	encode := func(op exprOp, payload []byte, tail ...exprOp) []byte {
		var data bytes.Buffer
		binary.Write(&data, binary.BigEndian, op)
		binary.Write(&data, binary.BigEndian, uint32(len(payload)))
		data.Write(payload)
		for _, next := range tail {
			binary.Write(&data, binary.BigEndian, next)
		}
		return data.Bytes()
	}
	got, err := ParseRequirements(bytes.NewReader(encode(opGenericFalse|0x1234, []byte{1, 2, 3})), Requirements{Type: DesignatedRequirementType})
	if err != nil || got != "false /* opcode 4660 */" {
		t.Fatalf("generic false = %q, %v", got, err)
	}
	got, err = ParseRequirements(bytes.NewReader(encode(opGenericSkip|0x1234, []byte{1, 2, 3}, opTrue)), Requirements{Type: DesignatedRequirementType})
	if err != nil || got != "always" {
		t.Fatalf("generic skip = %q, %v", got, err)
	}
}

func TestParseRequirementsEnforcesAppleStackLimit(t *testing.T) {
	nestedNot := func(expressionCount int) []byte {
		var encoded bytes.Buffer
		for range expressionCount - 1 {
			binary.Write(&encoded, binary.BigEndian, opNot)
		}
		binary.Write(&encoded, binary.BigEndian, opTrue)
		return encoded.Bytes()
	}
	for _, test := range []struct {
		expressionCount int
		wantErr         bool
	}{
		{expressionCount: requirementStackLimit - 1},
		{expressionCount: requirementStackLimit, wantErr: true},
		{expressionCount: requirementStackLimit + 1, wantErr: true},
	} {
		_, err := ParseRequirements(bytes.NewReader(nestedNot(test.expressionCount)), Requirements{Type: DesignatedRequirementType})
		if (err != nil) != test.wantErr {
			t.Fatalf("%d nested expressions error = %v, wantErr=%t", test.expressionCount, err, test.wantErr)
		}
	}

	// Generic-skip continues by recursively interpreting the next expression,
	// so it must consume the same budget as a named recursive opcode.
	var generic bytes.Buffer
	for range requirementStackLimit - 1 {
		binary.Write(&generic, binary.BigEndian, opGenericSkip|0x1234)
		binary.Write(&generic, binary.BigEndian, uint32(0))
	}
	binary.Write(&generic, binary.BigEndian, opTrue)
	if _, err := ParseRequirements(bytes.NewReader(generic.Bytes()), Requirements{Type: DesignatedRequirementType}); err == nil {
		t.Fatal("generic-skip chain bypassed the requirement stack limit")
	}
}

func TestRequirementDataFormattingMatchesAppleDumper(t *testing.T) {
	for _, test := range []struct {
		name    string
		data    []byte
		dotOkay bool
		want    string
	}{
		{name: "simple", data: []byte("abc123"), want: "abc123"},
		{name: "dot key", data: []byte("com.example.key"), dotOkay: true, want: "com.example.key"},
		{name: "dot value", data: []byte("com.example"), want: `"com.example"`},
		{name: "leading digit", data: []byte("10"), want: `"10"`},
		{name: "keyword", data: []byte("anchor"), want: `"anchor"`},
		{name: "quote and slash", data: []byte{'a', '"', 'b', '\\', 'c'}, want: `"a\"b\\c"`},
		{name: "whitespace", data: []byte("a b"), want: `"a b"`},
		{name: "binary", data: []byte{0x00, 0xff}, want: "0x00ff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := formatRequirementData(test.data, test.dotOkay); got != test.want {
				t.Fatalf("formatRequirementData(%x) = %q, want %q", test.data, got, test.want)
			}
		})
	}
	if got := formatRequirementHash([]byte{0x00, 0xff, 0x41}); got != `H"00ff41"` {
		t.Fatalf("formatRequirementHash = %q", got)
	}
}

func TestParseRequirementsUsesAppleDumperDataAndHashLiterals(t *testing.T) {
	encodeData := func(data []byte) []byte {
		encoded := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
		encoded = append(encoded, data...)
		for len(encoded)%4 != 0 {
			encoded = append(encoded, 0)
		}
		return encoded
	}
	parse := func(expression []byte) string {
		t.Helper()
		detail, err := ParseRequirements(bytes.NewReader(expression), Requirements{Type: DesignatedRequirementType})
		if err != nil {
			t.Fatalf("ParseRequirements: %v", err)
		}
		return detail
	}

	identifier := binary.BigEndian.AppendUint32(nil, uint32(opIdent))
	identifier = append(identifier, encodeData([]byte{'a', '"', 'b'})...)
	if got, want := parse(identifier), `identifier "a\"b"`; got != want {
		t.Fatalf("identifier detail = %q, want %q", got, want)
	}

	hashBytes := append([]byte{0x00, 0xff, 0x41}, bytes.Repeat([]byte{0x5a}, 17)...)
	cdhash := binary.BigEndian.AppendUint32(nil, uint32(opCDHash))
	cdhash = append(cdhash, encodeData(hashBytes)...)
	if got, want := parse(cdhash), `cdhash H"00ff415a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"`; got != want {
		t.Fatalf("cdhash detail = %q, want %q", got, want)
	}

	field := binary.BigEndian.AppendUint32(nil, uint32(opInfoKeyField))
	field = append(field, encodeData([]byte("a.b"))...)
	field = binary.BigEndian.AppendUint32(field, uint32(matchEqual))
	field = append(field, encodeData([]byte("anchor"))...)
	if got, want := parse(field), `info[a.b] = "anchor"`; got != want {
		t.Fatalf("field detail = %q, want %q", got, want)
	}
}
