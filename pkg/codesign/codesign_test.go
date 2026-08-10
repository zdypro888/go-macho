package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/zdypro888/go-macho/pkg/codesign/types"
)

func writeBigEndian(t *testing.T, buf *bytes.Buffer, value any) {
	t.Helper()
	if err := binary.Write(buf, binary.BigEndian, value); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
}

func makeRequirementsVector(t *testing.T) []byte {
	t.Helper()
	const (
		headerSize = uint32(12)
		indexSize  = uint32(8)
		innerSize  = uint32(16)
		count      = uint32(2)
	)
	firstOffset := headerSize + count*indexSize
	secondOffset := firstOffset + innerSize
	vectorLength := secondOffset + innerSize

	var vector bytes.Buffer
	writeBigEndian(t, &vector, types.RequirementsBlob{
		Magic:  types.MAGIC_REQUIREMENTS,
		Length: vectorLength,
		Data:   count,
	})
	writeBigEndian(t, &vector, []types.Requirements{
		{Type: types.HostRequirementType, Offset: firstOffset},
		{Type: types.GuestRequirementType, Offset: secondOffset},
	})
	for range count {
		writeBigEndian(t, &vector, types.RequirementsBlob{
			Magic:  types.MAGIC_REQUIREMENT,
			Length: innerSize,
			Data:   1, // Requirement::exprForm
		})
		writeBigEndian(t, &vector, uint32(1)) // opTrue
	}
	return vector.Bytes()
}

func makeCodeDirectoryBlob(t *testing.T, earliest types.CdEarliest) []byte {
	t.Helper()
	return makeCodeDirectoryBlobWithID(t, earliest, "fixture")
}

func makeCodeDirectoryBlobWithID(t *testing.T, earliest types.CdEarliest, identifier string) []byte {
	t.Helper()
	fixedSize := uint32(binary.Size(types.BlobHeader{}) + binary.Size(earliest))
	earliest.IdentOffset = fixedSize
	length := fixedSize + uint32(len(identifier)) + 1
	// With no hash slots, Apple's BlobCore::contains still requires the
	// zero-length hash-array position to be inside the blob and after BlobCore.
	earliest.HashOffset = length
	var blob bytes.Buffer
	writeBigEndian(t, &blob, types.BlobHeader{Magic: types.MAGIC_CODEDIRECTORY, Length: length})
	writeBigEndian(t, &blob, earliest)
	blob.WriteString(identifier)
	blob.WriteByte(0)
	return blob.Bytes()
}

func TestParseCodeDirectoryUsesAppleCDHashLengthForEverySupportedDigest(t *testing.T) {
	tests := []struct {
		name     string
		earliest types.CdEarliest
		digest   func([]byte) []byte
	}{
		{
			name:     "sha1",
			earliest: types.CdEarliest{Version: types.EARLIEST_VERSION, HashType: types.HASHTYPE_SHA1, HashSize: types.HASH_SIZE_SHA1},
			digest: func(data []byte) []byte {
				sum := sha1.Sum(data)
				return sum[:]
			},
		},
		{
			name:     "sha256",
			earliest: types.CdEarliest{Version: types.EARLIEST_VERSION, HashType: types.HASHTYPE_SHA256, HashSize: types.HASH_SIZE_SHA256},
			digest: func(data []byte) []byte {
				sum := sha256.Sum256(data)
				return sum[:]
			},
		},
		{
			name:     "sha256-truncated",
			earliest: types.CdEarliest{Version: types.EARLIEST_VERSION, HashType: types.HASHTYPE_SHA256_TRUNCATED, HashSize: types.HASH_SIZE_SHA256_TRUNCATED},
			digest: func(data []byte) []byte {
				sum := sha256.Sum256(data)
				return sum[:]
			},
		},
		{
			name:     "sha384",
			earliest: types.CdEarliest{Version: types.EARLIEST_VERSION, HashType: types.HASHTYPE_SHA384, HashSize: 48},
			digest: func(data []byte) []byte {
				sum := sha512.Sum384(data)
				return sum[:]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blob := makeCodeDirectoryBlob(t, test.earliest)
			directory, err := parseCodeDirectory(bytes.NewReader(blob), 0, uint64(len(blob)))
			if err != nil {
				t.Fatalf("parseCodeDirectory: %v", err)
			}
			digest := test.digest(blob)
			want := fmt.Sprintf("%x", digest[:types.CDHASH_LEN])
			if directory.CDHash != want || len(directory.CDHash) != 2*types.CDHASH_LEN {
				t.Fatalf("CDHash = %q (len %d), want %q", directory.CDHash, len(directory.CDHash), want)
			}
		})
	}
}

func TestParseCodeSignatureAcceptsEveryAlternateCodeDirectorySlot(t *testing.T) {
	blob := makeCodeDirectoryBlob(t, types.CdEarliest{
		Version:  types.EARLIEST_VERSION,
		HashType: types.HASHTYPE_SHA256,
		HashSize: types.HASH_SIZE_SHA256,
	})
	slots := []types.SlotType{
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES,
		types.CSSLOT_CODEDIRECTORY,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES1,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES2,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES3,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES4,
	}
	headerSize := uint32(binary.Size(types.SbHeader{}))
	indexSize := uint32(binary.Size(types.BlobIndex{}))
	firstOffset := headerSize + uint32(len(slots))*indexSize
	totalLength := firstOffset + uint32(len(slots)*len(blob))
	var signature bytes.Buffer
	writeBigEndian(t, &signature, types.SbHeader{
		Magic:  types.MAGIC_EMBEDDED_SIGNATURE,
		Length: totalLength,
		Count:  uint32(len(slots)),
	})
	for index, slot := range slots {
		writeBigEndian(t, &signature, types.BlobIndex{
			Type:   slot,
			Offset: firstOffset + uint32(index*len(blob)),
		})
	}
	for range slots {
		signature.Write(blob)
	}

	parsed, err := ParseCodeSignature(signature.Bytes())
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if len(parsed.CodeDirectories) != len(slots) {
		t.Fatalf("parsed %d CodeDirectories, want %d", len(parsed.CodeDirectories), len(slots))
	}
	if parsed.CodeDirectories[0].Slot != types.CSSLOT_CODEDIRECTORY {
		t.Fatalf("first CodeDirectory slot = %s, want primary", parsed.CodeDirectories[0].Slot)
	}
	primary := parsed.PrimaryCodeDirectory()
	if primary == nil || primary.Slot != types.CSSLOT_CODEDIRECTORY {
		t.Fatalf("PrimaryCodeDirectory = %#v, want slot 0", primary)
	}
	wantAlternates := []types.SlotType{
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES1,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES2,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES3,
		types.CSSLOT_ALTERNATE_CODEDIRECTORIES4,
	}
	for index, want := range wantAlternates {
		if got := parsed.CodeDirectories[index+1].Slot; got != want {
			t.Fatalf("alternate %d slot = %s, want %s", index, got, want)
		}
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal CodeSignature: %v", err)
	}
	var roundTrip CodeSignature
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal CodeSignature: %v", err)
	}
	if len(roundTrip.CodeDirectories) != len(parsed.CodeDirectories) {
		t.Fatalf("round-trip directories = %d, want %d", len(roundTrip.CodeDirectories), len(parsed.CodeDirectories))
	}
	for index := range parsed.CodeDirectories {
		if roundTrip.CodeDirectories[index].Slot != parsed.CodeDirectories[index].Slot {
			t.Fatalf("round-trip directory %d slot = %s, want %s", index, roundTrip.CodeDirectories[index].Slot, parsed.CodeDirectories[index].Slot)
		}
	}
}

func TestParseCodeSignatureValidatesEmbeddedSuperBlobMagic(t *testing.T) {
	config := &Config{ID: "com.example.magic", Flags: types.ADHOC, CodeSize: 1}
	config.InitSlotHashes()
	signature, err := Sign(bytes.NewReader([]byte{0x42}), config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, test := range []struct {
		name    string
		magic   types.Magic
		wantErr bool
	}{
		{name: "current embedded", magic: types.MAGIC_EMBEDDED_SIGNATURE},
		{name: "legacy embedded", magic: types.MAGIC_EMBEDDED_SIGNATURE_OLD},
		{name: "detached", magic: types.MAGIC_DETACHED_SIGNATURE, wantErr: true},
		{name: "unknown", magic: 0, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := bytes.Clone(signature)
			binary.BigEndian.PutUint32(encoded[:4], uint32(test.magic))
			_, err := ParseCodeSignature(encoded)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseCodeSignature magic %s error = %v, wantErr=%t", test.magic, err, test.wantErr)
			}
		})
	}
}

func TestSignPreservesLaunchConstraintBlobsAndBindings(t *testing.T) {
	code := bytes.Repeat([]byte{0x7c}, types.PAGE_SIZE+3)
	self := []byte{0x30, 0x03, 0x02, 0x01, 0x08}
	parent := []byte{0x30, 0x03, 0x02, 0x01, 0x09}
	config := &Config{
		ID:                      "com.example.constraints",
		Flags:                   types.ADHOC,
		CodeSize:                uint64(len(code)),
		LaunchConstraintsSelf:   self,
		LaunchConstraintsParent: parent,
	}
	config.InitSlotHashes()
	signature, err := Sign(bytes.NewReader(code), config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := ParseCodeSignature(signature)
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if !bytes.Equal(parsed.LaunchConstraintsSelf, self) || !bytes.Equal(parsed.LaunchConstraintsParent, parent) {
		t.Fatalf("constraint payloads changed: self=%x parent=%x", parsed.LaunchConstraintsSelf, parsed.LaunchConstraintsParent)
	}
	primary := parsed.PrimaryCodeDirectory()
	if primary == nil || primary.Header.NSpecialSlots != 9 {
		t.Fatalf("primary=%#v, want 9 special slots", primary)
	}
	for _, test := range []struct {
		slot    uint32
		payload []byte
	}{
		{8, self},
		{9, parent},
	} {
		blob := types.NewBlob(types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, test.payload)
		want, err := blob.Sha256Hash()
		if err != nil {
			t.Fatalf("hash slot %d: %v", test.slot, err)
		}
		got, ok := specialSlotHash(primary.SpecialSlots, test.slot)
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("slot %d hash = %x, want %x", test.slot, got, want)
		}
	}

	// Omitting a payload must also remove its historical binding, even when a
	// higher-numbered constraint keeps the CodeDirectory table extended.
	parentOnly := &Config{
		ID:                      "com.example.parent-only",
		Flags:                   types.ADHOC,
		CodeSize:                uint64(len(code)),
		LaunchConstraintsParent: parent,
		SpecialSlots: []types.SpecialSlot{
			{Index: 9, Hash: config.SlotHashes.LaunchConstraintsParent},
			{Index: 8, Hash: config.SlotHashes.LaunchConstraintsSelf},
		},
	}
	parentOnly.InitSlotHashes()
	parentSignature, err := Sign(bytes.NewReader(code), parentOnly)
	if err != nil {
		t.Fatalf("Sign(parent only): %v", err)
	}
	parentParsed, err := ParseCodeSignature(parentSignature)
	if err != nil {
		t.Fatalf("ParseCodeSignature(parent only): %v", err)
	}
	if len(parentParsed.LaunchConstraintsSelf) != 0 {
		t.Fatalf("omitted self constraint survived: %x", parentParsed.LaunchConstraintsSelf)
	}
	selfHash, ok := specialSlotHash(parentParsed.PrimaryCodeDirectory().SpecialSlots, 8)
	if !ok || isBoundSpecialSlotHash(selfHash) {
		t.Fatalf("omitted self slot remains bound: %x", selfHash)
	}
}

func TestSignTreatsAdhocAsBitmask(t *testing.T) {
	code := []byte("adhoc flags fixture")
	for _, test := range []struct {
		name  string
		flags types.CDFlag
		adhoc bool
	}{
		{"adhoc", types.ADHOC, true},
		{"adhoc runtime", types.ADHOC | types.RUNTIME, true},
		{"runtime", types.RUNTIME, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{ID: "com.example.flags", Flags: test.flags, CodeSize: uint64(len(code))}
			config.InitSlotHashes()
			signature, err := Sign(bytes.NewReader(code), config)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			parsed, err := ParseCodeSignature(signature)
			if err != nil {
				t.Fatalf("ParseCodeSignature: %v", err)
			}
			primary := parsed.PrimaryCodeDirectory()
			if primary == nil {
				t.Fatal("missing primary CodeDirectory")
			}
			requirementHash, ok := specialSlotHash(primary.SpecialSlots, 2)
			if !ok {
				t.Fatal("missing requirements special slot")
			}
			isEmpty := bytes.Equal(requirementHash, types.EmptySha256ReqSlot)
			if isEmpty != test.adhoc {
				t.Fatalf("empty requirements hash = %t, want %t", isEmpty, test.adhoc)
			}
		})
	}
}

func TestParseAndSignRawCodeSignatureComponents(t *testing.T) {
	raw := map[types.SlotType][]byte{
		types.CSSLOT_INFOSLOT:           []byte("info"),
		types.CSSLOT_RESOURCEDIR:        []byte("resources"),
		types.CSSLOT_APPLICATION:        []byte("application"),
		types.CSSLOT_REP_SPECIFIC:       []byte("representation"),
		types.CSSLOT_IDENTIFICATIONSLOT: []byte("identification"),
		types.CSSLOT_TICKETSLOT:         []byte("ticket"),
	}
	code := []byte("raw component signing fixture")
	config := &Config{
		ID:            "com.example.raw-components",
		Flags:         types.ADHOC,
		CodeSize:      uint64(len(code)),
		RawComponents: raw,
	}
	config.InitSlotHashes()
	signature, err := Sign(bytes.NewReader(code), config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := ParseCodeSignature(signature)
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	for slot, want := range raw {
		if got, ok := parsed.RawComponents[slot]; !ok || !bytes.Equal(got, want) {
			t.Fatalf("raw component %s = %x/%t, want %x", slot, got, ok, want)
		}
		if slot <= types.CSSLOT_REP_SPECIFIC {
			sum := sha256.Sum256(want)
			got, ok := specialSlotHash(parsed.PrimaryCodeDirectory().SpecialSlots, uint32(slot))
			if !ok || !bytes.Equal(got, sum[:]) {
				t.Fatalf("raw component %s hash = %x/%t, want %x", slot, got, ok, sum)
			}
		}
	}
}

func TestParseCodeSignatureRejectsCrossedRawAndNativeBlobMagic(t *testing.T) {
	encode := func(t *testing.T, slot types.SlotType, blob types.Blob) []byte {
		t.Helper()
		super := types.NewSuperBlob(types.MAGIC_EMBEDDED_SIGNATURE)
		super.AddBlob(slot, blob)
		var encoded bytes.Buffer
		if err := super.Write(&encoded, binary.BigEndian); err != nil {
			t.Fatalf("write SuperBlob: %v", err)
		}
		return encoded.Bytes()
	}
	if _, err := ParseCodeSignature(encode(t, types.CSSLOT_RESOURCEDIR,
		types.NewBlob(types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, []byte("wrong")))); err == nil {
		t.Fatal("accepted native launch-constraint magic for a raw component")
	}
	if _, err := ParseCodeSignature(encode(t, types.CSSLOT_LAUNCH_CONSTRAINT_SELF,
		types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte("wrong")))); err == nil {
		t.Fatal("accepted raw BlobWrapper magic for a launch constraint")
	}
}

func TestParseCodeSignatureParsesEveryRequirementInVector(t *testing.T) {
	vector := makeRequirementsVector(t)
	const signatureHeaderAndIndexSize = uint32(20)

	var signature bytes.Buffer
	writeBigEndian(t, &signature, types.SbHeader{
		Magic:  types.MAGIC_EMBEDDED_SIGNATURE,
		Length: signatureHeaderAndIndexSize + uint32(len(vector)),
		Count:  1,
	})
	writeBigEndian(t, &signature, types.BlobIndex{
		Type:   types.CSSLOT_REQUIREMENTS,
		Offset: signatureHeaderAndIndexSize,
	})
	signature.Write(vector)

	parsed, err := ParseCodeSignature(signature.Bytes())
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if len(parsed.Requirements) != 2 {
		t.Fatalf("parsed %d requirements, want 2", len(parsed.Requirements))
	}
	if got := parsed.Requirements[0]; got.Type != types.HostRequirementType || got.Detail != "host => always" || got.Offset != 28 {
		t.Fatalf("first requirement = %#v", got)
	}
	if got := parsed.Requirements[1]; got.Type != types.GuestRequirementType || got.Detail != "guest => always" || got.Offset != 44 {
		t.Fatalf("second requirement = %#v", got)
	}
	for i, req := range parsed.Requirements {
		if req.Magic != types.MAGIC_REQUIREMENTS || req.Data != 2 || req.Length != uint32(len(vector)) {
			t.Fatalf("requirement %d lost vector header: %#v", i, req.RequirementsBlob)
		}
		if req.Opaque != nil {
			t.Fatalf("expression requirement %d unexpectedly became opaque: %#v", i, req.Opaque)
		}
		encoded, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal expression requirement %d: %v", i, err)
		}
		if bytes.Contains(encoded, []byte(`"opaque"`)) {
			t.Fatalf("expression requirement %d changed its JSON shape: %s", i, encoded)
		}
	}
}

func TestParseCodeSignaturePreservesLightweightRequirement(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	const (
		vectorHeaderSize = uint32(12)
		indexSize        = uint32(8)
		innerHeaderSize  = uint32(12)
	)
	innerOffset := vectorHeaderSize + indexSize
	innerLength := innerHeaderSize + uint32(len(der))
	vectorLength := innerOffset + innerLength

	var vector bytes.Buffer
	writeBigEndian(t, &vector, types.RequirementsBlob{
		Magic:  types.MAGIC_REQUIREMENTS,
		Length: vectorLength,
		Data:   1,
	})
	writeBigEndian(t, &vector, types.Requirements{
		Type:   types.DesignatedRequirementType,
		Offset: innerOffset,
	})
	writeBigEndian(t, &vector, types.RequirementsBlob{
		Magic:  types.MAGIC_REQUIREMENT,
		Length: innerLength,
		Data:   2, // Requirement::lwcrForm
	})
	vector.Write(der)

	const signatureHeaderAndIndexSize = uint32(20)
	var signature bytes.Buffer
	writeBigEndian(t, &signature, types.SbHeader{
		Magic:  types.MAGIC_EMBEDDED_SIGNATURE,
		Length: signatureHeaderAndIndexSize + uint32(vector.Len()),
		Count:  1,
	})
	writeBigEndian(t, &signature, types.BlobIndex{
		Type:   types.CSSLOT_REQUIREMENTS,
		Offset: signatureHeaderAndIndexSize,
	})
	signature.Write(vector.Bytes())

	parsed, err := ParseCodeSignature(signature.Bytes())
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if len(parsed.Requirements) != 1 {
		t.Fatalf("parsed %d requirements, want 1", len(parsed.Requirements))
	}
	requirement := parsed.Requirements[0]
	if requirement.Opaque == nil {
		t.Fatal("lightweight requirement did not retain its opaque encoding")
	}
	if requirement.Opaque.Magic != types.MAGIC_REQUIREMENT || requirement.Opaque.Length != innerLength || requirement.Opaque.Data != 2 {
		t.Fatalf("opaque requirement lost its inner header: %#v", requirement.Opaque.RequirementsBlob)
	}
	if !bytes.Equal(requirement.Opaque.Payload, der) {
		t.Fatalf("opaque payload = %x, want %x", requirement.Opaque.Payload, der)
	}

	encoded, err := json.Marshal(requirement)
	if err != nil {
		t.Fatalf("marshal requirement: %v", err)
	}
	var roundTrip types.Requirement
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal requirement: %v", err)
	}
	if roundTrip.Opaque == nil || roundTrip.Opaque.RequirementsBlob != requirement.Opaque.RequirementsBlob || !bytes.Equal(roundTrip.Opaque.Payload, der) {
		t.Fatalf("opaque requirement did not survive JSON round-trip: %#v", roundTrip.Opaque)
	}

	var rebuilt bytes.Buffer
	writeBigEndian(t, &rebuilt, roundTrip.Opaque.RequirementsBlob)
	rebuilt.Write(roundTrip.Opaque.Payload)
	if got, want := rebuilt.Bytes(), vector.Bytes()[innerOffset:]; !bytes.Equal(got, want) {
		t.Fatalf("rebuilt lightweight requirement = %x, want %x", got, want)
	}
}

func TestParseRequirementsSlotRejectsMalformedVectorBounds(t *testing.T) {
	t.Run("index table", func(t *testing.T) {
		var vector bytes.Buffer
		writeBigEndian(t, &vector, types.RequirementsBlob{
			Magic:  types.MAGIC_REQUIREMENTS,
			Length: 12,
			Data:   1,
		})
		if _, err := parseRequirementsSlot(vector.Bytes(), 0, uint32(vector.Len())); err == nil {
			t.Fatal("accepted a count whose index table is outside the vector")
		}
	})

	t.Run("inner blob", func(t *testing.T) {
		var vector bytes.Buffer
		writeBigEndian(t, &vector, types.RequirementsBlob{
			Magic:  types.MAGIC_REQUIREMENTS,
			Length: 36,
			Data:   1,
		})
		writeBigEndian(t, &vector, types.Requirements{
			Type:   types.DesignatedRequirementType,
			Offset: 20,
		})
		writeBigEndian(t, &vector, types.RequirementsBlob{
			Magic:  types.MAGIC_REQUIREMENT,
			Length: 20, // extends four bytes past the enclosing vector
			Data:   1,
		})
		writeBigEndian(t, &vector, uint32(1))
		if _, err := parseRequirementsSlot(vector.Bytes(), 0, uint32(vector.Len())); err == nil {
			t.Fatal("accepted an inner requirement that extends beyond its vector")
		}
	})
}

func TestSignWritesOnlyTheSpecialSlotsItBinds(t *testing.T) {
	code := bytes.Repeat([]byte{0x5a}, types.PAGE_SIZE+17)
	plist := []byte("<plist><dict><key>test</key><true/></dict></plist>")

	tests := []struct {
		name         string
		der          []byte
		previous     []types.SpecialSlot
		wantSpecials uint32
		wantSlot6    []byte
	}{
		{name: "plist only", wantSpecials: 5},
		{
			name:         "plist plus bound representation-specific slot",
			previous:     []types.SpecialSlot{{Index: 6, Hash: bytes.Repeat([]byte{0x6a}, sha256.Size)}},
			wantSpecials: 6,
			wantSlot6:    bytes.Repeat([]byte{0x6a}, sha256.Size),
		},
		{name: "plist and DER", der: []byte{0x30, 0x00}, wantSpecials: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ID:              "com.example.fixture",
				Flags:           types.ADHOC,
				CodeSize:        uint64(len(code)),
				Entitlements:    plist,
				EntitlementsDER: tt.der,
				SpecialSlots:    tt.previous,
			}
			config.InitSlotHashes()
			signature, err := Sign(bytes.NewReader(code), config)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			parsed, err := ParseCodeSignature(signature)
			if err != nil {
				t.Fatalf("ParseCodeSignature: %v", err)
			}
			if len(parsed.CodeDirectories) != 1 {
				t.Fatalf("parsed %d CodeDirectories, want 1", len(parsed.CodeDirectories))
			}
			directory := parsed.CodeDirectories[0]
			if directory.Header.NSpecialSlots != tt.wantSpecials || len(directory.SpecialSlots) != int(tt.wantSpecials) {
				t.Fatalf("special slots = header:%d parsed:%d, want %d", directory.Header.NSpecialSlots, len(directory.SpecialSlots), tt.wantSpecials)
			}
			if len(directory.CodeSlots) != 2 {
				t.Fatalf("code slots = %d, want 2", len(directory.CodeSlots))
			}
			for index, slot := range directory.CodeSlots {
				start := index * types.PAGE_SIZE
				end := min(start+types.PAGE_SIZE, len(code))
				want := sha256.Sum256(code[start:end])
				if !bytes.Equal(slot.Hash, want[:]) {
					t.Fatalf("code slot %d hash = %x, want %x", index, slot.Hash, want)
				}
			}
			if tt.wantSlot6 != nil {
				if got := directory.SpecialSlots[0]; got.Index != 6 || !bytes.Equal(got.Hash, tt.wantSlot6) {
					t.Fatalf("slot 6 = %#v, want %x", got, tt.wantSlot6)
				}
			}
			if len(tt.der) == 0 {
				if len(parsed.EntitlementsDER) != 0 {
					t.Fatalf("unexpected DER entitlements: %x", parsed.EntitlementsDER)
				}
			} else if !bytes.Equal(parsed.EntitlementsDER, tt.der) {
				t.Fatalf("DER entitlements = %x, want %x", parsed.EntitlementsDER, tt.der)
			}
		})
	}
}

func TestParseCodeDirectoryPreservesScatterVectorAndSlotMapping(t *testing.T) {
	const codeSlots = uint32(3)
	headerSize := uint32(binary.Size(types.BlobHeader{}) + binary.Size(types.CdEarliest{}) + binary.Size(types.CdScatter{}))
	scatterSize := uint32(binary.Size(types.Scatter{}))
	hashOffset := headerSize + 3*scatterSize
	length := hashOffset + codeSlots*sha256.Size

	var blob bytes.Buffer
	writeBigEndian(t, &blob, types.BlobHeader{Magic: types.MAGIC_CODEDIRECTORY, Length: length})
	writeBigEndian(t, &blob, types.CdEarliest{
		Version:    types.SUPPORTS_SCATTER,
		HashOffset: hashOffset,
		NCodeSlots: codeSlots,
		CodeLimit:  codeSlots * types.PAGE_SIZE,
		HashSize:   sha256.Size,
		HashType:   types.HASHTYPE_SHA256,
		PageSize:   types.PAGE_SIZE_BITS,
	})
	writeBigEndian(t, &blob, types.CdScatter{ScatterOffset: headerSize})
	writeBigEndian(t, &blob, types.Scatter{Count: 1, Base: 2, TargetOffset: 0x100000})
	writeBigEndian(t, &blob, types.Scatter{Count: 2, Base: 10, TargetOffset: 0x200000})
	writeBigEndian(t, &blob, types.Scatter{})
	for index := range codeSlots {
		blob.Write(bytes.Repeat([]byte{byte(index + 1)}, sha256.Size))
	}

	directory, err := parseCodeDirectory(bytes.NewReader(blob.Bytes()), 0, uint64(blob.Len()))
	if err != nil {
		t.Fatalf("parseCodeDirectory: %v", err)
	}
	if len(directory.Scatters) != 2 || directory.Scatter != directory.Scatters[0] {
		t.Fatalf("scatter vector = %#v, first = %#v", directory.Scatters, directory.Scatter)
	}
	wantPages := []uint64{2 * types.PAGE_SIZE, 10 * types.PAGE_SIZE, 11 * types.PAGE_SIZE}
	wantTargets := []uint64{0x100000, 0x200000, 0x201000}
	for index, slot := range directory.CodeSlots {
		if !slot.ScatterMapped || slot.Page != wantPages[index] || slot.TargetOffset != wantTargets[index] {
			t.Fatalf("code slot %d = %#v, want page=%#x target=%#x", index, slot, wantPages[index], wantTargets[index])
		}
	}
}

func TestCodeDirectoryLargeCodeLimitsAndSlotBounds(t *testing.T) {
	if low, high := codeDirectoryLimits(math.MaxUint32); low != math.MaxUint32 || high != 0 {
		t.Fatalf("32-bit limit = %#x/%#x", low, high)
	}
	large := uint64(math.MaxUint32) + 1
	if low, high := codeDirectoryLimits(large); low != math.MaxUint32 || high != large {
		t.Fatalf("64-bit limit = %#x/%#x, want %#x/%#x", low, high, uint32(math.MaxUint32), large)
	}
	maximum := uint64(math.MaxUint32) * uint64(types.PAGE_SIZE)
	if count, err := codeSlotCount(maximum); err != nil || count != math.MaxUint32 {
		t.Fatalf("maximum slot count = %#x, %v", count, err)
	}
	if _, err := codeSlotCount(maximum + 1); err == nil {
		t.Fatal("accepted a code size requiring more than uint32 code slots")
	}
}

func TestParseCodeSignatureRejectsBlobOffsetsInsideIndexTable(t *testing.T) {
	// The first index points at the second index entry. Those eight bytes can be
	// shaped like an empty BlobWrapper, but Apple rejects the offset before any
	// typed interpretation because it is below ixLimit.
	var signature bytes.Buffer
	writeBigEndian(t, &signature, types.SbHeader{
		Magic:  types.MAGIC_EMBEDDED_SIGNATURE,
		Length: 28,
		Count:  2,
	})
	writeBigEndian(t, &signature, types.BlobIndex{
		Type:   types.CSSLOT_INFOSLOT,
		Offset: 20,
	})
	writeBigEndian(t, &signature, types.BlobIndex{
		Type:   types.SlotType(types.MAGIC_BLOBWRAPPER),
		Offset: 8,
	})
	if _, err := ParseCodeSignature(signature.Bytes()); err == nil {
		t.Fatal("accepted a child blob offset inside the SuperBlob index table")
	}

	// An actual child beginning exactly at ixLimit remains valid.
	super := types.NewSuperBlob(types.MAGIC_EMBEDDED_SIGNATURE)
	super.AddBlob(types.CSSLOT_INFOSLOT, types.NewBlob(types.MAGIC_BLOBWRAPPER, nil))
	var valid bytes.Buffer
	if err := super.Write(&valid, binary.BigEndian); err != nil {
		t.Fatalf("write boundary SuperBlob: %v", err)
	}
	if _, err := ParseCodeSignature(valid.Bytes()); err != nil {
		t.Fatalf("rejected child blob beginning at index end: %v", err)
	}
}

func TestParseCodeSignatureUsesFirstDuplicateSlotLikeApple(t *testing.T) {
	expressionBlob := func(op uint32) types.Blob {
		var payload bytes.Buffer
		writeBigEndian(t, &payload, uint32(1)) // Requirement::exprForm
		writeBigEndian(t, &payload, op)
		return types.NewBlob(types.MAGIC_REQUIREMENT, payload.Bytes())
	}
	codeDirectoryBlob := func(identifier string) types.Blob {
		encoded := makeCodeDirectoryBlobWithID(t, types.CdEarliest{
			Version:  types.EARLIEST_VERSION,
			HashType: types.HASHTYPE_SHA256,
			HashSize: types.HASH_SIZE_SHA256,
		}, identifier)
		return types.NewBlob(types.MAGIC_CODEDIRECTORY, encoded[binary.Size(types.BlobHeader{}):])
	}

	super := types.NewSuperBlob(types.MAGIC_EMBEDDED_SIGNATURE)
	super.AddBlob(types.CSSLOT_CODEDIRECTORY, codeDirectoryBlob("first.directory"))
	super.AddBlob(types.CSSLOT_CODEDIRECTORY, codeDirectoryBlob("second.directory"))
	super.AddBlob(types.CSSLOT_REQUIREMENTS, expressionBlob(1)) // opTrue
	super.AddBlob(types.CSSLOT_REQUIREMENTS, expressionBlob(0)) // opFalse
	super.AddBlob(types.CSSLOT_ENTITLEMENTS, types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS, []byte("first-entitlements")))
	super.AddBlob(types.CSSLOT_ENTITLEMENTS, types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS, []byte("second-entitlements")))
	super.AddBlob(types.CSSLOT_CMS_SIGNATURE, types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte("first-cms")))
	super.AddBlob(types.CSSLOT_CMS_SIGNATURE, types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte("second-cms")))
	super.AddBlob(types.CSSLOT_ENTITLEMENTS_DER, types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS_DER, []byte("first-der")))
	super.AddBlob(types.CSSLOT_ENTITLEMENTS_DER, types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS_DER, []byte("second-der")))
	super.AddBlob(types.CSSLOT_INFOSLOT, types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte("first-info")))
	super.AddBlob(types.CSSLOT_INFOSLOT, types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte("second-info")))
	super.AddBlob(types.CSSLOT_LAUNCH_CONSTRAINT_SELF, types.NewBlob(types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, []byte("first-constraint")))
	super.AddBlob(types.CSSLOT_LAUNCH_CONSTRAINT_SELF, types.NewBlob(types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, []byte("second-constraint")))

	var encoded bytes.Buffer
	if err := super.Write(&encoded, binary.BigEndian); err != nil {
		t.Fatalf("write duplicate-slot SuperBlob: %v", err)
	}
	parsed, err := ParseCodeSignature(encoded.Bytes())
	if err != nil {
		t.Fatalf("ParseCodeSignature: %v", err)
	}
	if primary := parsed.PrimaryCodeDirectory(); primary == nil || primary.ID != "first.directory" || len(parsed.CodeDirectories) != 1 {
		t.Fatalf("primary CodeDirectory = %#v (all=%d), want first only", primary, len(parsed.CodeDirectories))
	}
	if len(parsed.Requirements) != 1 || parsed.Requirements[0].Detail != "always" {
		t.Fatalf("requirements = %#v, want first expression", parsed.Requirements)
	}
	if parsed.Entitlements != "first-entitlements" ||
		!bytes.Equal(parsed.CMSSignature, []byte("first-cms")) ||
		!bytes.Equal(parsed.EntitlementsDER, []byte("first-der")) ||
		!bytes.Equal(parsed.RawComponents[types.CSSLOT_INFOSLOT], []byte("first-info")) ||
		!bytes.Equal(parsed.LaunchConstraintsSelf, []byte("first-constraint")) {
		t.Fatalf("duplicate slots did not preserve first components: %#v", parsed)
	}
	if len(parsed.Errors) != 7 {
		t.Fatalf("duplicate diagnostics = %d, want 7", len(parsed.Errors))
	}
}

func TestParseCodeDirectoryEnforcesAppleIntegrityContract(t *testing.T) {
	makeBlob := func(earliest types.CdEarliest, identifier string, hashes []byte) []byte {
		fixedSize := uint32(binary.Size(types.BlobHeader{}) + binary.Size(types.CdEarliest{}))
		earliest.IdentOffset = fixedSize
		if earliest.HashOffset == 0 {
			earliest.HashOffset = fixedSize + uint32(len(identifier)) + 1
		}
		length := fixedSize + uint32(len(identifier)) + 1 + uint32(len(hashes))
		var blob bytes.Buffer
		writeBigEndian(t, &blob, types.BlobHeader{Magic: types.MAGIC_CODEDIRECTORY, Length: length})
		writeBigEndian(t, &blob, earliest)
		blob.WriteString(identifier)
		blob.WriteByte(0)
		blob.Write(hashes)
		return blob.Bytes()
	}
	parse := func(blob []byte) error {
		_, err := parseCodeDirectory(bytes.NewReader(blob), 0, uint64(len(blob)))
		return err
	}

	for _, earliest := range []types.CdEarliest{
		{Version: types.EARLIEST_VERSION - 1},
		{Version: types.COMPATIBILITY_LIMIT + 1},
	} {
		blob := makeBlob(earliest, "version", nil)
		if err := parse(blob); err == nil {
			t.Fatalf("accepted unsupported CodeDirectory version %#x", uint32(earliest.Version))
		}
	}

	overlap := makeBlob(types.CdEarliest{
		Version:    types.EARLIEST_VERSION,
		HashOffset: 4,
		NCodeSlots: 1,
		CodeLimit:  1,
		HashSize:   types.HASH_SIZE_SHA1,
		HashType:   types.HASHTYPE_SHA1,
	}, "overlap", bytes.Repeat([]byte{0xaa}, types.HASH_SIZE_SHA1))
	if err := parse(overlap); err == nil {
		t.Fatal("accepted a CodeDirectory hash array inside BlobCore")
	}

	for _, test := range []struct {
		name      string
		codeLimit uint32
		codeSlots uint32
		wantErr   bool
	}{
		{name: "paged zero limit", codeSlots: 1, wantErr: true},
		{name: "paged slot mismatch", codeLimit: types.PAGE_SIZE + 1, codeSlots: 1, wantErr: true},
		{name: "paged exact coverage", codeLimit: types.PAGE_SIZE + 1, codeSlots: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob := makeBlob(types.CdEarliest{
				Version:    types.EARLIEST_VERSION,
				NCodeSlots: test.codeSlots,
				CodeLimit:  test.codeLimit,
				HashSize:   types.HASH_SIZE_SHA1,
				HashType:   types.HASHTYPE_SHA1,
				PageSize:   types.PAGE_SIZE_BITS,
			}, "coverage", bytes.Repeat([]byte{0xbb}, int(test.codeSlots)*types.HASH_SIZE_SHA1))
			err := parse(blob)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseCodeDirectory error = %v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}
