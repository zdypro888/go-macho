package types

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// Requirement object
type Requirement struct {
	RequirementsBlob
	Requirements
	Detail string             `json:"detail,omitempty"`
	Opaque *OpaqueRequirement `json:"opaque,omitempty"`
}

// OpaqueRequirement preserves a bounded requirement encoding whose semantics
// are not decoded by this package. The embedded header and payload are enough
// to reproduce the exact inner requirement blob.
type OpaqueRequirement struct {
	RequirementsBlob
	Payload []byte `json:"payload,omitempty"`
}

// RequirementsBlob object
type RequirementsBlob struct {
	Magic  Magic  `json:"magic,omitempty"`  // magic number
	Length uint32 `json:"length,omitempty"` // total length of blob
	Data   uint32 `json:"data,omitempty"`   // vector count for MAGIC_REQUIREMENTS; requirement kind for MAGIC_REQUIREMENT
}

type RequirementType uint32

const (
	HostRequirementType       RequirementType = 1 /* what hosts may run us */
	GuestRequirementType      RequirementType = 2 /* what guests we may run */
	DesignatedRequirementType RequirementType = 3 /* designated requirement */
	LibraryRequirementType    RequirementType = 4 /* what libraries we may link against */
	PluginRequirementType     RequirementType = 5 /* what plug-ins we may load */
)

func (cm RequirementType) String() string {
	switch cm {
	case HostRequirementType:
		return "Host Requirement"
	case GuestRequirementType:
		return "Guest Requirement"
	case DesignatedRequirementType:
		return "Designated Requirement"
	case LibraryRequirementType:
		return "Library Requirement"
	case PluginRequirementType:
		return "Plugin Requirement"
	default:
		return fmt.Sprintf("RequirementType(%d)", cm)
	}
}

// Requirements object
type Requirements struct {
	Type   RequirementType `json:"type,omitempty"`   // type of entry
	Offset uint32          `json:"offset,omitempty"` // offset of entry
}

// NOTE: https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-36591/lib/requirement.h.auto.html

// exprForm opcodes.
//
// Opcodes are broken into flags in the (HBO) high byte, and an opcode value
// in the remaining 24 bits. Note that opcodes will remain fairly small
// (almost certainly <60000), so we have the third byte to play around with
// in the future, if needed. For now, small opcodes effective reserve this byte
// as zero.
// The flag byte allows for limited understanding of unknown opcodes. It allows
// the interpreter to use the known opcode parts of the program while semi-creatively
// disregarding the parts it doesn't know about. An unrecognized opcode with zero
// flag byte causes evaluation to categorically fail, since the semantics of such
// an opcode cannot safely be predicted.
const (
	// semantic bits or'ed into the opcode
	opFlagMask     exprOp = 0xFF000000 // high bit flags
	opGenericFalse exprOp = 0x80000000 // has size field; okay to default to false
	opGenericSkip  exprOp = 0x40000000 // has size field; skip and continue
)

type exprOp uint32

const (
	opFalse              exprOp = iota // unconditionally false
	opTrue                             // unconditionally true
	opIdent                            // match canonical code [string]
	opAppleAnchor                      // signed by Apple as Apple's product
	opAnchorHash                       // match anchor [cert hash]
	opInfoKeyValue                     // *legacy* - use opInfoKeyField [key; value]
	opAnd                              // binary prefix expr AND expr [expr; expr]
	opOr                               // binary prefix expr OR expr [expr; expr]
	opCDHash                           // match hash of CodeDirectory directly [cd hash]
	opNot                              // logical inverse [expr]
	opInfoKeyField                     // Info.plist key field [string; match suffix]
	opCertField                        // Certificate field [cert index; field name; match suffix]
	opTrustedCert                      // require trust settings to approve one particular cert [cert index]
	opTrustedCerts                     // require trust settings to approve the cert chain
	opCertGeneric                      // Certificate component by OID [cert index; oid; match suffix]
	opAppleGenericAnchor               // signed by Apple in any capacity
	opEntitlementField                 // entitlement dictionary field [string; match suffix]
	opCertPolicy                       // Certificate policy by OID [cert index; oid; match suffix]
	opNamedAnchor                      // named anchor type
	opNamedCode                        // named subroutine
	opPlatform                         // platform constraint [integer]
	opNotarized                        // has a developer id + ticket
	opCertFieldDate                    // extension value as timestamp [cert index; oid; match suffix]
	opLegacyDevID                      // meets legacy pre-notarization policy
	exprOpCount                        // (total opcode count in use)
)

func (o exprOp) String() string {
	names := [...]string{
		"False",
		"True",
		"Ident",
		"AppleAnchor",
		"AnchorHash",
		"InfoKeyValue",
		"And",
		"Or",
		"CDHash",
		"Not",
		"InfoKeyField",
		"CertField",
		"TrustedCert",
		"TrustedCerts",
		"CertGeneric",
		"AppleGenericAnchor",
		"EntitlementField",
		"CertPolicy",
		"NamedAnchor",
		"NamedCode",
		"Platform",
		"Notarized",
		"CertFieldDate",
		"LegacyDevID",
		"exprOpCount",
	}
	if uint32(o) >= uint32(len(names)) {
		return fmt.Sprintf("exprOp(%d)", o)
	}
	return names[o]
}

type matchOp uint32

const requirementStackLimit = 1000

// match suffix opcodes
const (
	matchExists       matchOp = iota // anything but explicit "false" - no value stored
	matchEqual                       // equal (CFEqual)
	matchContains                    // partial match (substring)
	matchBeginsWith                  // partial match (initial substring)
	matchEndsWith                    // partial match (terminal substring)
	matchLessThan                    // less than (string with numeric comparison)
	matchGreaterThan                 // greater than (string with numeric comparison)
	matchLessEqual                   // less or equal (string with numeric comparison)
	matchGreaterEqual                // greater or equal (string with numeric comparison)
	matchOn                          // on (timestamp comparison)
	matchBefore                      // before (timestamp comparison)
	matchAfter                       // after (timestamp comparison)
	matchOnOrBefore                  // on or before (timestamp comparison)
	matchOnOrAfter                   // on or after (timestamp comparison)
	matchAbsent                      // not present
)

func (o matchOp) String() string {
	names := [...]string{
		"Exists",
		"Equal",
		"Contains",
		"BeginsWith",
		"EndsWith",
		"LessThan",
		"GreaterThan",
		"LessEqual",
		"GreaterEqual",
		"On",
		"Before",
		"After",
		"OnOrBefore",
		"OnOrAfter",
		"Absent",
	}
	if uint32(o) >= uint32(len(names)) {
		return fmt.Sprintf("matchOp(%d)", o)
	}
	return names[o]
}

const (
	// certificate positions (within a standard certificate chain)
	leafCertIndex   uint32 = 0          // index for leaf (first in chain)
	anchorCertIndex        = ^uint32(0) // index for anchor (last in chain), equiv to -1
)

func getData(r *bytes.Reader) ([]byte, error) {
	var idLength uint32

	if err := binary.Read(r, binary.BigEndian, &idLength); err != nil {
		return nil, err
	}

	// Requirement byte strings are padded to a four-byte boundary. Keep the
	// arithmetic wide and prove that the complete padded value is present before
	// allocating: bytes.Reader.Read may otherwise return a short read with nil.
	length := uint64(idLength)
	alignedLength := (length + 3) &^ uint64(3)
	if alignedLength > uint64(r.Len()) {
		return nil, fmt.Errorf("requirement data length %d (aligned %d) exceeds %d remaining bytes", length, alignedLength, r.Len())
	}
	data := make([]byte, int(alignedLength))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data[:int(length)], nil
}

func isRequirementKeyword(value string) bool {
	switch value {
	case "guest", "host", "designated", "library", "plugin",
		"or", "and", "always", "true", "never", "false",
		"identifier", "cdhash", "platform", "notarized", "legacy",
		"anchor", "apple", "generic", "certificate", "cert",
		"trusted", "info", "entitlement", "exists", "absent",
		"leaf", "root", "timestamp":
		return true
	default:
		return false
	}
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func isASCIIWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

// formatRequirementData mirrors Apple Requirement::Dumper::data: use a bare
// token when it is unambiguous, an escaped quoted token for printable bytes,
// and a hexadecimal literal for binary data. dotOkay is used for dictionary
// and certificate-field keys, where periods are valid in bare tokens.
func formatRequirementData(data []byte, dotOkay bool) string {
	const (
		dataSimple = iota
		dataPrintable
		dataBinary
	)
	mode := dataSimple
	for index, value := range data {
		switch {
		case isASCIIAlphaNumeric(value) || (value == '.' && dotOkay):
			if index == 0 && value >= '0' && value <= '9' {
				mode = dataPrintable
			}
		case value >= 0x21 && value <= 0x7e || isASCIIWhitespace(value):
			if mode == dataSimple {
				mode = dataPrintable
			}
		default:
			mode = dataBinary
		}
		if mode == dataBinary {
			break
		}
	}
	if mode == dataSimple {
		if !isRequirementKeyword(string(data)) {
			return string(data)
		}
		mode = dataPrintable
	}
	if mode == dataBinary {
		return fmt.Sprintf("0x%x", data)
	}

	var out strings.Builder
	out.Grow(len(data) + 2)
	out.WriteByte('"')
	for _, value := range data {
		if value == '\\' || value == '"' {
			out.WriteByte('\\')
		}
		out.WriteByte(value)
	}
	out.WriteByte('"')
	return out.String()
}

func formatRequirementHash(data []byte) string {
	return fmt.Sprintf("H\"%x\"", data)
}

func getMatch(r *bytes.Reader) (string, error) {
	var op matchOp
	err := binary.Read(r, binary.BigEndian, &op)
	if err != nil {
		return "", err
	}

	switch op {
	case matchExists:
		return " /* exists */", nil
	case matchEqual:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " = " + formatRequirementData(data, false), nil
	case matchContains:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " ~ " + formatRequirementData(data, false), nil
	case matchBeginsWith:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " = " + formatRequirementData(data, false) + "*", nil
	case matchEndsWith:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " = *" + formatRequirementData(data, false), nil
	case matchLessThan:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " < " + formatRequirementData(data, false), nil
	case matchGreaterThan:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " > " + formatRequirementData(data, false), nil
	case matchLessEqual:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " <= " + formatRequirementData(data, false), nil
	case matchGreaterEqual:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return " >= " + formatRequirementData(data, false), nil
	case matchOn, matchBefore, matchAfter, matchOnOrBefore, matchOnOrAfter:
		var absoluteTime int64
		if err := binary.Read(r, binary.BigEndian, &absoluteTime); err != nil {
			return "", err
		}
		operator := map[matchOp]string{
			matchOn:         " = ",
			matchBefore:     " < ",
			matchAfter:      " > ",
			matchOnOrBefore: " <= ",
			matchOnOrAfter:  " >= ",
		}[op]
		return operator + formatCFAbsoluteTime(absoluteTime), nil
	case matchAbsent:
		return " absent", nil
	}
	return "", fmt.Errorf("MATCH OPCODE %d NOT UNDERSTOOD", op)
}

func formatCFAbsoluteTime(value int64) string {
	const cfAbsoluteTimeUnixEpoch = int64(978307200) // 2001-01-01 00:00:00 UTC
	if value > math.MaxInt64-cfAbsoluteTimeUnixEpoch {
		return fmt.Sprintf("<CFAbsoluteTime %d>", value)
	}
	return "<" + time.Unix(value+cfAbsoluteTimeUnixEpoch, 0).UTC().Format("2006-01-02 15:04:05 -0700") + ">"
}

func skipGenericRequirementData(r *bytes.Reader) error {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}
	if uint64(length) > uint64(r.Len()) {
		return fmt.Errorf("generic requirement payload length %d exceeds %d remaining bytes", length, r.Len())
	}
	_, err := r.Seek(int64(length), io.SeekCurrent)
	return err
}

const (
	// certificate positions (within a standard certificate chain)
	leafCert   int32 = 0  // index for leaf (first in chain)
	anchorCert int32 = -1 // index for anchor (last in chain)
)

func getCertSlot(r *bytes.Reader) (string, error) {
	var slot int32

	err := binary.Read(r, binary.BigEndian, &slot)
	if err != nil {
		return "", err
	}

	switch slot {
	case leafCert:
		return "leaf", nil
	case anchorCert:
		return "root", nil
	default:
		return fmt.Sprintf("%d", slot), nil
	}
}

const (
	slPrimary = iota // syntax primary
	slAnd            // conjunctive
	slOr             // disjunctive
	slTop            // where we start
)

func getOid(r *bytes.Reader) (uint32, error) {
	var result uint32

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return 0, err
		}
		if err != nil {
			return 0, fmt.Errorf("could not parse OID value: %v", err)
		}

		result = uint32(result*128) + uint32(b&0x7f)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}
	}

	return result, nil
}

// NOTE:
// ref https://opensource.apple.com/source/Security/Security-59306.80.4/
// ref http://oid-info.com/get/1.2.840.113635.100.6.2.6
func toOID(data []byte) string {
	var oidStr strings.Builder

	r := bytes.NewReader(data)

	oid1, err := getOid(r)
	if err != nil {
		return ""
	}

	q1 := uint32(math.Min(float64(oid1)/40, 2))
	oidStr.WriteString(fmt.Sprintf("%d.%d", q1, oid1-q1*40))

	for {
		oid, err := getOid(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}

		oidStr.WriteString(fmt.Sprintf(".%d", uint32(oid)))
	}

	return oidStr.String()
}

func evalExpression(r *bytes.Reader, syntaxLevel, depth int) (string, error) {
	depth--
	if depth <= 0 {
		return "", fmt.Errorf("requirement expression exceeds stack limit %d", requirementStackLimit)
	}

	var op exprOp

	err := binary.Read(r, binary.BigEndian, &op)
	if err != nil {
		return "", err
	}

	switch op & ^opFlagMask {
	case opFalse:
		return "never", nil
	case opTrue:
		return "always", nil
	case opIdent:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return "identifier " + formatRequirementData(data, false), nil
	case opAppleAnchor:
		return "anchor apple", nil
	case opAppleGenericAnchor:
		return "anchor apple generic", nil
	case opAnchorHash:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s = %s", slot, formatRequirementHash(data)), nil
	case opInfoKeyValue:
		dot, err := getData(r)
		if err != nil {
			return "", err
		}
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("info[%s] = %s", formatRequirementData(dot, true), formatRequirementData(data, false)), nil
	case opAnd:
		var out string
		if syntaxLevel < slAnd {
			out += "("
		}
		part, err := evalExpression(r, slAnd, depth)
		if err != nil {
			return "", err
		}
		out += part
		out += " and "
		part, err = evalExpression(r, slAnd, depth)
		if err != nil {
			return "", err
		}
		out += part
		if syntaxLevel < slAnd {
			out += ")"
		}
		return out, nil
	case opOr:
		var out string
		if syntaxLevel < slOr {
			out += "("
		}
		part, err := evalExpression(r, slOr, depth)
		if err != nil {
			return "", err
		}
		out += part
		out += " or "
		part, err = evalExpression(r, slOr, depth)
		if err != nil {
			return "", err
		}
		out += part
		if syntaxLevel < slOr {
			out += ")"
		}
		return out, nil
	case opNot:
		part, err := evalExpression(r, slPrimary, depth)
		if err != nil {
			return "", err
		}
		return "! " + part, nil
	case opCDHash:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return "cdhash " + formatRequirementHash(data), nil
	case opInfoKeyField:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("info[%s]%s", formatRequirementData(data, true), match), nil
	case opEntitlementField:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("entitlement[%s]%s", formatRequirementData(data, true), match), nil
	case opCertField:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s[%s]%s", slot, formatRequirementData(data, true), match), nil
	case opCertGeneric:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s[field.%s]%s", slot, toOID(data), match), nil
	case opCertPolicy:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s[policy.%s]%s", slot, toOID(data), match), nil
	case opTrustedCert:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s trusted", slot), nil
	case opTrustedCerts:
		return "anchor trusted", nil
	case opNamedAnchor:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return "anchor apple " + formatRequirementData(data, false), nil
	case opNamedCode:
		data, err := getData(r)
		if err != nil {
			return "", err
		}
		return "(" + formatRequirementData(data, false) + ")", nil
	case opPlatform:
		var platform int32
		if err := binary.Read(r, binary.BigEndian, &platform); err != nil {
			return "", err
		}
		return fmt.Sprintf("platform = %d", platform), nil
	case opNotarized:
		return "notarized", nil
	case opCertFieldDate:
		slot, err := getCertSlot(r)
		if err != nil {
			return "", err
		}
		oid, err := getData(r)
		if err != nil {
			return "", err
		}
		match, err := getMatch(r)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("certificate %s[timestamp.%s]%s", slot, toOID(oid), match), nil
	case opLegacyDevID:
		return "legacy", nil
	default:
		if (op & opGenericFalse) != 0 {
			if err := skipGenericRequirementData(r); err != nil {
				return "", err
			}
			return fmt.Sprintf("false /* opcode %d */", op & ^opFlagMask), nil
		} else if (op & opGenericSkip) != 0 {
			if err := skipGenericRequirementData(r); err != nil {
				return "", err
			}
			return evalExpression(r, syntaxLevel, depth)
		}
		return "", fmt.Errorf("OPCODE %d NOT UNDERSTOOD", op)
	}
}

// ParseRequirements parses the requirements set bytes
func ParseRequirements(r *bytes.Reader, reqs Requirements) (string, error) {
	// NOTE: codesign -d -r- MACHO (to display requirement sets)
	if _, err := r.Seek(int64(reqs.Offset), io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to %s expression at offset %#x: %w", reqs.Type, reqs.Offset, err)
	}

	var prefix string
	switch reqs.Type {
	case HostRequirementType:
		prefix = "host => "
	case GuestRequirementType:
		prefix = "guest => "
	case DesignatedRequirementType:
		// Preserve the historical Detail format for designated requirements.
	case LibraryRequirementType:
		prefix = "library => "
	case PluginRequirementType:
		prefix = "plugin => "
	default:
		return "", fmt.Errorf("failed to dump requirements set; found unsupported codesign requirement type '%s', please notify author", reqs.Type)
	}

	detail, err := evalExpression(r, slTop, requirementStackLimit)
	if err != nil {
		return "", err
	}
	if r.Len() != 0 {
		return "", fmt.Errorf("requirement expression has %d trailing bytes", r.Len())
	}
	return prefix + detail, nil
}

// CreateRequirements creates a requirements set cs blob
// NOTE: /usr/bin/csreq -r="identifier com.foo.test" -t (to test it out)
func CreateRequirements(id string, certs []*x509.Certificate, adhoc bool) (Blob, error) {

	if len(id) == 0 || adhoc { // empty requirements set
		return NewBlob(MAGIC_REQUIREMENTS, make([]byte, 4)), nil
	}

	var ops []uint32
	var statements [][]uint32

	// add identifier
	ops = append(ops, uint32(opIdent))
	ops = append(ops, encodeBytes([]byte(id))...)
	statements = append(statements, ops)

	// add on "anchor apple generic"
	for _, cert := range certs {
		if len(cert.Subject.Organization) > 0 && cert.Subject.Organization[0] == "Apple Inc." {
			statements = append(statements, []uint32{uint32(opAppleGenericAnchor)})
			break
		}
	}

	// add appleCertificateExtensions cert extension check
	developerIdCAExtensionOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6}
	wwdrCAExtensionOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
	developerIdApplicationExtensionOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 13}

	var leafCert *x509.Certificate
	if len(certs) > 0 && !certs[len(certs)-1].IsCA {
		leafCert = certs[len(certs)-1]
	}

	// if any intermediate is an apple signing ca, add appropriate expressions
	for idx, cert := range certs {
		if !cert.IsCA {
			continue
		}
		slotIndex := uint32(idx)
		if idx == 0 {
			slotIndex = anchorCertIndex
		}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(developerIdCAExtensionOID) { // production certificate
				ops := []uint32{uint32(opCertGeneric), slotIndex}
				ops = append(ops, encodeBytes(encodeOID(developerIdCAExtensionOID))...)
				ops = append(ops, uint32(matchExists))
				statements = append(statements, ops)

				if leafCert == nil {
					break
				}

				// add on signing purpose check
				for _, ext := range leafCert.Extensions {
					if ext.Id.Equal(developerIdApplicationExtensionOID) {
						ops := []uint32{uint32(opCertGeneric), leafCertIndex}
						ops = append(ops, encodeBytes(encodeOID(developerIdApplicationExtensionOID))...)
						ops = append(ops, uint32(matchExists))
						statements = append(statements, ops)
					}
				}
				// add on subject OU check
				if len(leafCert.Subject.OrganizationalUnit) > 0 {
					ops := []uint32{uint32(opCertField), leafCertIndex}
					ops = append(ops, encodeBytes([]byte("subject.OU"))...)
					ops = append(ops, uint32(matchEqual))
					ops = append(ops, encodeBytes([]byte(leafCert.Subject.OrganizationalUnit[0]))...)
					statements = append(statements, ops)
				}
			} else if ext.Id.Equal(wwdrCAExtensionOID) { // developer certificate
				ops := []uint32{uint32(opCertGeneric), slotIndex}
				ops = append(ops, encodeBytes(encodeOID(wwdrCAExtensionOID))...)
				ops = append(ops, uint32(matchExists))
				statements = append(statements, ops)

				// add on subject CN check
				if leafCert != nil && len(leafCert.Subject.CommonName) > 0 {
					var ops []uint32
					ops = append(ops, uint32(opCertField))
					ops = append(ops, leafCertIndex)
					ops = append(ops, encodeBytes([]byte("subject.CN"))...)
					ops = append(ops, uint32(matchEqual))
					ops = append(ops, encodeBytes([]byte(leafCert.Subject.CommonName))...)
					statements = append(statements, ops)
				}
			}
		}
	}

	// and-conjoin all statements
	var finalOps []uint32
	for i := 0; i < len(statements); i++ {
		if i < len(statements)-1 {
			finalOps = append(finalOps, uint32(opAnd))
		}
		finalOps = append(finalOps, statements[i]...)
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		return Blob{}, err
	}
	if err := binary.Write(&buf, binary.BigEndian, Requirements{
		Type:   DesignatedRequirementType,
		Offset: uint32(binary.Size(RequirementsBlob{}) + binary.Size(Requirements{})),
	}); err != nil {
		return Blob{}, err
	}
	if err := binary.Write(&buf, binary.BigEndian, RequirementsBlob{
		Magic:  MAGIC_REQUIREMENT,
		Length: uint32(binary.Size(RequirementsBlob{}) + binary.Size(finalOps)),
		Data:   1,
	}); err != nil {
		return Blob{}, err
	}
	if err := binary.Write(&buf, binary.BigEndian, finalOps); err != nil {
		return Blob{}, err
	}

	return Blob{
		BlobHeader: BlobHeader{
			Magic:  MAGIC_REQUIREMENTS,
			Length: uint32(binary.Size(BlobHeader{}) + buf.Len()),
		},
		Data: buf.Bytes(),
	}, nil
}

func encodeOID(oid asn1.ObjectIdentifier) []byte {
	res, err := asn1.Marshal(oid)
	if err != nil {
		panic(fmt.Errorf("asn1.Marshal could not marshal object identifier %v: %w", oid, err))
	}
	return res[2:] // strip leading type tag and length
}

func encodeBytes(in []byte) []uint32 {
	var ops []uint32
	ops = append(ops, uint32(len(in)))
	if (len(in) % 4) != 0 {
		pad := make([]byte, 4-(len(in)%4))
		in = append(in, pad...)
	}
	data := make([]uint32, len(in)/binary.Size(uint32(0)))
	binary.Read(bytes.NewReader(in), binary.BigEndian, &data)
	ops = append(ops, data...)
	return ops
}
