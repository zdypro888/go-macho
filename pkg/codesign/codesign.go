package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"

	"github.com/zdypro888/go-macho/pkg/codesign/types"
	mtypes "github.com/zdypro888/go-macho/types"
)

// CodeSignature object
type CodeSignature struct {
	CodeDirectories              []types.CodeDirectory     `json:"code_directories,omitempty"`
	Requirements                 []types.Requirement       `json:"requirements,omitempty"`
	CMSSignature                 []byte                    `json:"cms_signature,omitempty"`
	Entitlements                 string                    `json:"entitlements,omitempty"`
	EntitlementsDER              []byte                    `json:"entitlements_der,omitempty"`
	LaunchConstraintsSelf        []byte                    `json:"launch_constraints_self,omitempty"`
	LaunchConstraintsParent      []byte                    `json:"launch_constraints_parent,omitempty"`
	LaunchConstraintsResponsible []byte                    `json:"launch_constraints_responsible,omitempty"`
	LibraryConstraints           []byte                    `json:"library_constraints,omitempty"`
	RawComponents                map[types.SlotType][]byte `json:"raw_components,omitempty"`
	Errors                       []error                   `json:"errors,omitempty"`
}

// PrimaryCodeDirectory returns the CodeDirectory stored in the primary
// SuperBlob slot. CodeDirectories is kept primary-first for compatibility,
// but callers should use this method rather than depending on wire order.
func (cs *CodeSignature) PrimaryCodeDirectory() *types.CodeDirectory {
	for i := range cs.CodeDirectories {
		if cs.CodeDirectories[i].Slot == types.CSSLOT_CODEDIRECTORY {
			return &cs.CodeDirectories[i]
		}
	}
	return nil
}

// MarshalJSON custom JSON marshaller for CodeSignature
func (cs *CodeSignature) MarshalJSON() ([]byte, error) {
	var (
		err                         error
		lcself, lcpar, lcresp, libc *types.LaunchContraints
	)
	if len(cs.LaunchConstraintsSelf) > 0 {
		lcself, err = types.ParseLaunchContraints(cs.LaunchConstraintsSelf)
		if err != nil {
			return nil, fmt.Errorf("failed to parse launch constraints (self): %w", err)
		}
	}
	if len(cs.LaunchConstraintsParent) > 0 {
		lcpar, err = types.ParseLaunchContraints(cs.LaunchConstraintsParent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse launch constraints (self): %w", err)
		}
	}
	if len(cs.LaunchConstraintsResponsible) > 0 {
		lcresp, err = types.ParseLaunchContraints(cs.LaunchConstraintsResponsible)
		if err != nil {
			return nil, fmt.Errorf("failed to parse launch constraints (self): %w", err)
		}
	}
	if len(cs.LibraryConstraints) > 0 {
		libc, err = types.ParseLaunchContraints(cs.LibraryConstraints)
		if err != nil {
			return nil, fmt.Errorf("failed to parse launch constraints (self): %w", err)
		}
	}
	return json.Marshal(&struct {
		CodeDirectories              []types.CodeDirectory     `json:"code_directories,omitempty"`
		Requirements                 []types.Requirement       `json:"requirements,omitempty"`
		CMSSignature                 []byte                    `json:"cms_signature,omitempty"`
		Entitlements                 string                    `json:"entitlements,omitempty"`
		EntitlementsDER              []byte                    `json:"entitlements_der,omitempty"`
		LaunchConstraintsSelf        *types.LaunchContraints   `json:"launch_constraints_self,omitempty"`
		LaunchConstraintsParent      *types.LaunchContraints   `json:"launch_constraints_parent,omitempty"`
		LaunchConstraintsResponsible *types.LaunchContraints   `json:"launch_constraints_responsible,omitempty"`
		LibraryConstraints           *types.LaunchContraints   `json:"library_constraints,omitempty"`
		RawComponents                map[types.SlotType][]byte `json:"raw_components,omitempty"`
		Errors                       []string                  `json:"errors,omitempty"`
	}{
		CodeDirectories:              cs.CodeDirectories,
		Requirements:                 cs.Requirements,
		CMSSignature:                 cs.CMSSignature,
		Entitlements:                 cs.Entitlements,
		EntitlementsDER:              cs.EntitlementsDER,
		LaunchConstraintsSelf:        lcself,
		LaunchConstraintsParent:      lcpar,
		LaunchConstraintsResponsible: lcresp,
		LibraryConstraints:           libc,
		RawComponents:                cs.RawComponents,
		Errors: func() []string {
			var errs []string
			for _, e := range cs.Errors {
				errs = append(errs, e.Error())
			}
			return errs
		}(),
	})
}

// ParseCodeSignature parses the LC_CODE_SIGNATURE data
func ParseCodeSignature(cmddat []byte) (*CodeSignature, error) {
	r := bytes.NewReader(cmddat)
	cs := &CodeSignature{}
	var superBlobLength uint32
	payloadLen := func(total uint32, headerSize int, baseOffset uint32) (int, error) {
		if total < uint32(headerSize) {
			return 0, fmt.Errorf("invalid blob length %d (header %d)", total, headerSize)
		}
		if uint64(baseOffset)+uint64(total) > uint64(superBlobLength) {
			return 0, fmt.Errorf("blob length %d exceeds code signature data", total)
		}
		return int(total) - headerSize, nil
	}

	csBlob := types.SuperBlob{}
	if err := binary.Read(r, binary.BigEndian, &csBlob.SbHeader); err != nil {
		return nil, err
	}
	switch csBlob.Magic {
	case types.MAGIC_EMBEDDED_SIGNATURE, types.MAGIC_EMBEDDED_SIGNATURE_OLD:
		// Both values are defined embedded-signature containers. The old magic
		// remains accepted for legacy Mach-O inputs.
	default:
		return nil, fmt.Errorf("invalid embedded code signature SuperBlob magic: %s", csBlob.Magic)
	}
	const superBlobHeaderSize = uint64(12)
	if csBlob.Length < uint32(superBlobHeaderSize) || uint64(csBlob.Length) > uint64(len(cmddat)) {
		return nil, fmt.Errorf("invalid code signature SuperBlob length %d (data size %d)", csBlob.Length, len(cmddat))
	}
	indexBytes := uint64(csBlob.Count) * uint64(binary.Size(types.BlobIndex{}))
	indexEnd := superBlobHeaderSize + indexBytes
	if indexEnd > uint64(csBlob.Length) {
		return nil, fmt.Errorf("code signature SuperBlob count %d exceeds declared length %d", csBlob.Count, csBlob.Length)
	}
	superBlobLength = csBlob.Length

	csIndex := make([]types.BlobIndex, csBlob.Count)
	if err := binary.Read(r, binary.BigEndian, &csIndex); err != nil {
		return nil, err
	}

	// SuperBlobCore::validateBlob requires every non-null child offset to start
	// after the complete index vector and requires each child's declared extent
	// to fit inside the enclosing SuperBlob. Do this for every index, including
	// duplicate and unknown types, before applying typed lookup semantics below.
	for _, index := range csIndex {
		if index.Offset == 0 {
			continue
		}
		if uint64(index.Offset) < indexEnd {
			return nil, fmt.Errorf("code signature slot %s offset %#x overlaps index table ending at %#x", index.Type, index.Offset, indexEnd)
		}
		if uint64(index.Offset)+uint64(binary.Size(types.BlobHeader{})) > uint64(superBlobLength) {
			return nil, fmt.Errorf("code signature slot %s offset %#x exceeds declared length %d", index.Type, index.Offset, superBlobLength)
		}
		var header types.BlobHeader
		if err := binary.Read(bytes.NewReader(cmddat[index.Offset:uint64(index.Offset)+uint64(binary.Size(header))]), binary.BigEndian, &header); err != nil {
			return nil, fmt.Errorf("failed to read code signature slot %s header at %#x: %w", index.Type, index.Offset, err)
		}
		if uint64(index.Offset)+uint64(header.Length) > uint64(superBlobLength) {
			return nil, fmt.Errorf("code signature slot %s length %d at %#x exceeds declared length %d", index.Type, header.Length, index.Offset, superBlobLength)
		}
	}

	// SuperBlobCore::find scans in index order and returns the first matching
	// type. Preserve that first-wins behavior for every slot type. Later entries
	// remain visible as diagnostics but cannot replace the component Apple uses.
	seenSlots := make(map[types.SlotType]struct{}, len(csIndex))
	for _, index := range csIndex {
		if _, duplicate := seenSlots[index.Type]; duplicate {
			cs.Errors = append(cs.Errors, fmt.Errorf("duplicate code signature slot %s ignored; first index entry wins", index.Type))
			continue
		}
		seenSlots[index.Type] = struct{}{}
		if index.Offset == 0 {
			continue
		}
		if _, err := r.Seek(int64(index.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to code signature slot %s at %#x: %w", index.Type, index.Offset, err)
		}

		if index.Type == types.CSSLOT_CODEDIRECTORY ||
			(index.Type >= types.CSSLOT_ALTERNATE_CODEDIRECTORIES &&
				index.Type < types.CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT) {
			cd, err := parseCodeDirectory(r, index.Offset, uint64(superBlobLength))
			if err != nil {
				return nil, err
			}
			cd.Slot = index.Type
			if index.Type == types.CSSLOT_CODEDIRECTORY {
				// The SuperBlob index is explicitly unordered. Preserve the public
				// primary-first convention without losing each directory's slot.
				cs.CodeDirectories = append(cs.CodeDirectories, types.CodeDirectory{})
				copy(cs.CodeDirectories[1:], cs.CodeDirectories[:len(cs.CodeDirectories)-1])
				cs.CodeDirectories[0] = *cd
			} else {
				cs.CodeDirectories = append(cs.CodeDirectories, *cd)
			}
			continue
		}

		switch index.Type {
		case types.CSSLOT_REQUIREMENTS:
			requirements, err := parseRequirementsSlot(cmddat, index.Offset, superBlobLength)
			if err != nil {
				return nil, err
			}
			cs.Requirements = append(cs.Requirements, requirements...)
		case types.CSSLOT_ENTITLEMENTS:
			entBlob := types.BlobHeader{}
			if err := binary.Read(r, binary.BigEndian, &entBlob); err != nil {
				return nil, err
			}
			if entBlob.Magic != types.MAGIC_EMBEDDED_ENTITLEMENTS {
				return nil, fmt.Errorf("invalid CSSLOT_ENTITLEMENTS blob magic: %s", entBlob.Magic)
			}
			plistLen, err := payloadLen(entBlob.Length, binary.Size(entBlob), index.Offset)
			if err != nil {
				return nil, err
			}
			plistData := make([]byte, plistLen)
			if err := binary.Read(r, binary.BigEndian, &plistData); err != nil {
				return nil, err
			}
			cs.Entitlements = string(plistData)
		case types.CSSLOT_CMS_SIGNATURE:
			cmsBlob := types.BlobHeader{}
			if err := binary.Read(r, binary.BigEndian, &cmsBlob); err != nil {
				return nil, err
			}
			if cmsBlob.Magic != types.MAGIC_BLOBWRAPPER {
				return nil, fmt.Errorf("invalid CSSLOT_CMS_SIGNATURE blob magic: %s", cmsBlob.Magic)
			}
			cmsLen, err := payloadLen(cmsBlob.Length, binary.Size(cmsBlob), index.Offset)
			if err != nil {
				return nil, err
			}
			cmsData := make([]byte, cmsLen)
			if err := binary.Read(r, binary.BigEndian, &cmsData); err != nil {
				return nil, err
			}
			// NOTE: openssl pkcs7 -inform DER -in <cmsData> -print_certs -text -noout
			cs.CMSSignature = cmsData
		case types.CSSLOT_ENTITLEMENTS_DER:
			entDerBlob := types.BlobHeader{}
			if err := binary.Read(r, binary.BigEndian, &entDerBlob); err != nil {
				return nil, err
			}
			if entDerBlob.Magic != types.MAGIC_EMBEDDED_ENTITLEMENTS_DER {
				return nil, fmt.Errorf("invalid CSSLOT_ENTITLEMENTS_DER blob magic: %s", entDerBlob.Magic)
			}
			entDerLen, err := payloadLen(entDerBlob.Length, binary.Size(entDerBlob), index.Offset)
			if err != nil {
				return nil, err
			}
			entDerData := make([]byte, entDerLen)
			if err := binary.Read(r, binary.BigEndian, &entDerData); err != nil {
				return nil, err
			}
			cs.EntitlementsDER = entDerData
		case types.CSSLOT_INFOSLOT, types.CSSLOT_RESOURCEDIR, types.CSSLOT_APPLICATION,
			types.CSSLOT_REP_SPECIFIC, types.CSSLOT_IDENTIFICATIONSLOT, types.CSSLOT_TICKETSLOT:
			rawBlob := types.BlobHeader{}
			if err := binary.Read(r, binary.BigEndian, &rawBlob); err != nil {
				return nil, err
			}
			if rawBlob.Magic != types.MAGIC_BLOBWRAPPER {
				return nil, fmt.Errorf("invalid %s raw-component blob magic: %s", index.Type, rawBlob.Magic)
			}
			rawLen, err := payloadLen(rawBlob.Length, binary.Size(rawBlob), index.Offset)
			if err != nil {
				return nil, err
			}
			rawData := make([]byte, rawLen)
			if err := binary.Read(r, binary.BigEndian, &rawData); err != nil {
				return nil, err
			}
			if cs.RawComponents == nil {
				cs.RawComponents = make(map[types.SlotType][]byte)
			}
			cs.RawComponents[index.Type] = rawData
		case types.CSSLOT_LAUNCH_CONSTRAINT_SELF, types.CSSLOT_LAUNCH_CONSTRAINT_PARENT, types.CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE, types.CSSLOT_LIBRARY_CONSTRAINT:
			lcBlob := types.BlobHeader{}
			if err := binary.Read(r, binary.BigEndian, &lcBlob); err != nil {
				return nil, err
			}
			if lcBlob.Magic != types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT {
				return nil, fmt.Errorf("invalid CSSLOT_LAUNCH_CONSTRAINT_SELF blob magic: %s", lcBlob.Magic)
			}
			lcLen, err := payloadLen(lcBlob.Length, binary.Size(lcBlob), index.Offset)
			if err != nil {
				return nil, err
			}
			lcData := make([]byte, lcLen)
			if err := binary.Read(r, binary.BigEndian, &lcData); err != nil {
				return nil, err
			}
			switch index.Type {
			case types.CSSLOT_LAUNCH_CONSTRAINT_SELF:
				cs.LaunchConstraintsSelf = lcData
			case types.CSSLOT_LAUNCH_CONSTRAINT_PARENT:
				cs.LaunchConstraintsParent = lcData
			case types.CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE:
				cs.LaunchConstraintsResponsible = lcData
			case types.CSSLOT_LIBRARY_CONSTRAINT:
				cs.LibraryConstraints = lcData
			}
		default:
			cs.Errors = append(cs.Errors, fmt.Errorf("unknown slot type: %s, please notify author", index.Type))
		}
	}
	return cs, nil
}

func parseRequirementsSlot(data []byte, slotOffset, superBlobLength uint32) ([]types.Requirement, error) {
	const (
		requirementsHeaderSize = uint64(12) // magic, length, count/kind
		requirementIndexSize   = uint64(8)  // type, offset
	)
	if uint64(superBlobLength) > uint64(len(data)) {
		return nil, fmt.Errorf("requirements superblob length %d exceeds code signature data size %d", superBlobLength, len(data))
	}
	if uint64(slotOffset)+requirementsHeaderSize > uint64(superBlobLength) {
		return nil, fmt.Errorf("requirements slot offset %#x has no complete header", slotOffset)
	}

	var outer types.RequirementsBlob
	if err := binary.Read(bytes.NewReader(data[slotOffset:uint64(slotOffset)+requirementsHeaderSize]), binary.BigEndian, &outer); err != nil {
		return nil, fmt.Errorf("failed to read requirements header: %w", err)
	}
	if outer.Magic != types.MAGIC_REQUIREMENT && outer.Magic != types.MAGIC_REQUIREMENTS {
		return nil, fmt.Errorf("invalid CSSLOT_REQUIREMENTS blob magic: %s", outer.Magic)
	}
	if uint64(outer.Length) < requirementsHeaderSize || uint64(slotOffset)+uint64(outer.Length) > uint64(superBlobLength) {
		return nil, fmt.Errorf("requirements blob length %d at %#x exceeds declared code signature length %d", outer.Length, slotOffset, superBlobLength)
	}
	slot := data[slotOffset : uint64(slotOffset)+uint64(outer.Length)]

	parseInner := func(index types.Requirements, innerOffset uint64) (types.Requirement, error) {
		if innerOffset+requirementsHeaderSize > uint64(len(slot)) {
			return types.Requirement{}, fmt.Errorf("%s blob offset %#x has no complete requirement header", index.Type, innerOffset)
		}
		var inner types.RequirementsBlob
		if err := binary.Read(bytes.NewReader(slot[innerOffset:innerOffset+requirementsHeaderSize]), binary.BigEndian, &inner); err != nil {
			return types.Requirement{}, fmt.Errorf("failed to read %s blob at %#x: %w", index.Type, innerOffset, err)
		}
		if inner.Magic != types.MAGIC_REQUIREMENT {
			return types.Requirement{}, fmt.Errorf("%s entry at %#x has invalid inner magic %s", index.Type, innerOffset, inner.Magic)
		}
		if uint64(inner.Length) < requirementsHeaderSize || innerOffset+uint64(inner.Length) > uint64(len(slot)) {
			return types.Requirement{}, fmt.Errorf("%s blob [%#x,%#x) exceeds requirements vector length %#x", index.Type, innerOffset, innerOffset+uint64(inner.Length), len(slot))
		}

		innerData := slot[innerOffset : innerOffset+uint64(inner.Length)]
		switch inner.Data {
		case 1: // Requirement::exprForm
			if uint64(inner.Length) < requirementsHeaderSize+4 {
				return types.Requirement{}, fmt.Errorf("%s expression blob at %#x has no complete opcode", index.Type, innerOffset)
			}
			parseIndex := index
			parseIndex.Offset = uint32(requirementsHeaderSize)
			detail, err := types.ParseRequirements(bytes.NewReader(innerData), parseIndex)
			if err != nil {
				return types.Requirement{}, fmt.Errorf("failed to parse %s blob at %#x: %w", index.Type, innerOffset, err)
			}
			return types.Requirement{
				RequirementsBlob: outer,
				Requirements:     index,
				Detail:           detail,
			}, nil
		case 2: // Requirement::lwcrForm (DER lightweight code requirement)
			return types.Requirement{
				RequirementsBlob: outer,
				Requirements:     index,
				Detail:           "lightweight code requirement (opaque DER)",
				Opaque: &types.OpaqueRequirement{
					RequirementsBlob: inner,
					Payload:          append([]byte(nil), innerData[requirementsHeaderSize:]...),
				},
			}, nil
		default:
			return types.Requirement{}, fmt.Errorf("%s blob at %#x uses unsupported requirement kind %d", index.Type, innerOffset, inner.Data)
		}
	}

	if outer.Magic == types.MAGIC_REQUIREMENT {
		index := types.Requirements{Type: types.DesignatedRequirementType, Offset: uint32(requirementsHeaderSize)}
		req, err := parseInner(index, 0)
		if err != nil {
			return nil, err
		}
		return []types.Requirement{req}, nil
	}

	count := uint64(outer.Data)
	indexEnd := requirementsHeaderSize + count*requirementIndexSize
	if indexEnd < requirementsHeaderSize || indexEnd > uint64(len(slot)) {
		return nil, fmt.Errorf("requirements vector count %d exceeds blob length %d", count, len(slot))
	}
	if count == 0 {
		return []types.Requirement{{RequirementsBlob: outer, Detail: "empty requirement set"}}, nil
	}

	requirements := make([]types.Requirement, 0, int(count))
	for i := uint64(0); i < count; i++ {
		indexOffset := requirementsHeaderSize + i*requirementIndexSize
		var index types.Requirements
		if err := binary.Read(bytes.NewReader(slot[indexOffset:indexOffset+requirementIndexSize]), binary.BigEndian, &index); err != nil {
			return nil, fmt.Errorf("failed to read requirements vector index %d: %w", i, err)
		}
		if uint64(index.Offset) < indexEnd {
			return nil, fmt.Errorf("requirements vector index %d offset %#x overlaps index table ending at %#x", i, index.Offset, indexEnd)
		}
		req, err := parseInner(index, uint64(index.Offset))
		if err != nil {
			return nil, fmt.Errorf("requirements vector index %d: %w", i, err)
		}
		requirements = append(requirements, req)
	}
	return requirements, nil
}

func parseCodeDirectory(r *bytes.Reader, offset uint32, maxSize uint64) (*types.CodeDirectory, error) {
	var cd types.CodeDirectory
	const blobHeaderSize = uint64(8)
	if maxSize > uint64(r.Size()) {
		return nil, fmt.Errorf("CodeDirectory container size %d exceeds reader size %d", maxSize, r.Size())
	}
	if uint64(offset)+blobHeaderSize > maxSize {
		return nil, fmt.Errorf("CodeDirectory offset %#x exceeds code signature data", offset)
	}

	headerData := make([]byte, blobHeaderSize)
	if _, err := r.ReadAt(headerData, int64(offset)); err != nil {
		return nil, fmt.Errorf("failed to read CodeDirectory header at %#x: %w", offset, err)
	}
	if err := binary.Read(bytes.NewReader(headerData), binary.BigEndian, &cd.BlobHeader); err != nil {
		return nil, err
	}
	if cd.BlobHeader.Magic != types.MAGIC_CODEDIRECTORY {
		return nil, fmt.Errorf("invalid CSSLOT_(ALTERNATE_)CODEDIRECTORY blob magic: %#x", cd.BlobHeader.Magic)
	}
	minimumLength := blobHeaderSize + uint64(binary.Size(cd.Header.CdEarliest))
	if uint64(cd.BlobHeader.Length) < minimumLength {
		return nil, fmt.Errorf("invalid CodeDirectory length %d (minimum %d)", cd.BlobHeader.Length, minimumLength)
	}
	if uint64(offset)+uint64(cd.BlobHeader.Length) > maxSize {
		return nil, fmt.Errorf("CodeDirectory length %d exceeds code signature data", cd.BlobHeader.Length)
	}

	cdData := make([]byte, int(cd.BlobHeader.Length))
	if _, err := r.ReadAt(cdData, int64(offset)); err != nil {
		return nil, fmt.Errorf("failed to read CodeDirectory data at %#x: %w", offset, err)
	}
	cdReader := bytes.NewReader(cdData[blobHeaderSize:])
	if err := binary.Read(cdReader, binary.BigEndian, &cd.Header.CdEarliest); err != nil {
		return nil, fmt.Errorf("failed to read CodeDirectory earliest header: %w", err)
	}
	if cd.Header.Version < types.EARLIEST_VERSION {
		return nil, fmt.Errorf("unsupported CodeDirectory version %#x (earliest %#x)", uint32(cd.Header.Version), uint32(types.EARLIEST_VERSION))
	}
	if cd.Header.Version > types.COMPATIBILITY_LIMIT {
		return nil, fmt.Errorf("unsupported CodeDirectory version %#x (compatibility limit %#x)", uint32(cd.Header.Version), uint32(types.COMPATIBILITY_LIMIT))
	}
	cd.CodeLimit = uint64(cd.Header.CodeLimit)

	readVersionedHeader := func(name string, value any) error {
		if err := binary.Read(cdReader, binary.BigEndian, value); err != nil {
			return fmt.Errorf("CodeDirectory %s header exceeds blob length %d: %w", name, cd.BlobHeader.Length, err)
		}
		return nil
	}
	if cd.Header.Version >= types.SUPPORTS_SCATTER {
		if err := readVersionedHeader("scatter", &cd.Header.CdScatter); err != nil {
			return nil, err
		}
	}
	if cd.Header.Version >= types.SUPPORTS_TEAMID {
		if err := readVersionedHeader("team ID", &cd.Header.CdTeamID); err != nil {
			return nil, err
		}
	}
	if cd.Header.Version >= types.SUPPORTS_CODELIMIT64 {
		if err := readVersionedHeader("64-bit code limit", &cd.Header.CdCodeLimit64); err != nil {
			return nil, err
		}
		if cd.Header.CodeLimit64 > 0 {
			cd.CodeLimit = cd.Header.CodeLimit64
		}
	}
	if cd.Header.Version >= types.SUPPORTS_EXECSEG {
		if err := readVersionedHeader("exec segment", &cd.Header.CdExecSeg); err != nil {
			return nil, err
		}
	}
	if cd.Header.Version >= types.SUPPORTS_RUNTIME {
		if err := readVersionedHeader("runtime", &cd.Header.CdRuntime); err != nil {
			return nil, err
		}
		cd.RuntimeVersion = cd.Header.Runtime.String()
	}
	if cd.Header.Version >= types.SUPPORTS_LINKAGE {
		if err := readVersionedHeader("linkage", &cd.Header.CdLinkage); err != nil {
			return nil, err
		}
	}

	// Calculate the cdhash only after the declared blob has been bounded and
	// read. Apple defines CDHash as the first 20 bytes of the CodeDirectory's
	// selected digest, even when the underlying digest is wider.
	var digest []byte
	switch cd.Header.HashType {
	case types.HASHTYPE_SHA1:
		sum := sha1.Sum(cdData)
		digest = sum[:]
	case types.HASHTYPE_SHA256, types.HASHTYPE_SHA256_TRUNCATED:
		sum := sha256.Sum256(cdData)
		digest = sum[:]
	case types.HASHTYPE_SHA384:
		sum := sha512.Sum384(cdData)
		digest = sum[:]
	default:
		cd.CDHash = fmt.Sprintf("unsupported code directory hash type %s, please notify author", cd.Header.HashType)
	}
	if len(digest) != 0 {
		cd.CDHash = fmt.Sprintf("%x", digest[:min(len(digest), types.CDHASH_LEN)])
	}

	span := func(name string, start, size uint64) ([]byte, error) {
		if start > uint64(len(cdData)) || size > uint64(len(cdData))-start {
			return nil, fmt.Errorf("CodeDirectory %s range [%#x,%#x) exceeds blob length %#x", name, start, start+size, len(cdData))
		}
		return cdData[int(start):int(start+size)], nil
	}
	interiorSpan := func(name string, start, size uint64) ([]byte, error) {
		if start < blobHeaderSize {
			return nil, fmt.Errorf("CodeDirectory %s offset %#x overlaps BlobCore header", name, start)
		}
		return span(name, start, size)
	}
	cstringAt := func(name string, value uint32) (string, error) {
		data, err := span(name, uint64(value), uint64(len(cdData))-min(uint64(value), uint64(len(cdData))))
		if err != nil {
			return "", err
		}
		end := bytes.IndexByte(data, 0)
		if end < 0 {
			return "", fmt.Errorf("CodeDirectory %s at %#x is not NUL-terminated within blob length %#x", name, value, len(cdData))
		}
		return string(data[:end]), nil
	}

	if cd.Header.IdentOffset > 0 {
		id, err := cstringAt("identity", cd.Header.IdentOffset)
		if err != nil {
			return nil, err
		}
		cd.ID = id
	}

	if cd.Header.Version >= types.SUPPORTS_TEAMID && cd.Header.TeamOffset > 0 {
		teamID, err := cstringAt("team ID", cd.Header.TeamOffset)
		if err != nil {
			return nil, err
		}
		cd.TeamID = teamID
	}

	if cd.Header.Version >= types.SUPPORTS_SCATTER && cd.Header.ScatterOffset > 0 {
		scatterSize := uint64(binary.Size(types.Scatter{}))
		var pagesConsumed uint64
		for cursor := uint64(cd.Header.ScatterOffset); ; cursor += scatterSize {
			scatterData, err := interiorSpan("scatter vector", cursor, scatterSize)
			if err != nil {
				return nil, err
			}
			var entry types.Scatter
			if err := binary.Read(bytes.NewReader(scatterData), binary.BigEndian, &entry); err != nil {
				return nil, fmt.Errorf("failed to read CodeDirectory scatter vector at %#x: %w", cursor, err)
			}
			if entry.Count == 0 {
				break
			}
			codeSlots := uint64(cd.Header.NCodeSlots)
			if pagesConsumed > codeSlots || uint64(entry.Count) > codeSlots-pagesConsumed {
				return nil, fmt.Errorf("CodeDirectory scatter vector consumes more than %d code slots", cd.Header.NCodeSlots)
			}
			if len(cd.Scatters) == 0 {
				cd.Scatter = entry // retain the historical first-entry field
			}
			cd.Scatters = append(cd.Scatters, entry)
			pagesConsumed += uint64(entry.Count)
		}
	}

	hashSize := uint64(cd.Header.HashSize)
	totalSlotCount := uint64(cd.Header.NSpecialSlots) + uint64(cd.Header.NCodeSlots)
	if totalSlotCount > 0 && hashSize == 0 {
		return nil, fmt.Errorf("CodeDirectory has %d hash slots with zero hash size", totalSlotCount)
	}
	specialBytes := uint64(cd.Header.NSpecialSlots) * hashSize
	codeBytes := uint64(cd.Header.NCodeSlots) * hashSize
	hashOffset := uint64(cd.Header.HashOffset)
	if hashOffset < specialBytes {
		return nil, fmt.Errorf("CodeDirectory special slots size %#x underflows hash offset %#x", specialBytes, hashOffset)
	}
	specialStart := hashOffset - specialBytes
	hashData, err := interiorSpan("hash slots", specialStart, specialBytes+codeBytes)
	if err != nil {
		return nil, err
	}
	specialData := hashData[:int(specialBytes)]
	codeData := hashData[int(specialBytes):]

	if cd.Header.Version >= types.SUPPORTS_RUNTIME && cd.Header.PreEncryptOffset > 0 {
		preEncryptData, err := interiorSpan("pre-encrypt hash slots", uint64(cd.Header.PreEncryptOffset), codeBytes)
		if err != nil {
			return nil, err
		}
		cd.PreEncryptSlots = make([][]byte, 0, int(cd.Header.NCodeSlots))
		for slot := uint32(0); slot < cd.Header.NCodeSlots; slot++ {
			start := uint64(slot) * hashSize
			cd.PreEncryptSlots = append(cd.PreEncryptSlots, append([]byte(nil), preEncryptData[int(start):int(start+hashSize)]...))
		}
	}

	if cd.Header.Version >= types.SUPPORTS_LINKAGE {
		if cd.Header.LinkageHashType != 0 {
			linkage, err := interiorSpan("linkage data", uint64(cd.Header.LinkageOffset), uint64(cd.Header.LinkageSize))
			if err != nil {
				return nil, err
			}
			cd.LinkageData = append([]byte(nil), linkage...)
		}
	}

	zeroHash := make([]byte, int(cd.Header.HashSize))
	cd.SpecialSlots = make([]types.SpecialSlot, 0, int(cd.Header.NSpecialSlots))
	for slot := cd.Header.NSpecialSlots; slot > 0; slot-- {
		index := uint64(cd.Header.NSpecialSlots-slot) * hashSize
		hash := append([]byte(nil), specialData[int(index):int(index+hashSize)]...)
		sslot := types.SpecialSlot{Index: slot, Hash: hash}
		if bytes.Equal(hash, zeroHash) {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %-22v Not Bound", slot, types.SlotType(slot).String()+":")
		} else if bytes.Equal(hash, types.EmptySha256ReqSlot) && sslot.Index == 2 && cd.Header.HashType == types.HASHTYPE_SHA256 {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %-22v Empty Requirement Set", slot, types.SlotType(slot).String()+":")
		} else {
			sslot.Desc = fmt.Sprintf("Special Slot   %d %-22v %x", slot, types.SlotType(slot).String()+":", hash)
		}
		cd.SpecialSlots = append(cd.SpecialSlots, sslot)
	}

	if cd.Header.PageSize >= 64 {
		return nil, fmt.Errorf("CodeDirectory page-size exponent %d overflows uint64", cd.Header.PageSize)
	}
	if cd.Header.PageSize != 0 {
		if cd.CodeLimit == 0 {
			return nil, fmt.Errorf("CodeDirectory has paged hashes with zero signing limit")
		}
		coveredPages := ((cd.CodeLimit - 1) >> cd.Header.PageSize) + 1
		if coveredPages != uint64(cd.Header.NCodeSlots) {
			return nil, fmt.Errorf("CodeDirectory signing limit %#x at page exponent %d requires %d code slots, found %d", cd.CodeLimit, cd.Header.PageSize, coveredPages, cd.Header.NCodeSlots)
		}
	} else if (cd.CodeLimit > 0) != (cd.Header.NCodeSlots != 0) {
		return nil, fmt.Errorf("CodeDirectory unpaged signing limit %#x is inconsistent with %d code slots", cd.CodeLimit, cd.Header.NCodeSlots)
	}
	pageSize := uint64(1) << cd.Header.PageSize
	cd.CodeSlots = make([]types.CodeSlot, 0, int(cd.Header.NCodeSlots))
	var scatterIndex int
	var scatterSlot uint64
	for slot := uint32(0); slot < cd.Header.NCodeSlots; slot++ {
		index := uint64(slot) * hashSize
		hash := append([]byte(nil), codeData[int(index):int(index+hashSize)]...)
		cslot := types.CodeSlot{Index: slot, Hash: hash}
		if len(cd.Scatters) == 0 {
			cslot.Page = uint64(slot) * pageSize
		}
		if len(cd.Scatters) != 0 && scatterIndex < len(cd.Scatters) {
			entry := cd.Scatters[scatterIndex]
			pageNumber := uint64(entry.Base) + scatterSlot
			if pageNumber > ^uint64(0)/pageSize {
				return nil, fmt.Errorf("CodeDirectory scatter page %#x overflows", pageNumber)
			}
			cslot.Page = pageNumber * pageSize
			if scatterSlot > (^uint64(0)-entry.TargetOffset)/pageSize {
				return nil, fmt.Errorf("CodeDirectory scatter target %#x overflows", entry.TargetOffset)
			}
			cslot.TargetOffset = entry.TargetOffset + scatterSlot*pageSize
			cslot.ScatterMapped = true
			scatterSlot++
			if scatterSlot == uint64(entry.Count) {
				scatterIndex++
				scatterSlot = 0
			}
		}
		if len(cd.Scatters) != 0 && !cslot.ScatterMapped {
			cslot.Desc = fmt.Sprintf("Slot   %d (not referenced by scatter vector):\t%x", slot, hash)
		} else if bytes.Equal(hash, types.NULL_PAGE_SHA256_HASH) && cd.Header.HashType == types.HASHTYPE_SHA256 {
			cslot.Desc = fmt.Sprintf("Slot   %d (File page @0x%04X):\tNULL PAGE HASH", slot, cslot.Page)
		} else {
			cslot.Desc = fmt.Sprintf("Slot   %d (File page @0x%04X):\t%x", slot, cslot.Page, hash)
		}
		cd.CodeSlots = append(cd.CodeSlots, cslot)
	}

	return &cd, nil
}

type slotHashes struct {
	InfoPlist                    []byte
	Requirements                 []byte
	ResourceDir                  []byte
	Entitlements                 []byte
	AppSpecific                  []byte
	DmgSpecific                  []byte
	EntitlementsDER              []byte
	LaunchConstraintsSelf        []byte
	LaunchConstraintsParent      []byte
	LaunchConstraintsResponsible []byte
	LibraryConstraints           []byte
}

type Config struct {
	ID            string
	TeamID        string
	IsMain        bool
	Flags         types.CDFlag
	CodeSize      uint64
	TextOffset    uint64
	TextSize      uint64
	NSpecialSlots uint32
	SpecialSlots  []types.SpecialSlot
	// SpecialSlotsHashType and SpecialSlotsHashSize describe the CodeDirectory
	// that supplied SpecialSlots. A zero type keeps compatibility with callers
	// that historically supplied SHA-256 hashes without metadata.
	SpecialSlotsHashType         uint8
	SpecialSlotsHashSize         uint8
	InfoPlist                    []byte
	Entitlements                 []byte
	EntitlementsDER              []byte
	LaunchConstraintsSelf        []byte
	LaunchConstraintsParent      []byte
	LaunchConstraintsResponsible []byte
	LibraryConstraints           []byte
	RawComponents                map[types.SlotType][]byte
	ResourceDirSlotHash          []byte
	SlotHashes                   slotHashes
	RuntimeVersion               mtypes.Version
	CertChain                    []*x509.Certificate
	SignerFunction               func([]byte) ([]byte, error)
}

func (c *Config) InitSlotHashes() {
	c.SlotHashes = slotHashes{
		InfoPlist:                    types.EmptySha256Slot,
		Requirements:                 types.EmptySha256ReqSlot,
		ResourceDir:                  types.EmptySha256Slot,
		Entitlements:                 types.EmptySha256Slot,
		AppSpecific:                  types.EmptySha256Slot,
		DmgSpecific:                  types.EmptySha256Slot,
		EntitlementsDER:              types.EmptySha256Slot,
		LaunchConstraintsSelf:        types.EmptySha256Slot,
		LaunchConstraintsParent:      types.EmptySha256Slot,
		LaunchConstraintsResponsible: types.EmptySha256Slot,
		LibraryConstraints:           types.EmptySha256Slot,
	}
}

func specialSlotHash(slots []types.SpecialSlot, index uint32) ([]byte, bool) {
	for _, slot := range slots {
		if slot.Index == index {
			return slot.Hash, true
		}
	}
	// Preserve compatibility with callers that supplied the historical
	// descending positional slice without populating SpecialSlot.Index.
	if index > 0 && uint64(index) <= uint64(len(slots)) {
		slot := slots[len(slots)-int(index)]
		if slot.Index == 0 {
			return slot.Hash, true
		}
	}
	return nil, false
}

func isBoundSpecialSlotHash(hash []byte) bool {
	if len(hash) == 0 {
		return false
	}
	for _, value := range hash {
		if value != 0 {
			return true
		}
	}
	return false
}

func previousSpecialSlotUsesSHA256(config *Config, hash []byte) bool {
	if config.SpecialSlotsHashType == 0 {
		return len(hash) == sha256.Size
	}
	hashSize := int(config.SpecialSlotsHashSize)
	if hashSize == 0 {
		hashSize = sha256.Size
	}
	return config.SpecialSlotsHashType == uint8(types.HASHTYPE_SHA256) && hashSize == sha256.Size && len(hash) == hashSize
}

func previousSpecialSlotDigest(config *Config, data []byte, previous []byte) ([]byte, error) {
	hashType := config.SpecialSlotsHashType
	hashSize := int(config.SpecialSlotsHashSize)
	if hashType == 0 {
		switch len(previous) {
		case sha1.Size:
			hashType = uint8(types.HASHTYPE_SHA1)
			hashSize = sha1.Size
		case sha256.Size:
			hashType = uint8(types.HASHTYPE_SHA256)
			hashSize = sha256.Size
		case sha512.Size384:
			hashType = uint8(types.HASHTYPE_SHA384)
			hashSize = sha512.Size384
		default:
			return nil, fmt.Errorf("previous special slot hash has unsupported size %d without hash metadata", len(previous))
		}
	}
	if hashSize == 0 {
		switch hashType {
		case uint8(types.HASHTYPE_SHA1), uint8(types.HASHTYPE_SHA256_TRUNCATED):
			hashSize = sha1.Size
		case uint8(types.HASHTYPE_SHA256):
			hashSize = sha256.Size
		case uint8(types.HASHTYPE_SHA384):
			hashSize = sha512.Size384
		}
	}
	if hashSize != len(previous) {
		return nil, fmt.Errorf("previous special slot hash size %d does not match CodeDirectory hash size %d", len(previous), hashSize)
	}
	var digest []byte
	switch hashType {
	case uint8(types.HASHTYPE_SHA1):
		sum := sha1.Sum(data)
		digest = sum[:]
	case uint8(types.HASHTYPE_SHA256), uint8(types.HASHTYPE_SHA256_TRUNCATED):
		sum := sha256.Sum256(data)
		digest = sum[:]
	case uint8(types.HASHTYPE_SHA384):
		sum := sha512.Sum384(data)
		digest = sum[:]
	default:
		return nil, fmt.Errorf("previous special slot uses unsupported hash type %d", hashType)
	}
	if hashSize > len(digest) {
		return nil, fmt.Errorf("previous CodeDirectory hash size %d exceeds digest size %d", hashSize, len(digest))
	}
	return digest[:hashSize], nil
}

func verifyPreviousSpecialSlot(config *Config, index uint32, data []byte) error {
	previous, ok := specialSlotHash(config.SpecialSlots, index)
	if !ok || !isBoundSpecialSlotHash(previous) {
		return nil
	}
	digest, err := previousSpecialSlotDigest(config, data, previous)
	if err != nil {
		return fmt.Errorf("failed to verify previous special slot %d: %w", index, err)
	}
	if !bytes.Equal(previous, digest) {
		return fmt.Errorf("previous and calculated special slot %d hashes do not match", index)
	}
	return nil
}

func verifyPreviousBlobSpecialSlot(config *Config, index uint32, blob types.Blob) error {
	data, err := blob.Bytes()
	if err != nil {
		return fmt.Errorf("failed to encode special slot %d blob: %w", index, err)
	}
	return verifyPreviousSpecialSlot(config, index, data)
}

func maxBoundSpecialSlot(config *Config, limit uint32) uint32 {
	var maximum uint32
	for position, slot := range config.SpecialSlots {
		index := slot.Index
		if index == 0 {
			index = uint32(len(config.SpecialSlots) - position)
		}
		// Requirements are rebuilt on every signature. Entitlements are embedded
		// in the SuperBlob and must never retain a binding when their blob is absent.
		if index == 2 || index == 5 {
			continue
		}
		if index <= limit && index > maximum && isBoundSpecialSlotHash(slot.Hash) && previousSpecialSlotUsesSHA256(config, slot.Hash) {
			maximum = index
		}
	}
	return maximum
}

func ensureMinimumSpecialSlots(config *Config, minimum uint32) {
	if config.NSpecialSlots < minimum {
		config.NSpecialSlots = minimum
	}
}

func configuredSpecialSlotHash(config *Config, index uint32) []byte {
	var hash []byte
	switch index {
	case 1:
		hash = config.SlotHashes.InfoPlist
	case 2:
		hash = config.SlotHashes.Requirements
	case 3:
		hash = config.SlotHashes.ResourceDir
	case 4:
		hash = config.SlotHashes.AppSpecific
	case 5:
		hash = config.SlotHashes.Entitlements
	case 6:
		hash = config.SlotHashes.DmgSpecific
	case 7:
		hash = config.SlotHashes.EntitlementsDER
	case 8:
		hash = config.SlotHashes.LaunchConstraintsSelf
	case 9:
		hash = config.SlotHashes.LaunchConstraintsParent
	case 10:
		hash = config.SlotHashes.LaunchConstraintsResponsible
	case 11:
		hash = config.SlotHashes.LibraryConstraints
	}
	// Only external/raw slots may retain an existing SHA-256 binding without a
	// rebuilt native component. Slot 5 binds the embedded entitlements blob and
	// therefore must be zero whenever that blob is absent.
	if (index == 1 || index == 3 || index == 4 || index == 6) && !isBoundSpecialSlotHash(hash) {
		if previous, ok := specialSlotHash(config.SpecialSlots, index); ok && isBoundSpecialSlotHash(previous) {
			if previousSpecialSlotUsesSHA256(config, previous) {
				hash = previous
			}
		}
	}
	if len(hash) == 0 {
		return types.EmptySha256Slot
	}
	return hash
}

func Sign(r io.Reader, config *Config) ([]byte, error) {
	var err error
	var buf bytes.Buffer
	var reqBlob types.Blob
	var entBlob types.Blob
	var entDerBlob types.Blob
	type constraintBlob struct {
		slot types.SlotType
		blob types.Blob
	}
	var constraintBlobs []constraintBlob
	var rawBlobs []constraintBlob

	sb := types.NewSuperBlob(types.MAGIC_EMBEDDED_SIGNATURE)

	// Requirements /////////////////////////////////////////////
	adhoc := config.Flags&types.ADHOC != 0
	reqBlob, err = types.CreateRequirements(config.ID, config.CertChain, adhoc)
	if err != nil {
		return nil, fmt.Errorf("failed to create Requirements: %v", err)
	}
	if !adhoc {
		config.SlotHashes.Requirements, err = reqBlob.Sha256Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to hash Requirements: %v", err)
		}
	}
	// Native embedded components cannot remain bound when their payload is
	// absent. Clear stale hashes as well as historical SpecialSlots so a reused
	// Config cannot produce a CodeDirectory binding with no matching blob.
	if len(config.Entitlements) == 0 {
		config.SlotHashes.Entitlements = types.EmptySha256Slot
	}
	if len(config.EntitlementsDER) == 0 {
		config.SlotHashes.EntitlementsDER = types.EmptySha256Slot
	}

	config.NSpecialSlots = 2
	// Slots above 6 bind embedded components. They are retained only when the
	// corresponding payload is actually rebuilt below.
	ensureMinimumSpecialSlots(config, maxBoundSpecialSlot(config, 6))

	knownRawSlots := []types.SlotType{
		types.CSSLOT_INFOSLOT,
		types.CSSLOT_RESOURCEDIR,
		types.CSSLOT_APPLICATION,
		types.CSSLOT_REP_SPECIFIC,
		types.CSSLOT_IDENTIFICATIONSLOT,
		types.CSSLOT_TICKETSLOT,
	}
	seenRaw := 0
	for _, slot := range knownRawSlots {
		payload, ok := config.RawComponents[slot]
		if !ok {
			continue
		}
		seenRaw++
		if slot <= types.CSSLOT_REP_SPECIFIC {
			sum := sha256.Sum256(payload)
			var target *[]byte
			switch slot {
			case types.CSSLOT_INFOSLOT:
				target = &config.SlotHashes.InfoPlist
			case types.CSSLOT_RESOURCEDIR:
				target = &config.SlotHashes.ResourceDir
			case types.CSSLOT_APPLICATION:
				target = &config.SlotHashes.AppSpecific
			case types.CSSLOT_REP_SPECIFIC:
				target = &config.SlotHashes.DmgSpecific
			}
			if isBoundSpecialSlotHash(*target) && !bytes.Equal(*target, sum[:]) {
				return nil, fmt.Errorf("configured and embedded raw component slot %d hashes do not match", slot)
			}
			if err := verifyPreviousSpecialSlot(config, uint32(slot), payload); err != nil {
				return nil, fmt.Errorf("previous and embedded raw component slot %d hashes do not match: %w", slot, err)
			}
			*target = append([]byte(nil), sum[:]...)
			ensureMinimumSpecialSlots(config, uint32(slot))
		}
		rawBlobs = append(rawBlobs, constraintBlob{
			slot: slot,
			blob: types.NewBlob(types.MAGIC_BLOBWRAPPER, payload),
		})
	}
	if seenRaw != len(config.RawComponents) {
		return nil, fmt.Errorf("raw components contain an unsupported slot")
	}

	// Entitlements /////////////////////////////////////////////
	if len(config.Entitlements) > 0 {
		ensureMinimumSpecialSlots(config, 5)
		entBlob = types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS, config.Entitlements)
		config.SlotHashes.Entitlements, err = entBlob.Sha256Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to hash entitlements plist blob: %v", err)
		}
		if err := verifyPreviousBlobSpecialSlot(config, 5, entBlob); err != nil {
			return nil, fmt.Errorf("previous and calculated entitlements plist hashes do not match: %w", err)
		}
	}
	if len(config.EntitlementsDER) > 0 {
		ensureMinimumSpecialSlots(config, 7)
		entDerBlob = types.NewBlob(types.MAGIC_EMBEDDED_ENTITLEMENTS_DER, config.EntitlementsDER)
		config.SlotHashes.EntitlementsDER, err = entDerBlob.Sha256Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to hash entitlements asn1/der blob: %v", err)
		}
		if err := verifyPreviousBlobSpecialSlot(config, 7, entDerBlob); err != nil {
			return nil, fmt.Errorf("previous and calculated entitlements asn1/der hashes do not match: %w", err)
		}
	} else if len(config.Entitlements) > 0 {
		// A plist-only signature has no slot 7. Preserve a genuinely bound slot
		// 6 if present, but do not let a positional len or an empty slot 7 force
		// two hashes that have no corresponding data.
		config.NSpecialSlots = 5
		ensureMinimumSpecialSlots(config, maxBoundSpecialSlot(config, 6))
	}

	constraints := []struct {
		slot    types.SlotType
		payload []byte
		hash    *[]byte
	}{
		{types.CSSLOT_LAUNCH_CONSTRAINT_SELF, config.LaunchConstraintsSelf, &config.SlotHashes.LaunchConstraintsSelf},
		{types.CSSLOT_LAUNCH_CONSTRAINT_PARENT, config.LaunchConstraintsParent, &config.SlotHashes.LaunchConstraintsParent},
		{types.CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE, config.LaunchConstraintsResponsible, &config.SlotHashes.LaunchConstraintsResponsible},
		{types.CSSLOT_LIBRARY_CONSTRAINT, config.LibraryConstraints, &config.SlotHashes.LibraryConstraints},
	}
	for _, constraint := range constraints {
		if len(constraint.payload) == 0 {
			*constraint.hash = types.EmptySha256Slot
			continue
		}
		blob := types.NewBlob(types.MAGIC_EMBEDDED_LAUNCH_CONSTRAINT, constraint.payload)
		*constraint.hash, err = blob.Sha256Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to hash launch constraint slot %d: %v", constraint.slot, err)
		}
		if err := verifyPreviousBlobSpecialSlot(config, uint32(constraint.slot), blob); err != nil {
			return nil, fmt.Errorf("previous and calculated launch constraint slot %d hashes do not match: %w", constraint.slot, err)
		}
		ensureMinimumSpecialSlots(config, uint32(constraint.slot))
		constraintBlobs = append(constraintBlobs, constraintBlob{slot: constraint.slot, blob: blob})
	}

	// CodeDirectory ////////////////////////////////////////////
	cdbuf, err := createCodeDirectory(r, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create CodeDirectory: %v", err)
	}
	// Blobs ////////////////////////////////////////////////////
	sb.AddBlob(types.CSSLOT_CODEDIRECTORY, types.NewBlob(types.MAGIC_CODEDIRECTORY, cdbuf.Bytes()))
	sb.AddBlob(types.CSSLOT_REQUIREMENTS, reqBlob)
	if len(config.Entitlements) > 0 {
		sb.AddBlob(types.CSSLOT_ENTITLEMENTS, entBlob)
	}
	if len(config.EntitlementsDER) > 0 {
		sb.AddBlob(types.CSSLOT_ENTITLEMENTS_DER, entDerBlob)
	}
	for _, constraint := range constraintBlobs {
		sb.AddBlob(constraint.slot, constraint.blob)
	}
	for _, raw := range rawBlobs {
		sb.AddBlob(raw.slot, raw.blob)
	}
	if config.SignerFunction != nil {
		cdblob, err := sb.GetBlob(types.CSSLOT_CODEDIRECTORY)
		if err != nil {
			return nil, fmt.Errorf("failed to get CodeDirectory blob: %v", err)
		}
		cddata, err := cdblob.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get CodeDirectory blob data: %v", err)
		}
		cert, err := config.SignerFunction(cddata)
		if err != nil {
			return nil, fmt.Errorf("failed to sign CodeDirectory blob: %w", err)
		}
		sb.AddBlob(types.CSSLOT_CMS_SIGNATURE, types.NewBlob(types.MAGIC_BLOBWRAPPER, cert))
	} else {
		sb.AddBlob(types.CSSLOT_CMS_SIGNATURE, types.NewBlob(types.MAGIC_BLOBWRAPPER, []byte{}))
	}

	if size := sb.Size(); size < 0 || uint64(size) != uint64(sb.Length) {
		return nil, fmt.Errorf("SuperBlob size mismatch: calculated Size %d != Length %d", size, sb.Length)
	}

	// write SuperBlob
	if err := sb.Write(&buf, binary.BigEndian); err != nil {
		return nil, fmt.Errorf("failed to write SuperBlob: %v", err)
	}

	return buf.Bytes(), nil
}

func codeSlotCount(codeSize uint64) (uint32, error) {
	pageSize := uint64(types.PAGE_SIZE)
	count := codeSize / pageSize
	if codeSize%pageSize != 0 {
		count++
	}
	if count > math.MaxUint32 {
		return 0, fmt.Errorf("code size %#x requires %#x slots, exceeding uint32", codeSize, count)
	}
	return uint32(count), nil
}

func codeDirectoryLimits(codeSize uint64) (uint32, uint64) {
	if codeSize > math.MaxUint32 {
		return math.MaxUint32, codeSize
	}
	return uint32(codeSize), 0
}

func EstimateCodeSignatureSize(config *Config) uint64 {
	codeSlots, err := codeSlotCount(config.CodeSize)
	if err != nil {
		return math.MaxUint64
	}
	cdHeaderSize := uint64(binary.Size(types.BlobHeader{}) + binary.Size(types.CodeDirectoryType{}))
	cdVariableSize := uint64(len(config.ID)+1) + uint64(len(types.EmptySha256Slot))*(uint64(config.NSpecialSlots)+uint64(codeSlots))
	extraSlotsSize := uint64(0)
	if len(config.Entitlements) > 0 {
		extraSlotsSize += uint64(binary.Size(types.BlobHeader{}) + len(config.Entitlements))
	}
	if len(config.EntitlementsDER) > 0 {
		extraSlotsSize += uint64(binary.Size(types.BlobHeader{}) + len(config.EntitlementsDER))
	}
	for _, payload := range [][]byte{
		config.LaunchConstraintsSelf,
		config.LaunchConstraintsParent,
		config.LaunchConstraintsResponsible,
		config.LibraryConstraints,
	} {
		if len(payload) > 0 {
			extraSlotsSize += uint64(binary.Size(types.BlobHeader{}) + len(payload))
		}
	}
	for _, payload := range config.RawComponents {
		extraSlotsSize += uint64(binary.Size(types.BlobHeader{}) + len(payload))
	}
	extraSlotsSize += 1024     // guess at maximum size of requirements
	sigSize := uint64(1 << 14) // guess at size of CMS blob, including timestamp
	for _, cert := range config.CertChain {
		sigSize += uint64(len(cert.Raw))
	}
	return cdHeaderSize + cdVariableSize + extraSlotsSize + sigSize
}

func createCodeDirectory(r io.Reader, config *Config) (*bytes.Buffer, error) {
	var cddelta int
	var cdbuf bytes.Buffer
	codeSlots, err := codeSlotCount(config.CodeSize)
	if err != nil {
		return nil, err
	}
	codeLimit, codeLimit64 := codeDirectoryLimits(config.CodeSize)

	// Info.plist ///////////////////////////////////////////////
	if config.InfoPlist != nil {
		h := sha256.New()
		if _, err := h.Write(config.InfoPlist); err != nil {
			return nil, fmt.Errorf("failed to hash Info.plist: %v", err)
		}
		calculated := h.Sum(nil)
		if isBoundSpecialSlotHash(config.SlotHashes.InfoPlist) && !bytes.Equal(config.SlotHashes.InfoPlist, calculated) {
			return nil, fmt.Errorf("embedded and Mach-O Info.plist hashes do not match")
		}
		if err := verifyPreviousSpecialSlot(config, 1, config.InfoPlist); err != nil {
			return nil, fmt.Errorf("previous and calculated Info.plist hashes do not match: %w", err)
		}
		config.SlotHashes.InfoPlist = calculated
	}

	// Resource Directory ///////////////////////////////////////
	if previous, ok := specialSlotHash(config.SpecialSlots, 3); ok {
		// NOTE: this is sha256sum Some.app/Contents/_CodeSignature/CodeResources (which is a XML representation of the Resources directory)
		if bytes.Equal(config.SlotHashes.ResourceDir, types.EmptySha256Slot) && previousSpecialSlotUsesSHA256(config, previous) {
			// if the slot is empty it was NOT set by the caller (try and reuse previous value)
			config.SlotHashes.ResourceDir = previous
		}
		// if the slot is NOT empty it was set by the caller (and was calculated from the created CodeResources file)
	}

	// Application Specific /////////////////////////////////////
	if previous, ok := specialSlotHash(config.SpecialSlots, 4); ok {
		if bytes.Equal(config.SlotHashes.AppSpecific, types.EmptySha256Slot) && previousSpecialSlotUsesSHA256(config, previous) {
			// if the slot is empty it was NOT set by the caller (try and reuse previous value)
			config.SlotHashes.AppSpecific = previous
		}
	}

	// DMG Specific /////////////////////////////////////////////
	if previous, ok := specialSlotHash(config.SpecialSlots, 6); ok {
		if bytes.Equal(config.SlotHashes.DmgSpecific, types.EmptySha256Slot) && previousSpecialSlotUsesSHA256(config, previous) {
			// if the slot is empty it was NOT set by the caller (try and reuse previous value)
			config.SlotHashes.DmgSpecific = previous
		}
	}

	// calculate the CodeDirectory offsets
	identOffset := uint32(binary.Size(types.BlobHeader{}) + binary.Size(types.CodeDirectoryType{}))
	teamOffset := uint32(binary.Size(types.BlobHeader{}) + binary.Size(types.CodeDirectoryType{}) + len(config.ID) + 1)
	teamLen := len(config.TeamID)
	if teamLen > 0 {
		teamLen++
	} else {
		teamOffset = 0
	}
	hashOffset := identOffset + uint32(len(config.ID)+1+teamLen+len(types.EmptySha256Slot)*int(config.NSpecialSlots))

	cdHeader := types.CodeDirectoryType{
		CdEarliest: types.CdEarliest{
			Version:       types.SUPPORTS_RUNTIME, // TODO: support other versions (e.g.SUPPORTS_LINKAGE)
			Flags:         config.Flags,
			HashOffset:    hashOffset,
			IdentOffset:   identOffset,
			NSpecialSlots: config.NSpecialSlots,
			NCodeSlots:    codeSlots,
			CodeLimit:     codeLimit,
			HashSize:      sha256.Size,
			HashType:      types.HASHTYPE_SHA256,
			PageSize:      uint8(types.PAGE_SIZE_BITS),
		},
		CdTeamID: types.CdTeamID{
			TeamOffset: teamOffset,
		},
		CdCodeLimit64: types.CdCodeLimit64{
			CodeLimit64: codeLimit64,
		},
		CdExecSeg: types.CdExecSeg{
			ExecSegBase:  uint64(config.TextOffset),
			ExecSegLimit: uint64(config.TextSize),
		},
		CdRuntime: types.CdRuntime{
			Runtime: config.RuntimeVersion,
		},
	}

	// CodeDirectoryType is a variable length struct based on the Version field
	if cdHeader.Version >= types.EARLIEST_VERSION {
		cddelta = binary.Size(types.CodeDirectoryType{}) - binary.Size(types.CdEarliest{})
	}
	if cdHeader.Version >= types.SUPPORTS_SCATTER {
		cddelta -= binary.Size(types.CdScatter{})
	}
	if cdHeader.Version >= types.SUPPORTS_TEAMID {
		cddelta -= binary.Size(types.CdTeamID{})
	}
	if cdHeader.Version >= types.SUPPORTS_CODELIMIT64 {
		cddelta -= binary.Size(types.CdCodeLimit64{})
	}
	if cdHeader.Version >= types.SUPPORTS_EXECSEG {
		cddelta -= binary.Size(types.CdExecSeg{})
	}
	if cdHeader.Version >= types.SUPPORTS_RUNTIME {
		cddelta -= binary.Size(types.CdRuntime{})
	}
	if cdHeader.Version >= types.SUPPORTS_LINKAGE {
		cddelta -= binary.Size(types.CdLinkage{})
	}
	// adjust CodeDirectory header offsets
	cdHeader.IdentOffset -= uint32(cddelta)
	cdHeader.HashOffset -= uint32(cddelta)
	if cdHeader.TeamOffset != 0 {
		cdHeader.TeamOffset -= uint32(cddelta)
	}

	if config.IsMain {
		cdHeader.ExecSegFlags = types.EXECSEG_MAIN_BINARY
	}

	// write CodeDirectory header
	if err := binary.Write(&cdbuf, binary.BigEndian, &cdHeader); err != nil {
		return nil, fmt.Errorf("failed to write CodeDirectory: %v", err)
	}
	// truncate CodeDirectory header to match Version length
	cdbuf.Truncate(cdbuf.Len() - cddelta)
	// write CodeDirectory identifier
	if _, err := cdbuf.WriteString(config.ID + "\x00"); err != nil {
		return nil, fmt.Errorf("failed to write identifier %s: %v", config.ID, err)
	}
	// write team identifier
	if len(config.TeamID) > 0 {
		if _, err := cdbuf.WriteString(config.TeamID + "\x00"); err != nil {
			return nil, fmt.Errorf("failed to write team identifier %s: %v", config.TeamID, err)
		}
	}
	for slot := config.NSpecialSlots; slot > 0; slot-- {
		hash := configuredSpecialSlotHash(config, slot)
		if len(hash) != sha256.Size {
			return nil, fmt.Errorf("special slot %d hash has size %d, want %d", slot, len(hash), sha256.Size)
		}
		if _, err := cdbuf.Write(hash); err != nil {
			return nil, fmt.Errorf("failed to write special slot %d hash: %v", slot, err)
		}
	}
	// write page hashes
	var hashCount uint64
	var hashes [types.PAGE_SIZE]byte
	h := sha256.New()
	var consumed uint64
	for consumed < config.CodeSize {
		remaining := config.CodeSize - consumed
		chunk := uint64(len(hashes))
		if remaining < chunk {
			chunk = remaining
		}
		n, err := io.ReadFull(r, hashes[:int(chunk)])
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("failed to read file content without the signature: %v", err)
		}
		if n != int(chunk) {
			return nil, fmt.Errorf("file content ended at %#x, before declared code size %#x", consumed+uint64(n), config.CodeSize)
		}
		consumed += uint64(n)
		h.Reset()
		h.Write(hashes[:n])
		b := h.Sum(nil)
		if _, err := cdbuf.Write(b[:]); err != nil {
			return nil, fmt.Errorf("failed to write page %d hash: %v", hashCount, err)
		}
		hashCount++
	}

	return &cdbuf, nil
}
