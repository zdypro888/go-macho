package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/zdypro888/go-macho/internal/saferio"
	"github.com/zdypro888/go-macho/types"
	"github.com/zdypro888/go-macho/types/objc"
)

var ErrObjcSectionNotFound = errors.New("missing required ObjC section")
var ErrObjcSectionNEmpty = errors.New("required ObjC section is empty")
var ErrObjcFragileRuntimeUnsupported = errors.New("objective-c fragile runtime metadata is unsupported")

// ErrObjCSelectorBaseUnavailable indicates a relative ObjC method list whose
// selectors are offsets into the shared cache's global selector-string table,
// which is not present when parsing a dylib in isolation (e.g. one extracted
// from a dyld_shared_cache). Such method names can only be resolved against the
// full cache.
var ErrObjCSelectorBaseUnavailable = errors.New("ObjC relative method selectors require the shared cache's selector base, which is unavailable in a standalone dylib")

var legacyObjCSectionNames = map[string]struct{}{
	"__image_info":     {},
	"__module_info":    {},
	"__class":          {},
	"__meta_class":     {},
	"__protocol":       {},
	"__protocol_ext":   {},
	"__category":       {},
	"__class_vars":     {},
	"__instance_vars":  {},
	"__cls_refs":       {},
	"__message_refs":   {},
	"__symbols":        {},
	"__sel_refs":       {},
	"__string_object":  {},
	"__class_names":    {},
	"__meth_var_names": {},
	"__meth_var_types": {},
	"__selector_strs":  {},
}

func isLegacyObjCSectionName(name string) bool {
	_, ok := legacyObjCSectionNames[strings.ToLower(name)]
	return ok
}

// TODO refactor into a pkg

func (f *File) PutObjC(addr uint64, obj any) {
	f.mu.Lock()
	f.objc[addr] = obj
	f.mu.Unlock()
}

func (f *File) GetObjC(addr uint64) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	val, ok := f.objc[addr]
	return val, ok
}

func (f *File) cachedObjCClass(addr uint64) (*objc.Class, bool) {
	cached, ok := f.GetObjC(addr)
	if !ok {
		return nil, false
	}
	class, ok := cached.(*objc.Class)
	return class, ok
}

func (f *File) rebasePtr(ptr uint64) uint64 {
	if f.Flags.DylibInCache() {
		return ptr
	} else {
		return ptr + f.GetBaseAddress()
	}
}

func (f *File) getCStringWithFallback(addr uint64, label string, allowSwift bool) (string, error) {
	if !f.addrResolvable(addr) && f.objcMetadataIsCacheOptimized() {
		return fmt.Sprintf("/* unresolved shared-cache %s at %#x */", label, addr), nil
	}
	str, err := f.GetCString(addr)
	if err == nil {
		return str, nil
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, ErrCStringNoTerminator) ||
		errors.Is(err, ErrCStringNotFound) {
		if allowSwift {
			if swiftStr, swiftErr := f.swiftSymbolicName(addr); swiftErr == nil {
				return swiftStr, nil
			}
			return fmt.Sprintf("@\"SwiftUnresolved_0x%x\"", addr), nil
		}
		return fmt.Sprintf("/* unresolved %s at %#x */", label, addr), nil
	}
	return "", err
}

func (f *File) hasObjCNonFragileRuntime() bool {
	f.detectObjCRuntimeKinds()
	return f.objcHasNonFragileRuntime
}

func (f *File) hasObjCFragileRuntime() bool {
	f.detectObjCRuntimeKinds()
	return f.objcHasFragileRuntime
}

func (f *File) detectObjCRuntimeKinds() {
	f.objcRuntimeOnce.Do(func() {
		for _, sec := range f.Sections {
			if strings.HasPrefix(sec.Seg, "__DATA") && strings.HasPrefix(sec.Name, "__objc_") {
				f.objcHasNonFragileRuntime = true
			}
			if strings.EqualFold(sec.Seg, "__OBJC") && isLegacyObjCSectionName(sec.Name) {
				f.objcHasFragileRuntime = true
			}
			if f.objcHasNonFragileRuntime && f.objcHasFragileRuntime {
				return
			}
		}
	})
}

func (f *File) ensureObjCNonFragileRuntime(api string) error {
	f.detectObjCRuntimeKinds()
	if f.objcHasFragileRuntime && !f.objcHasNonFragileRuntime {
		return fmt.Errorf("%s requires the Objective-C non-fragile runtime: %w", api, ErrObjcFragileRuntimeUnsupported)
	}
	return nil
}

func decodeLegacyObjCCachePointer(pointer, valueAdd uint64) (uint64, bool) {
	const deltaMask = uint64(0xe0000000)
	value := pointer &^ deltaMask
	if value == 0 {
		return 0, true
	}
	if value > ^uint64(0)-valueAdd {
		return 0, false
	}
	return value + valueAdd, true
}

// inferLegacyObjCCacheValueAdd recognizes legacy 32-bit dyld-cache slide-info-v2
// pointers only when the complete local class-list address set has one unique
// value_add that maps it onto the image's defined ObjC class symbols. Apple
// reserves the three most-significant 32-bit pointer bits for the chain delta.
func (f *File) inferLegacyObjCCacheValueAdd() {
	if f.pointerSize() != 4 || f.Symtab == nil {
		return
	}

	var classList *types.Section
	for _, section := range f.Sections {
		if section.Name == "__objc_classlist" {
			classList = section
			break
		}
	}
	if classList == nil || classList.Size < 2*f.pointerSize() {
		return
	}
	pointers, err := f.readPointerArrayAtAddress(classList.Addr, classList.Size)
	if err != nil || len(pointers) < 2 {
		return
	}

	classSymbols := make(map[uint64]struct{})
	for _, symbol := range f.Symtab.Syms {
		if symbol.Sect == 0 || !strings.Contains(symbol.Name, "OBJC_CLASS_$_") {
			continue
		}
		if f.addrResolvable(symbol.Value) {
			classSymbols[symbol.Value] = struct{}{}
		}
	}
	if len(classSymbols) < len(pointers) {
		return
	}

	const valueMask = uint64(0x1fffffff)
	firstValue := pointers[0] & valueMask
	if firstValue == 0 {
		return
	}
	candidates := make(map[uint64]struct{})
	for symbolAddress := range classSymbols {
		if symbolAddress < firstValue {
			continue
		}
		valueAdd := symbolAddress - firstValue
		matches := true
		for _, pointer := range pointers {
			translated, ok := decodeLegacyObjCCachePointer(pointer, valueAdd)
			if !ok {
				matches = false
				break
			}
			if _, ok := classSymbols[translated]; !ok {
				matches = false
				break
			}
		}
		if matches {
			candidates[valueAdd] = struct{}{}
		}
	}
	if len(candidates) != 1 {
		return
	}
	for valueAdd := range candidates {
		f.objcCacheValueAdd = valueAdd
		f.objcCacheValueAddKnown = true
	}
}

func (f *File) resolveObjCPointerAtAddress(slotVMAddr, pointer uint64) (uint64, error) {
	if target, resolved, err := f.resolvePointerAtAddress(slotVMAddr, pointer); err != nil {
		return 0, err
	} else if resolved {
		return target, nil
	}
	return f.resolveObjCPointerValue(pointer), nil
}

func (f *File) resolveObjCPointerValue(pointer uint64) uint64 {
	if pointer == 0 || f.addrResolvable(pointer) {
		return pointer
	}
	converted := f.vma.Convert(pointer)
	if converted == 0 || f.addrResolvable(converted) {
		return converted
	}

	f.objcCacheValueAddOnce.Do(f.inferLegacyObjCCacheValueAdd)
	if !f.objcCacheValueAddKnown {
		return converted
	}
	translated, ok := decodeLegacyObjCCachePointer(pointer, f.objcCacheValueAdd)
	if ok && f.addrResolvable(translated) {
		return translated
	}
	return converted
}

func (f *File) readResolvedObjCPointerArrayAtAddress(address, size uint64) ([]uint64, error) {
	pointers, err := f.readPointerArrayAtAddress(address, size)
	if err != nil {
		return nil, err
	}
	if err := f.resolveObjCPointerArrayAtAddress(address, pointers); err != nil {
		return nil, err
	}
	return pointers, nil
}

func (f *File) resolveObjCPointerArrayAtAddress(address uint64, pointers []uint64) error {
	var err error
	for index, pointer := range pointers {
		slotVMAddr := address + uint64(index)*f.pointerSize()
		pointers[index], err = f.resolveObjCPointerAtAddress(slotVMAddr, pointer)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *File) objcCachePointerUnavailable(pointer uint64) bool {
	return pointer != 0 && !f.addrResolvable(pointer) && f.objcMetadataIsCacheOptimized()
}

func (f *File) objcMetadataIsCacheOptimized() bool {
	f.objcCacheValueAddOnce.Do(f.inferLegacyObjCCacheValueAdd)
	if f.Flags.DylibInCache() || f.objcCacheValueAddKnown {
		return true
	}
	imageInfo, err := f.GetObjCImageInfo()
	return err == nil && imageInfo.Flags.OptimizedByDyld()
}

// HasObjC returns true if MachO contains Objective-C metadata.
func (f *File) HasObjC() bool {
	return f.hasObjCNonFragileRuntime() || f.hasObjCFragileRuntime()
}

// HasPlusLoadMethod returns true if MachO contains a __objc_nlclslist or __objc_nlcatlist section
func (f *File) HasPlusLoadMethod() bool {
	// TODO add the old way of detecting from dyld3/MachOAnalyzer.cpp
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_nlclslist"); sec != nil {
				return true
			}
			if sec := f.Section(s.Name, "__objc_nlcatlist"); sec != nil {
				return true
			}
		}
	}
	if sec := f.Section("__OBJC", "__message_refs"); sec != nil {
		return true
	}
	return false
}

// HasObjCMessageReferences returns true if MachO contains a __objc_msgrefs section
func (f *File) HasObjCMessageReferences() bool {
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_msgrefs"); sec != nil {
				return true
			}
		}
	}
	return false
}

// GetObjCToc returns a table of contents of the ObjC objects in the MachO
func (f *File) GetObjCToc() objc.Toc {
	var oInfo objc.Toc
	for _, sec := range f.Sections {
		if strings.HasPrefix(sec.SectionHeader.Seg, "__DATA") {
			switch sec.Name {
			case "__objc_classlist":
				oInfo.ClassList = sec.Size / f.pointerSize()
			case "__objc_nlclslist":
				oInfo.NonLazyClassList = sec.Size / f.pointerSize()
			case "__objc_catlist":
				oInfo.CatList = sec.Size / f.pointerSize()
			case "__objc_nlcatlist":
				oInfo.NonLazyCatList = sec.Size / f.pointerSize()
			case "__objc_protolist":
				oInfo.ProtoList = sec.Size / f.pointerSize()
			case "__objc_classrefs":
				oInfo.ClassRefs = sec.Size / f.pointerSize()
			case "__objc_superrefs":
				oInfo.SuperRefs = sec.Size / f.pointerSize()
			case "__objc_selrefs":
				oInfo.SelRefs = sec.Size / f.pointerSize()
			}
		} else if strings.EqualFold(sec.Seg, "__OBJC") {
			if strings.EqualFold(sec.Name, "__message_refs") {
				oInfo.SelRefs += sec.SectionHeader.Size / 4
			} else if strings.EqualFold(sec.Name, "__class") {
				oInfo.ClassList += sec.SectionHeader.Size / 48
			} else if strings.EqualFold(sec.Name, "__protocol") {
				oInfo.ProtoList += sec.SectionHeader.Size / 20
			}
		}
		// if sec := f.Section("__TEXT", "__objc_stubs"); sec != nil {
		// 	oInfo.Stubs = sec.Size / f.pointerSize()
		// }
	}
	return oInfo
}

// GetObjCImageInfo returns the parsed __objc_imageinfo data
func (f *File) GetObjCImageInfo() (*objc.ImageInfo, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCImageInfo"); err != nil {
		return nil, err
	}

	var imgInfo objc.ImageInfo
	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_imageinfo"); sec != nil {
				off, err := f.vma.GetOffset(sec.Addr)
				if err != nil {
					return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
				}
				f.cr.Seek(int64(off), io.SeekStart)

				var dat []byte
				if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
					return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
				}

				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &imgInfo); err != nil {
					return nil, fmt.Errorf("failed to read %T: %v", imgInfo, err)
				}

				return &imgInfo, nil
			}
		}
	}
	return nil, fmt.Errorf("macho does not contain __objc_imageinfo section: %w", ErrObjcSectionNotFound)
}

func (f *File) objcClassDataMask() uint64 {
	if f.is64bit() {
		return objc.FAST_DATA_MASK64
	}
	return objc.FAST_DATA_MASK
}

func (f *File) readObjCClassRecord(vmaddr uint64) (objc.ObjcClass64, error) {
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr, 5*f.pointerSize())
	if err != nil {
		return objc.ObjcClass64{}, fmt.Errorf("failed to read objc_class at %#x: %w", vmaddr, err)
	}
	return objc.ObjcClass64{
		IsaVMAddr:              pointers[0],
		SuperclassVMAddr:       pointers[1],
		MethodCacheBuckets:     pointers[2],
		MethodCacheProperties:  pointers[3],
		DataVMAddrAndFastFlags: pointers[4],
	}, nil
}

func (f *File) readObjCCategoryRecord(vmaddr uint64) (objc.CategoryT, error) {
	pointerCount := uint64(6)
	imageInfo, imageInfoErr := f.GetObjCImageInfo()
	if imageInfoErr == nil && imageInfo.Flags.HasCategoryClassProperties() {
		pointerCount = 7
	} else if imageInfoErr != nil && !errors.Is(imageInfoErr, ErrObjcSectionNotFound) {
		return objc.CategoryT{}, fmt.Errorf("failed to determine category_t layout: %w", imageInfoErr)
	}
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr, pointerCount*f.pointerSize())
	if err != nil {
		return objc.CategoryT{}, fmt.Errorf("failed to read category_t at %#x: %w", vmaddr, err)
	}
	category := objc.CategoryT{
		NameVMAddr:               pointers[0],
		ClsVMAddr:                pointers[1],
		InstanceMethodsVMAddr:    pointers[2],
		ClassMethodsVMAddr:       pointers[3],
		ProtocolsVMAddr:          pointers[4],
		InstancePropertiesVMAddr: pointers[5],
	}
	if pointerCount == 7 {
		category.ClassPropertiesVMAddr = pointers[6]
	}
	return category, nil
}

func (f *File) readObjCMethodRecord(vmaddr uint64) (objc.MethodT, error) {
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr, 3*f.pointerSize())
	if err != nil {
		return objc.MethodT{}, fmt.Errorf("failed to read method_t at %#x: %w", vmaddr, err)
	}
	return objc.MethodT{
		NameVMAddr:  pointers[0],
		TypesVMAddr: pointers[1],
		ImpVMAddr:   pointers[2],
	}, nil
}

func (f *File) readObjCIvarRecord(vmaddr uint64) (objc.IvarT, error) {
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr, 3*f.pointerSize())
	if err != nil {
		return objc.IvarT{}, fmt.Errorf("failed to read ivar_t pointers at %#x: %w", vmaddr, err)
	}
	tailAddr := vmaddr + 3*f.pointerSize()
	tail, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: tailAddr}, 8, 0)
	if err != nil {
		return objc.IvarT{}, fmt.Errorf("failed to read ivar_t scalar fields at %#x: %w", tailAddr, err)
	}
	return objc.IvarT{
		Offset:       pointers[0],
		NameVMAddr:   pointers[1],
		TypesVMAddr:  pointers[2],
		AlignmentRaw: f.ByteOrder.Uint32(tail[0:4]),
		Size:         f.ByteOrder.Uint32(tail[4:8]),
	}, nil
}

func (f *File) readObjCPropertyRecord(vmaddr uint64) (objc.PropertyT, error) {
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr, 2*f.pointerSize())
	if err != nil {
		return objc.PropertyT{}, fmt.Errorf("failed to read property_t at %#x: %w", vmaddr, err)
	}
	return objc.PropertyT{NameVMAddr: pointers[0], AttributesVMAddr: pointers[1]}, nil
}

func (f *File) readCFStringRecord(vmaddr uint64) (objc.CFString64Type, error) {
	pointerSize := f.pointerSize()
	recordSize := 4 * pointerSize
	data, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: vmaddr}, recordSize, 0)
	if err != nil {
		return objc.CFString64Type{}, fmt.Errorf("failed to read constant CFString at %#x: %w", vmaddr, err)
	}
	isa, err := decodePointerValue(data[0:pointerSize], pointerSize, f.ByteOrder)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	isa, err = f.resolveObjCPointerAtAddress(vmaddr, isa)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	characters, err := decodePointerValue(data[2*pointerSize:3*pointerSize], pointerSize, f.ByteOrder)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	characters, err = f.resolveObjCPointerAtAddress(vmaddr+2*pointerSize, characters)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	info, err := decodePointerValue(data[pointerSize:2*pointerSize], pointerSize, f.ByteOrder)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	length, err := decodePointerValue(data[3*pointerSize:4*pointerSize], pointerSize, f.ByteOrder)
	if err != nil {
		return objc.CFString64Type{}, err
	}
	return objc.CFString64Type{
		IsaVMAddr: isa,
		Info:      info,
		Data:      characters,
		Length:    length,
	}, nil
}

func (f *File) readObjCProtocolRecord(vmaddr uint64) (objc.ProtocolT, bool, bool, bool, error) {
	pointerSize := f.pointerSize()
	baseSize := 8*pointerSize + 8 // eight pointers followed by uint32 size and flags
	data, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: vmaddr}, baseSize, 0)
	if err != nil {
		return objc.ProtocolT{}, false, false, false, fmt.Errorf("failed to read protocol_t at %#x: %w", vmaddr, err)
	}
	pointers, err := decodePointerArray(data[:8*pointerSize], pointerSize, f.ByteOrder)
	if err != nil {
		return objc.ProtocolT{}, false, false, false, err
	}
	if err := f.resolveObjCPointerArrayAtAddress(vmaddr, pointers); err != nil {
		return objc.ProtocolT{}, false, false, false, err
	}
	sizeOffset := 8 * pointerSize
	protocol := objc.ProtocolT{
		IsaVMAddr:                     pointers[0],
		NameVMAddr:                    pointers[1],
		ProtocolsVMAddr:               pointers[2],
		InstanceMethodsVMAddr:         pointers[3],
		ClassMethodsVMAddr:            pointers[4],
		OptionalInstanceMethodsVMAddr: pointers[5],
		OptionalClassMethodsVMAddr:    pointers[6],
		InstancePropertiesVMAddr:      pointers[7],
		Size:                          f.ByteOrder.Uint32(data[sizeOffset : sizeOffset+4]),
		Flags:                         f.ByteOrder.Uint32(data[sizeOffset+4 : sizeOffset+8]),
	}

	hasExtended := uint64(protocol.Size) >= baseSize+pointerSize
	hasDemangled := uint64(protocol.Size) >= baseSize+2*pointerSize
	hasClassProperties := uint64(protocol.Size) >= baseSize+3*pointerSize
	optionalCount := uint64(0)
	if hasClassProperties {
		optionalCount = 3
	} else if hasDemangled {
		optionalCount = 2
	} else if hasExtended {
		optionalCount = 1
	}
	if optionalCount > 0 {
		optional, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr+baseSize, optionalCount*pointerSize)
		if err != nil {
			return objc.ProtocolT{}, false, false, false, fmt.Errorf("failed to read protocol_t optional fields: %w", err)
		}
		protocol.ExtendedMethodTypesVMAddr = optional[0]
		if optionalCount > 1 {
			protocol.DemangledNameVMAddr = optional[1]
		}
		if optionalCount > 2 {
			protocol.ClassPropertiesVMAddr = optional[2]
		}
	}
	return protocol, hasExtended, hasDemangled, hasClassProperties, nil
}

// GetObjCClassInfo returns class_ro_t normalized into the 64-bit public model.
func (f *File) GetObjCClassInfo(vmaddr uint64) (*objc.ClassRO64, error) {
	pointerStart := uint64(12)
	if f.is64bit() {
		pointerStart = 16 // LP64 has a reserved uint32 after instanceSize
	}
	header, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: vmaddr}, pointerStart, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t header at %#x: %w", vmaddr, err)
	}
	pointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr+pointerStart, 7*f.pointerSize())
	if err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t pointers at %#x: %w", vmaddr, err)
	}
	classData := objc.ClassRO64{
		Flags:                objc.ClassRoFlags(f.ByteOrder.Uint32(header[0:4])),
		InstanceStart:        f.ByteOrder.Uint32(header[4:8]),
		InstanceSize:         uint64(f.ByteOrder.Uint32(header[8:12])),
		IvarLayoutVMAddr:     pointers[0],
		NameVMAddr:           pointers[1],
		BaseMethodsVMAddr:    pointers[2],
		BaseProtocolsVMAddr:  pointers[3],
		IvarsVMAddr:          pointers[4],
		WeakIvarLayoutVMAddr: pointers[5],
		BasePropertiesVMAddr: pointers[6],
	}

	return &classData, nil
}

// GetObjCClassNames returns a map of section data virtual memory address to their class names
func (f *File) GetObjCClassNames() (map[uint64]string, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClassNames"); err != nil {
		return nil, err
	}

	class2vmaddr := make(map[uint64]string)

	if sec := f.Section("__TEXT", "__objc_classname"); sec != nil { // Names for locally implemented classes
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		var dat []byte
		if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from class name string pool: %v", err)
			}

			if len(strings.Trim(s, "\x00")) > 0 && types.IsASCII(strings.Trim(s, "\x00")) {
				class2vmaddr[sec.Addr+(sec.Size-uint64(r.Len()+len(s)))] = strings.Trim(s, "\x00")
			}
		}
	}

	return class2vmaddr, nil
}

// GetObjCMethodNames returns a map of section data virtual memory addresses to their method names
func (f *File) GetObjCMethodNames() (map[uint64]string, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethodNames"); err != nil {
		return nil, err
	}

	meth2vmaddr := make(map[uint64]string)

	if sec := f.Section("__TEXT", "__objc_methname"); sec != nil { // Method names for locally implemented methods
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		var dat []byte
		if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewBuffer(dat)

		for {
			s, err := r.ReadString('\x00')
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read from method name string pool: %v", err)
			}

			if len(strings.Trim(s, "\x00")) > 0 && types.IsASCII(strings.Trim(s, "\x00")) {
				meth2vmaddr[sec.Addr+(sec.Size-uint64(r.Len()+len(s)))] = strings.Trim(s, "\x00")
			}
		}
	}

	return meth2vmaddr, nil
}

// GetObjCClasses returns an array of Objective-C classes
func (f *File) GetObjCClasses() ([]objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClasses"); err != nil {
		return nil, err
	}

	var classes []objc.Class

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_classlist"); sec != nil { // An array of pointers to ObjC classes
				ptrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for idx, ptr := range ptrs {
					slotAddr := sec.Addr + uint64(idx)*f.pointerSize()
					if c, ok := f.cachedObjCClass(ptr); ok {
						classes = append(classes, *c)
					} else {
						class, err := f.GetObjCClass(ptr)
						if err != nil {
							if f.HasFixups() {
								bindName, bindErr := f.getBindNameAtAddress(slotAddr)
								if bindErr == nil {
									class = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
								} else {
									return nil, fmt.Errorf("failed to read objc_class_t at vmaddr %#x: %w", ptr, errors.Join(err, bindErr))
								}
							} else {
								return nil, fmt.Errorf("failed to read objc_class_t at vmaddr %#x: %v", ptr, err)
							}
						}
						classes = append(classes, *class)
						f.PutObjC(ptr, class)
					}
				}
			}
		}
	}

	return classes, nil
}

// GetObjCNonLazyClasses returns an array of Objective-C classes that implement +load
func (f *File) GetObjCNonLazyClasses() ([]objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCNonLazyClasses"); err != nil {
		return nil, err
	}

	var classes []objc.Class

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_nlclslist"); sec != nil { // An array of pointers to classes who implement +load
				ptrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for idx, ptr := range ptrs {
					slotAddr := sec.Addr + uint64(idx)*f.pointerSize()
					if c, ok := f.cachedObjCClass(ptr); ok {
						classes = append(classes, *c)
					} else {
						class, err := f.GetObjCClass(ptr)
						if err != nil {
							bindName, bindErr := f.getBindNameAtAddress(slotAddr)
							if bindErr != nil {
								return nil, fmt.Errorf("failed to read non-lazy objc_class_t at vmaddr %#x: %w", ptr, errors.Join(err, bindErr))
							}
							class = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
						}
						classes = append(classes, *class)
						f.PutObjC(ptr, class)
					}
				}
			}
		}
	}

	return classes, nil
}

func checkedAddSignedOffset(base uint64, offset int64) (uint64, error) {
	if offset >= 0 {
		amount := uint64(offset)
		if amount > ^uint64(0)-base {
			return 0, errors.New("relative list-of-lists offset overflows")
		}
		return base + amount, nil
	}
	amount := uint64(-(offset + 1)) + 1 // safe for math.MinInt64
	if amount > base {
		return 0, errors.New("relative list-of-lists offset underflows")
	}
	return base - amount, nil
}

func (f *File) disablePreattachedCategories(vmaddr uint64) (uint64, error) {
	if (vmaddr & 1) == 0 {
		return vmaddr, nil
	}

	// Apple's relative_list_list_t is a contiguous array of 8-byte
	// ListOfListsEntry values. Entry zero is also the {entsize,count} header;
	// the final entry points at the original class list.
	listVMAddr := vmaddr &^ uint64(1)
	if err := f.cr.SeekToAddr(listVMAddr); err != nil {
		return 0, fmt.Errorf("failed to seek to entry_list_t at %#x: %v", listVMAddr, err)
	}

	var entryList objc.EntryList
	if err := binary.Read(f.cr, f.ByteOrder, &entryList); err != nil {
		return 0, fmt.Errorf("failed to read entry_list_t at %#x: %v", listVMAddr, err)
	}
	if entryList.Count == 0 {
		return listVMAddr, nil
	}

	headerSize := uint64(binary.Size(entryList))
	entrySize := uint64(binary.Size(objc.Entry(0)))
	lastIndex := uint64(entryList.Count - 1)
	if listVMAddr > ^uint64(0)-headerSize || lastIndex > (^uint64(0)-listVMAddr-headerSize)/entrySize {
		return 0, fmt.Errorf("entry_list_t at %#x entry array address overflows", listVMAddr)
	}
	lastEntryVMAddr := listVMAddr + headerSize + lastIndex*entrySize
	if err := f.cr.SeekToAddr(lastEntryVMAddr); err != nil {
		return 0, fmt.Errorf("failed to seek to final entry_list_t entry at %#x: %v", lastEntryVMAddr, err)
	}
	var entry objc.Entry
	if err := binary.Read(f.cr, f.ByteOrder, &entry); err != nil {
		return 0, fmt.Errorf("failed to read final entry_list_t entry at %#x: %v", lastEntryVMAddr, err)
	}
	target, err := checkedAddSignedOffset(lastEntryVMAddr, entry.MethodListOffset())
	if err != nil {
		return 0, fmt.Errorf("resolve final entry_list_t entry at %#x: %w", lastEntryVMAddr, err)
	}
	return target, nil
}

// GetObjCClass parses an Objective-C class at a given virtual memory address
func (f *File) GetObjCClass(vmaddr uint64) (*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClass"); err != nil {
		return nil, err
	}

	if c, ok := f.cachedObjCClass(vmaddr); ok {
		return c, nil
	}

	classPtr, err := f.readObjCClassRecord(vmaddr)
	if err != nil {
		return nil, err
	}

	dataMask := f.objcClassDataMask()
	info, err := f.GetObjCClassInfo(classPtr.DataVMAddrAndFastFlags & dataMask)
	if err != nil {
		return nil, fmt.Errorf("failed to get class info at vmaddr: %#x; %v", classPtr.DataVMAddrAndFastFlags&dataMask, err)
	}

	name, err := f.GetCString(info.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	var methods []objc.Method
	if info.BaseMethodsVMAddr > 0 && !f.objcCachePointerUnavailable(info.BaseMethodsVMAddr) {
		info.BaseMethodsVMAddr, err = f.disablePreattachedCategories(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		methods, err = f.GetObjCMethods(info.BaseMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get methods at vmaddr: %#x; %v", info.BaseMethodsVMAddr, err)
		}
	}

	var prots []objc.Protocol
	if info.BaseProtocolsVMAddr > 0 && !f.objcCachePointerUnavailable(info.BaseProtocolsVMAddr) {
		info.BaseProtocolsVMAddr, err = f.disablePreattachedCategories(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		prots, err = f.parseObjcProtocolList(info.BaseProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
		}
	}

	isSwiftClass := (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY != 0) || (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE != 0)

	var ivars []objc.Ivar
	if info.IvarsVMAddr > 0 && !f.objcCachePointerUnavailable(info.IvarsVMAddr) {
		ivars, err = f.getObjCIvarsWithSwift(info.IvarsVMAddr, isSwiftClass)
		if err != nil {
			return nil, fmt.Errorf("failed to get ivars at vmaddr: %#x; %v", info.IvarsVMAddr, err)
		}
		if isSwiftClass {
			if fieldMap, ferr := f.swiftFieldTypesForClass(name); ferr == nil && len(fieldMap) > 0 {
				for idx := range ivars {
					if typ, ok := matchSwiftFieldType(ivars[idx].Name, fieldMap); ok {
						ivars[idx].Type = typ
					}
				}
			}
		}
	}

	var props []objc.Property
	if info.BasePropertiesVMAddr > 0 && !f.objcCachePointerUnavailable(info.BasePropertiesVMAddr) {
		info.BasePropertiesVMAddr, err = f.disablePreattachedCategories(info.BasePropertiesVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to disable preattached categories: %v", err)
		}
		props, err = f.getObjCPropertiesWithSwift(info.BasePropertiesVMAddr, isSwiftClass)
		if err != nil {
			return nil, fmt.Errorf("failed to get props at vmaddr: %#x; %v", info.BasePropertiesVMAddr, err)
		}
	}

	superClass := &objc.Class{}
	if classPtr.SuperclassVMAddr > 0 {
		if info.Flags.IsRoot() {
			superClass = &objc.Class{Name: "<ROOT>"}
		} else if info.Flags.IsMeta() {
			superClass = &objc.Class{Name: "<META>"}
			// } else if info.Flags > 0 {
		} else {
			if c, ok := f.cachedObjCClass(classPtr.SuperclassVMAddr); ok {
				superClass = c
			} else {
				superClass, err = f.GetObjCClass(classPtr.SuperclassVMAddr)
				if err != nil {
					if f.objcCachePointerUnavailable(classPtr.SuperclassVMAddr) {
						superClass = &objc.Class{Name: fmt.Sprintf("<unresolved shared-cache class %#x>", classPtr.SuperclassVMAddr)}
					} else if f.HasFixups() {
						bindName, bindErr := f.getBindNameAtAddress(vmaddr + f.pointerSize())
						if bindErr == nil {
							superClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
						} else {
							return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %w", vmaddr, errors.Join(err, bindErr))
						}
					} else {
						superClass = &objc.Class{}
					}
				}
				f.PutObjC(classPtr.SuperclassVMAddr, superClass)
			}
		}
	} else {
		bind, err := f.getBindNameAtAddress(vmaddr + f.pointerSize())
		if err == nil {
			if info.Flags.IsRoot() {
				superClass = &objc.Class{Name: bind}
			} else if info.Flags.IsMeta() {
				superClass = &objc.Class{Name: strings.TrimPrefix(bind, "_OBJC_METACLASS_$_")}
			} else {
				superClass = &objc.Class{Name: strings.TrimPrefix(bind, "_OBJC_CLASS_$_")}
			}
		}
	}

	isaClass := &objc.Class{}
	var cMethods []objc.Method
	if classPtr.IsaVMAddr > 0 {
		if !info.Flags.IsMeta() {
			if c, ok := f.cachedObjCClass(classPtr.IsaVMAddr); ok {
				isaClass = c
				cMethods = isaClass.InstanceMethods
			} else {
				isaClass, err = f.GetObjCClass(classPtr.IsaVMAddr)
				if err != nil {
					if f.objcCachePointerUnavailable(classPtr.IsaVMAddr) {
						isaClass = &objc.Class{Name: fmt.Sprintf("<unresolved shared-cache class %#x>", classPtr.IsaVMAddr)}
					} else if f.HasFixups() {
						bindName, bindErr := f.getBindNameAtAddress(vmaddr)
						if bindErr == nil {
							isaClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
						} else {
							return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: %#x; %w", vmaddr, errors.Join(err, bindErr))
						}
					} else {
						isaClass = &objc.Class{}
					}
				} else {
					if isaClass.ReadOnlyData.Flags.IsMeta() {
						cMethods = isaClass.InstanceMethods
					}
				}
				f.PutObjC(classPtr.IsaVMAddr, isaClass)
			}
		}
	} else {
		bind, err := f.getBindNameAtAddress(vmaddr)
		if err == nil {
			if info.Flags.IsRoot() {
				isaClass = &objc.Class{Name: bind}
			} else if info.Flags.IsMeta() {
				isaClass = &objc.Class{Name: strings.TrimPrefix(bind, "_OBJC_METACLASS_$_")}
			} else {
				isaClass = &objc.Class{Name: strings.TrimPrefix(bind, "_OBJC_CLASS_$_")}
			}
		}
	}

	return &objc.Class{
		Name:                  name,
		SuperClass:            superClass.Name,
		Isa:                   isaClass.Name,
		InstanceMethods:       methods,
		ClassMethods:          cMethods,
		Ivars:                 ivars,
		Props:                 props,
		Protocols:             prots,
		ClassPtr:              f.rebasePtr(vmaddr),
		IsaVMAddr:             classPtr.IsaVMAddr,
		SuperclassVMAddr:      classPtr.SuperclassVMAddr,
		MethodCacheBuckets:    classPtr.MethodCacheBuckets,
		MethodCacheProperties: classPtr.MethodCacheProperties,
		DataVMAddr:            classPtr.DataVMAddrAndFastFlags & dataMask,
		IsSwiftLegacy:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY != 0),
		IsSwiftStable:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE != 0),
		ReadOnlyData:          *info,
	}, nil
}

// GetObjCClass2 is retained as a compatibility alias for GetObjCClass.
func (f *File) GetObjCClass2(vmaddr uint64) (*objc.Class, error) {
	return f.GetObjCClass(vmaddr)
}

// GetObjCCategories returns an array of Objective-C categories by parsing the __objc_catlist data
func (f *File) GetObjCCategories() ([]objc.Category, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCCategories"); err != nil {
		return nil, err
	}

	var categories []objc.Category
	for _, segment := range f.Segments() {
		if !strings.HasPrefix(segment.Name, "__DATA") {
			continue
		}
		section := f.Section(segment.Name, "__objc_catlist")
		if section == nil {
			continue
		}
		pointers, err := f.readResolvedObjCPointerArrayAtAddress(section.Addr, section.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s.%s pointers: %w", section.Seg, section.Name, err)
		}
		for _, pointer := range pointers {
			if cached, ok := f.GetObjC(pointer); ok {
				category, ok := cached.(*objc.Category)
				if !ok {
					return nil, fmt.Errorf("ObjC cache entry at %#x has type %T, want *objc.Category", pointer, cached)
				}
				categories = append(categories, *category)
				continue
			}
			category, err := f.parseCategory(pointer)
			if err != nil {
				return nil, fmt.Errorf("failed to read category_t at vmaddr %#x: %w", pointer, err)
			}
			categories = append(categories, *category)
			f.PutObjC(pointer, category)
		}
	}
	return categories, nil
}

// GetObjCNonLazyCategories returns an array of Objective-C classes that implement +load
func (f *File) GetObjCNonLazyCategories() ([]objc.Category, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCNonLazyCategories"); err != nil {
		return nil, err
	}

	var cats []objc.Category

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_nlcatlist"); sec != nil { // An array of pointers to classes who implement +load
				ptrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for _, ptr := range ptrs {
					if c, ok := f.GetObjC(ptr); ok {
						category, ok := c.(*objc.Category)
						if !ok {
							return nil, fmt.Errorf("ObjC cache entry at %#x has type %T, want *objc.Category", ptr, c)
						}
						cats = append(cats, *category)
					} else {
						cat, err := f.parseCategory(ptr)
						if err != nil {
							return nil, fmt.Errorf("failed to read non-lazy category_t at vmaddr %#x: %v", ptr, err)
						}
						cats = append(cats, *cat)
						f.PutObjC(ptr, cat)
					}
				}
			}
		}
	}

	return cats, nil
}

func (f *File) parseCategory(vmaddr uint64) (*objc.Category, error) {
	categoryPtr, err := f.readObjCCategoryRecord(vmaddr)
	if err != nil {
		return nil, err
	}

	name, err := f.GetCString(categoryPtr.NameVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	category := &objc.Category{
		Name:      name,
		VMAddr:    f.rebasePtr(vmaddr),
		Class:     &objc.Class{},
		CategoryT: categoryPtr,
	}
	classSlot := vmaddr + f.pointerSize()
	if categoryPtr.ClsVMAddr > 0 {
		if cached, ok := f.cachedObjCClass(categoryPtr.ClsVMAddr); ok {
			category.Class = cached
		} else if class, classErr := f.GetObjCClass(categoryPtr.ClsVMAddr); classErr == nil {
			category.Class = class
			f.PutObjC(categoryPtr.ClsVMAddr, class)
		} else if f.objcCachePointerUnavailable(categoryPtr.ClsVMAddr) {
			category.Class = &objc.Class{Name: fmt.Sprintf("<unresolved shared-cache class %#x>", categoryPtr.ClsVMAddr)}
		} else if bindName, bindErr := f.getBindNameAtAddress(classSlot); bindErr == nil {
			category.Class = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
		} else {
			return nil, fmt.Errorf("failed to read category class at %#x: %w", categoryPtr.ClsVMAddr, errors.Join(classErr, bindErr))
		}
	} else if bindName, bindErr := f.getBindNameAtAddress(classSlot); bindErr == nil {
		category.Class = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
	} else if !errors.Is(bindErr, ErrMachONoBindInfo) {
		return nil, fmt.Errorf("failed to read category class bind at %#x: %w", classSlot, bindErr)
	}

	if categoryPtr.InstanceMethodsVMAddr > 0 && !f.objcCachePointerUnavailable(categoryPtr.InstanceMethodsVMAddr) {
		category.InstanceMethods, err = f.GetObjCMethods(categoryPtr.InstanceMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read category instance methods at %#x: %w", categoryPtr.InstanceMethodsVMAddr, err)
		}
	}
	if categoryPtr.ClassMethodsVMAddr > 0 && !f.objcCachePointerUnavailable(categoryPtr.ClassMethodsVMAddr) {
		category.ClassMethods, err = f.GetObjCMethods(categoryPtr.ClassMethodsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read category class methods at %#x: %w", categoryPtr.ClassMethodsVMAddr, err)
		}
	}
	if categoryPtr.ProtocolsVMAddr > 0 && !f.objcCachePointerUnavailable(categoryPtr.ProtocolsVMAddr) {
		category.Protocols, err = f.parseObjcProtocolList(categoryPtr.ProtocolsVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read category protocols at %#x: %w", categoryPtr.ProtocolsVMAddr, err)
		}
	}
	allowSwift := category.Class != nil && category.Class.IsSwift()
	if categoryPtr.InstancePropertiesVMAddr > 0 && !f.objcCachePointerUnavailable(categoryPtr.InstancePropertiesVMAddr) {
		category.Properties, err = f.getObjCPropertiesWithSwift(categoryPtr.InstancePropertiesVMAddr, allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read category instance properties at %#x: %w", categoryPtr.InstancePropertiesVMAddr, err)
		}
	}
	if categoryPtr.ClassPropertiesVMAddr > 0 && !f.objcCachePointerUnavailable(categoryPtr.ClassPropertiesVMAddr) {
		category.ClassProperties, err = f.getObjCPropertiesWithSwift(categoryPtr.ClassPropertiesVMAddr, allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read category class properties at %#x: %w", categoryPtr.ClassPropertiesVMAddr, err)
		}
	}

	return category, nil
}

func (f *File) parseObjcProtocolList(vmaddr uint64) ([]objc.Protocol, error) {
	var protocols []objc.Protocol

	count, err := f.readPointerAtAddress(vmaddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t count: %w", err)
	}
	if count > ^uint64(0)/f.pointerSize() {
		return nil, fmt.Errorf("protocol_list_t count %d overflows its pointer array size", count)
	}
	protocolPointers, err := f.readResolvedObjCPointerArrayAtAddress(vmaddr+f.pointerSize(), count*f.pointerSize())
	if err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t protocols: %w", err)
	}

	for _, protAddr := range protocolPointers {
		if !f.addrResolvable(protAddr) {
			continue // skip cross-image (external) protocol reference
		}
		prot, err := f.getObjcProtocol(protAddr)
		if err != nil {
			return nil, err
		}
		protocols = append(protocols, *prot)
	}

	return protocols, nil
}

func (f *File) getObjcProtocol(vmaddr uint64) (proto *objc.Protocol, err error) {
	protoPtr, hasExtendedMethodTypes, hasDemangledName, hasClassProperties, err := f.readObjCProtocolRecord(vmaddr)
	if err != nil {
		return nil, err
	}

	proto = &objc.Protocol{Ptr: f.rebasePtr(vmaddr)}

	if protoPtr.NameVMAddr > 0 {
		proto.Name, err = f.getCStringWithFallback(protoPtr.NameVMAddr, "protocol name", false)
		if err != nil {
			return nil, fmt.Errorf("failed to read cstring: %v", err)
		}
	}
	if protoPtr.IsaVMAddr > 0 {
		if c, ok := f.cachedObjCClass(protoPtr.IsaVMAddr); ok {
			proto.Isa = c
		} else {
			// FIXME: causes infinite loop
			// proto.Isa, err = f.GetObjCClass(protoPtr.IsaVMAddr)
			// if err != nil {
			// 	return nil, fmt.Errorf("failed to get class at vmaddr: %#x; %v", protoPtr.IsaVMAddr, err)
			// }
			// f.objc[protoPtr.IsaVMAddr] = proto.Isa
		}
	}
	if protoPtr.ProtocolsVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.ProtocolsVMAddr) {
			proto.Prots, err = f.parseObjcProtocolList(protoPtr.ProtocolsVMAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
			}
		}
	}
	if protoPtr.InstanceMethodsVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.InstanceMethodsVMAddr) {
			proto.InstanceMethods, err = f.GetObjCMethods(protoPtr.InstanceMethodsVMAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read instance method vmaddr: %v", err)
			}
		}
	}
	if protoPtr.OptionalInstanceMethodsVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.OptionalInstanceMethodsVMAddr) {
			proto.OptionalInstanceMethods, err = f.GetObjCMethods(protoPtr.OptionalInstanceMethodsVMAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read optional instance method vmaddr: %v", err)
			}
		}
	}
	if protoPtr.ClassMethodsVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.ClassMethodsVMAddr) {
			proto.ClassMethods, err = f.GetObjCMethods(protoPtr.ClassMethodsVMAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read class method vmaddr: %v", err)
			}
		}
	}
	if protoPtr.OptionalClassMethodsVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.OptionalClassMethodsVMAddr) {
			proto.OptionalClassMethods, err = f.GetObjCMethods(protoPtr.OptionalClassMethodsVMAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to read optional class method vmaddr: %v", err)
			}
		}
	}
	if protoPtr.InstancePropertiesVMAddr > 0 {
		if !f.objcCachePointerUnavailable(protoPtr.InstancePropertiesVMAddr) {
			proto.InstanceProperties, err = f.getObjCPropertiesWithSwift(protoPtr.InstancePropertiesVMAddr, false)
			if err != nil {
				return nil, fmt.Errorf("failed to read instance property vmaddr: %v", err)
			}
		}
	}
	if hasExtendedMethodTypes {
		if protoPtr.ExtendedMethodTypesVMAddr > 0 {
			if f.objcCachePointerUnavailable(protoPtr.ExtendedMethodTypesVMAddr) {
				proto.ExtendedMethodTypes = fmt.Sprintf("/* unresolved shared-cache protocol extended method types at %#x */", protoPtr.ExtendedMethodTypesVMAddr)
			} else {
				extendedTypePointers, err := f.readResolvedObjCPointerArrayAtAddress(protoPtr.ExtendedMethodTypesVMAddr, f.pointerSize())
				if err != nil {
					return nil, fmt.Errorf("failed to read ExtendedMethodTypesVMAddr: %v", err)
				}

				resolvedExtendedType := extendedTypePointers[0]
				proto.ExtendedMethodTypes, err = f.getCStringWithFallback(resolvedExtendedType, "protocol extended method type", false)
				if err != nil {
					return nil, fmt.Errorf("failed to read protocol_t at %#x extended method types pointer %#x -> %#x: %v", vmaddr, protoPtr.ExtendedMethodTypesVMAddr, resolvedExtendedType, err)
				}
			}
		}
	}
	if hasDemangledName {
		if protoPtr.DemangledNameVMAddr > 0 {
			proto.DemangledName, err = f.getCStringWithFallback(protoPtr.DemangledNameVMAddr, "protocol demangled name", false)
			if err != nil {
				return nil, fmt.Errorf("failed to read proto demangled name cstring: %v", err)
			}
		}
	}

	// Optional class properties (newer ABI)
	if hasClassProperties {
		if protoPtr.ClassPropertiesVMAddr > 0 {
			if !f.objcCachePointerUnavailable(protoPtr.ClassPropertiesVMAddr) {
				proto.ClassProperties, err = f.getObjCPropertiesWithSwift(protoPtr.ClassPropertiesVMAddr, false)
				if err != nil {
					return nil, fmt.Errorf("failed to read class property vmaddr: %v", err)
				}
			}
		}
	}

	proto.ProtocolT = protoPtr

	return proto, nil
}

// ObjCSelectorBaseUnavailable reports whether ObjC parsing encountered a
// relative method list whose selectors are offsets into the shared cache's
// global selector-string table. That table is absent when a dylib is parsed in
// isolation (e.g. extracted from a dyld_shared_cache), so such method names
// cannot be resolved without the full cache. See [ErrObjCSelectorBaseUnavailable].
func (f *File) ObjCSelectorBaseUnavailable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objcSelectorBaseUnavailable
}

// GetObjCProtocols returns the Objective-C protocols
func (f *File) GetObjCProtocols() ([]objc.Protocol, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProtocols"); err != nil {
		return nil, err
	}

	var protocols []objc.Protocol

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_protolist"); sec != nil {
				ptrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for _, protAddr := range ptrs {
					if !f.addrResolvable(protAddr) {
						continue // skip cross-image (external) protocol reference
					}
					proto, err := f.getObjcProtocol(protAddr)
					if err != nil {
						return nil, fmt.Errorf("failed to read protocol at pointer %#x: %v", protAddr, err)
					}
					protocols = append(protocols, *proto)
				}
			}
		}
	}
	return protocols, nil
}

func (f *File) GetObjCMethods(vmaddr uint64) ([]objc.Method, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethods"); err != nil {
		return nil, err
	}

	if c, ok := f.GetObjC(vmaddr); ok {
		methods, ok := c.([]objc.Method)
		if !ok {
			return nil, fmt.Errorf("ObjC cache entry at %#x has type %T, want []objc.Method", vmaddr, c)
		}
		return methods, nil
	}

	var methods []objc.Method

	if err := f.forEachObjCMethod(vmaddr, func(u uint64, m objc.Method, b *bool) {
		methods = append(methods, m)
	}); err != nil {
		return nil, fmt.Errorf("failed to read methods at vmaddr %#x: %v", vmaddr, err)
	}

	f.PutObjC(vmaddr, methods)

	return methods, nil
}

// GetObjCMethodLists parses the method lists in the __objc_methlist section
func (f *File) GetObjCMethodLists() ([]objc.Method, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCMethodLists"); err != nil {
		return nil, err
	}

	var methods []objc.Method
	var methodList objc.MethodList
	var nextMethodListOffset uint64

	if sec := f.Section("__TEXT", "__objc_methlist"); sec != nil {
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}

		var dat []byte
		if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		r := bytes.NewReader(dat)

		var mladdrs []uint64

		for {
			currOffset, _ := r.Seek(0, io.SeekCurrent)
			currAddr := sec.Addr + uint64(currOffset)

			err := binary.Read(r, f.ByteOrder, &methodList)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read method_list_t: %v", err)
			}

			mladdrs = append(mladdrs, currAddr)
			currOffset, _ = r.Seek(0, io.SeekCurrent)

			// objc emits zero-count sentinels whose entsize contains only flags
			// (and may therefore mask to zero). The header itself is still a
			// complete list and the next header begins at the aligned offset.
			if methodList.Count == 0 {
				var atSectionEnd bool
				nextMethodListOffset, atSectionEnd, err = nextObjCMethodListOffset(uint64(currOffset), sec.Size, f.pointerSize())
				if err != nil {
					return nil, fmt.Errorf("empty method_list_t at %#x extends past %s.%s", currAddr, sec.Seg, sec.Name)
				}
				if atSectionEnd {
					break
				}
				if _, err := r.Seek(int64(nextMethodListOffset), io.SeekStart); err != nil {
					return nil, fmt.Errorf("failed to seek past empty method_list_t: %v", err)
				}
				continue
			}

			entrySize := uint64(methodList.EntSize())
			minimumEntrySize := 3 * f.pointerSize()
			if methodList.UsesRelativeOffsets() {
				minimumEntrySize = uint64(binary.Size(objc.RelativeMethodT{}))
			}
			if entrySize < minimumEntrySize {
				return nil, fmt.Errorf("method_list_t at %#x has entry size %d, smaller than required %d", currAddr, entrySize, minimumEntrySize)
			}
			if uint64(methodList.Count) > (^uint64(0)-uint64(currOffset))/entrySize {
				return nil, fmt.Errorf("method_list_t at %#x entry array size overflows", currAddr)
			}
			bodyEnd := uint64(currOffset) + uint64(methodList.Count)*entrySize
			var atSectionEnd bool
			nextMethodListOffset, atSectionEnd, err = nextObjCMethodListOffset(bodyEnd, sec.Size, f.pointerSize())
			if err != nil {
				return nil, fmt.Errorf("method_list_t at %#x extends past %s.%s", currAddr, sec.Seg, sec.Name)
			}
			if atSectionEnd {
				break
			}
			if _, err := r.Seek(int64(nextMethodListOffset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to next method_list_t: %v", err)
			}
		}

		for _, mladdr := range mladdrs {
			if err := f.forEachObjCMethod(mladdr, func(u uint64, m objc.Method, b *bool) {
				methods = append(methods, m)
			}); err != nil {
				return nil, fmt.Errorf("failed to read methods for method_list_t at vmaddr %#x: %v", mladdr, err)
			}
		}
	} else {
		return nil, fmt.Errorf("macho does not contain __objc_methlist section: %w", ErrObjcSectionNotFound)
	}

	return methods, nil
}

// nextObjCMethodListOffset returns the aligned start of a following method
// list. A final list may end exactly at the section boundary; in that case no
// padding for a non-existent next list is required.
func nextObjCMethodListOffset(bodyEnd, sectionSize, alignment uint64) (uint64, bool, error) {
	if bodyEnd > sectionSize {
		return 0, false, fmt.Errorf("method list body end %#x exceeds section size %#x", bodyEnd, sectionSize)
	}
	if bodyEnd == sectionSize {
		return bodyEnd, true, nil
	}
	if alignment == 0 {
		return 0, false, errors.New("method list alignment is zero")
	}
	padding := (alignment - bodyEnd%alignment) % alignment
	if padding > sectionSize-bodyEnd {
		return 0, false, fmt.Errorf("aligned method list end %#x exceeds section size %#x", bodyEnd+padding, sectionSize)
	}
	next := bodyEnd + padding
	return next, next == sectionSize, nil
}

func (f *File) forEachObjCMethod(methodListVMAddr uint64, handler func(uint64, objc.Method, *bool)) error {
	var methodList objc.MethodList

	if err := f.cr.SeekToAddr(methodListVMAddr); err != nil {
		return fmt.Errorf("failed to seek to method_list_t at %#x: %v", methodListVMAddr, err)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &methodList); err != nil {
		return fmt.Errorf("failed to read method_list_t at %#x: %v", methodListVMAddr, err)
	}
	// The cache builder's shared empty method list has no entries and carries
	// only the uniqued/sorted low-bit flags (raw entsizeAndFlags == 3). Its
	// masked entry size is therefore zero, which is valid because count is zero.
	if methodList.Count == 0 {
		return nil
	}

	if methodList.UsesRelativeOffsets() {
		methodListArrayBaseVMAddr := methodListVMAddr + uint64(binary.Size(methodList))
		entrySize := uint64(methodList.EntSize())
		minimumEntrySize := uint64(binary.Size(objc.RelativeMethodT{}))
		if entrySize < minimumEntrySize {
			return fmt.Errorf("relative method_list_t at %#x has entry size %d, smaller than required %d", methodListVMAddr, entrySize, minimumEntrySize)
		}
		if uint64(methodList.Count) > (^uint64(0)-methodListArrayBaseVMAddr)/entrySize {
			return fmt.Errorf("relative method_list_t at %#x entry array size overflows", methodListVMAddr)
		}

		for idx := uint32(0); idx < methodList.Count; idx++ {
			methodVMAddr := methodListArrayBaseVMAddr + uint64(idx)*entrySize
			data, err := saferio.ReadDataAt(&addrReaderAt{r: f.cr, addr: methodVMAddr}, minimumEntrySize, 0)
			if err != nil {
				return fmt.Errorf("failed to read relative_method_t at %#x: %v", methodVMAddr, err)
			}
			m := objc.RelativeMethodT{
				NameOffset:  int32(f.ByteOrder.Uint32(data[0:4])),
				TypesOffset: int32(f.ByteOrder.Uint32(data[4:8])),
				ImpOffset:   int32(f.ByteOrder.Uint32(data[8:12])),
			}

			method := objc.Method{}

			if methodList.UsesDirectOffsetsToSelectors() {
				if f.sharedCacheRelativeSelectorBaseVMAddress != 0 {
					// nameOffset is an unsigned offset into the shared cache's
					// selector strings buffer (dyld reads it as uint32), matching
					// the relative method types buffer handling below.
					method.NameVMAddr = f.sharedCacheRelativeSelectorBaseVMAddress + uint64(uint32(m.NameOffset))
				} else {
					f.mu.Lock()
					f.objcSelectorBaseUnavailable = true
					f.mu.Unlock()
					return fmt.Errorf("%w (method list %#x)", ErrObjCSelectorBaseUnavailable, methodListVMAddr)
				}
			} else {
				// RelativePointer offsets are relative to the field address, not the struct base
				nameFieldAddr := methodVMAddr + uint64(unsafe.Offsetof(m.NameOffset))
				nameIndirectAddr := uint64(int64(nameFieldAddr) + int64(m.NameOffset))
				method.NameVMAddr, err = f.GetPointerAtAddress(nameIndirectAddr)
				if err != nil {
					return fmt.Errorf("failed to read relative_method_t name pointer: %v", err)
				}
			}

			method.NameLocationVMAddr = methodVMAddr + uint64(unsafe.Offsetof(m.NameOffset))

			// RelativePointer offsets are relative to the field address, not the struct base
			// This matches Apple's objc4 RelativePointer implementation: actual_address = &offset_field + offset
			typesFieldAddr := int64(methodVMAddr) + int64(unsafe.Offsetof(m.TypesOffset))
			impFieldAddr := int64(methodVMAddr) + int64(unsafe.Offsetof(m.ImpOffset))
			if methodList.UsesDirectOffsetsToTypes() && f.sharedCacheRelativeSelectorBaseVMAddress != 0 {
				// iOS 27+: typesOffset is an unsigned offset into the shared cache's
				// relative method types buffer (which follows the selector strings
				// buffer), measured from the same selector base address.
				method.TypesVMAddr = f.sharedCacheRelativeSelectorBaseVMAddress + uint64(uint32(m.TypesOffset))
			} else {
				method.TypesVMAddr = uint64(typesFieldAddr + int64(m.TypesOffset))
			}
			method.ImpVMAddr = uint64(impFieldAddr + int64(m.ImpOffset))

			method.Name, err = f.getCStringWithFallback(method.NameVMAddr, "selector", false)
			if err != nil {
				return fmt.Errorf("failed to read relative_method_t name cstring: %v", err)
			}
			method.Types, err = f.getCStringWithFallback(method.TypesVMAddr, "method types", false)
			if err != nil {
				return fmt.Errorf("failed to read relative_method_t types cstring: %v", err)
			}

			stop := false
			handler(methodVMAddr, method, &stop)
			if stop { // handler requested to halt iteration
				break
			}
		}
	} else {
		methodListArrayBaseVMAddr := methodListVMAddr + uint64(binary.Size(methodList))
		entrySize := uint64(methodList.EntSize())
		minimumEntrySize := 3 * f.pointerSize()
		if entrySize < minimumEntrySize {
			return fmt.Errorf("method_list_t at %#x has entry size %d, smaller than required %d", methodListVMAddr, entrySize, minimumEntrySize)
		}
		if uint64(methodList.Count) > (^uint64(0)-methodListArrayBaseVMAddr)/entrySize {
			return fmt.Errorf("method_list_t at %#x entry array size overflows", methodListVMAddr)
		}
		for idx := uint32(0); idx < methodList.Count; idx++ {
			methodVMAddr := methodListArrayBaseVMAddr + uint64(idx)*entrySize
			m, err := f.readObjCMethodRecord(methodVMAddr)
			if err != nil {
				return err
			}
			n, err := f.getCStringWithFallback(m.NameVMAddr, "selector", false)
			if err != nil {
				return fmt.Errorf("failed to read method_t name cstring: %v", err)
			}
			t, err := f.getCStringWithFallback(m.TypesVMAddr, "method types", false)
			if err != nil {
				return fmt.Errorf("failed to read method_t types cstring: %v", err)
			}
			stop := false
			handler(methodVMAddr, objc.Method{
				NameVMAddr:         m.NameVMAddr,
				TypesVMAddr:        m.TypesVMAddr,
				ImpVMAddr:          m.ImpVMAddr,
				NameLocationVMAddr: methodVMAddr,
				Name:               n,
				Types:              t,
			}, &stop)
			if stop { // handler requested to halt iteration
				break
			}
		}
	}

	return nil
}

// GetObjCIvars returns the Objective-C instance variables
func (f *File) GetObjCIvars(vmaddr uint64) ([]objc.Ivar, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCIvars"); err != nil {
		return nil, err
	}

	return f.getObjCIvarsWithSwift(vmaddr, false)
}

func (f *File) getObjCIvarsWithSwift(vmaddr uint64, allowSwift bool) ([]objc.Ivar, error) {

	var ivarsList objc.IvarList
	var ivars []objc.Ivar

	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc_ivar_list_t at %#x: %v", vmaddr, err)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &ivarsList); err != nil {
		return nil, fmt.Errorf("failed to read objc_ivar_list_t: %v", err)
	}
	if ivarsList.Count == 0 {
		return nil, nil
	}

	minimumEntrySize := 3*f.pointerSize() + 8
	entrySize := uint64(ivarsList.EntSize)
	if entrySize < minimumEntrySize {
		return nil, fmt.Errorf("objc_ivar_list_t at %#x has entry size %d, smaller than required %d", vmaddr, entrySize, minimumEntrySize)
	}
	arrayBase := vmaddr + uint64(binary.Size(ivarsList))
	if uint64(ivarsList.Count) > (^uint64(0)-arrayBase)/entrySize {
		return nil, fmt.Errorf("objc_ivar_list_t at %#x entry array size overflows", vmaddr)
	}

	// FIXME: what ARE these alignments ?
	// var maxAlignment uint32
	// for _, ivar := range ivs {
	// 	if ivar.Alignment() > maxAlignment {
	// 		maxAlignment = ivar.Alignment()
	// 	}
	// }

	// var diff uint32
	// if maxAlignment > 0 {
	// 	alignMask := maxAlignment - 1
	// 	diff = (diff + alignMask) &^ alignMask
	// }

	for idx := uint32(0); idx < ivarsList.Count; idx++ {
		ivar, err := f.readObjCIvarRecord(arrayBase + uint64(idx)*entrySize)
		if err != nil {
			return nil, err
		}
		// ivar.Offset += uint64(diff) // align ivar offsets to max alignment

		if ivar.Offset > 0 {
			if err := f.cr.SeekToAddr(ivar.Offset); err != nil {
				return nil, fmt.Errorf("failed to seek to objc_ivar_list_t at %#x: %v", vmaddr, err)
			}
		}

		var o uint32
		if err := binary.Read(f.cr, f.ByteOrder, &o); err != nil {
			if err == io.EOF {
				o = 0 // I've seen this happen when this points to the zero-filled __DATA __common section
			} else {
				return nil, fmt.Errorf("failed to read ivar.offset: %v", err)
			}
		}
		n, err := f.GetCString(ivar.NameVMAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read ivar name cstring: %v", err)
		}
		// if diff > 0 {
		// 	ivar.TypesVMAddr += uint64(diff) // align ivar types to max alignment
		// }
		t, err := f.getCStringWithFallback(ivar.TypesVMAddr, "ivar type", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read ivar types cstring: %v", err)
		}
		if allowSwift {
			t = normalizeSwiftIvarTypeEncoding(t)
		}
		if allowSwift && t == "" {
			if guess, ok := f.swiftASCIITypeGuess(ivar.TypesVMAddr); ok {
				t = guess
			}
		}
		ivars = append(ivars, objc.Ivar{
			Name:   n,
			Type:   t,
			Offset: o,
			IvarT:  ivar,
		})
	}

	return ivars, nil
}

func normalizeSwiftIvarTypeEncoding(enc string) string {
	enc = strings.TrimSpace(enc)
	if enc == "" || !strings.Contains(enc, ":") {
		return enc
	}

	typ, rest, ok := objc.CutType(enc)
	if !ok || rest == "" {
		return enc
	}

	stackSizePrefixLen := leadingDecimalLen(rest)
	if stackSizePrefixLen == 0 {
		return enc
	}

	if strings.Contains(rest[stackSizePrefixLen:], ":") {
		return typ
	}

	return enc
}

func leadingDecimalLen(input string) int {
	length := 0
	for length < len(input) && input[length] >= '0' && input[length] <= '9' {
		length++
	}
	return length
}

// GetObjCProperties returns the Objective-C properties
func (f *File) GetObjCProperties(vmaddr uint64) ([]objc.Property, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProperties"); err != nil {
		return nil, err
	}

	return f.getObjCPropertiesWithSwift(vmaddr, false)
}

func (f *File) getObjCPropertiesWithSwift(vmaddr uint64, allowSwift bool) ([]objc.Property, error) {

	var propList objc.PropertyList
	var objcProperties []objc.Property

	if err := f.cr.SeekToAddr(vmaddr); err != nil {
		return nil, fmt.Errorf("failed to seek to objc_property_list_t at %#x: %v", vmaddr, err)
	}

	if err := binary.Read(f.cr, f.ByteOrder, &propList); err != nil {
		return nil, fmt.Errorf("failed to read objc_property_list_t: %v", err)
	}
	// Apple emits an all-zero ListOfListsEntry as the final entry when a
	// preattached class has no original properties. offset==0 makes that entry
	// point to itself, where it is intentionally interpreted as the empty
	// property_list_t { entsize: 0, count: 0 }. No entry is accessed when count
	// is zero, so entsize has no validity requirement in this case.
	if propList.Count == 0 {
		return objcProperties, nil
	}

	minimumEntrySize := 2 * f.pointerSize()
	entrySize := uint64(propList.EntSize &^ 3)
	if entrySize < minimumEntrySize {
		return nil, fmt.Errorf("objc_property_list_t at %#x has entry size %d, smaller than required %d", vmaddr, entrySize, minimumEntrySize)
	}
	arrayBase := vmaddr + uint64(binary.Size(propList))
	if uint64(propList.Count) > (^uint64(0)-arrayBase)/entrySize {
		return nil, fmt.Errorf("objc_property_list_t at %#x entry array size overflows", vmaddr)
	}

	for idx := uint32(0); idx < propList.Count; idx++ {
		prop, err := f.readObjCPropertyRecord(arrayBase + uint64(idx)*entrySize)
		if err != nil {
			return nil, err
		}
		name, err := f.getCStringWithFallback(prop.NameVMAddr, "property name", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read prop name cstring: %v", err)
		}
		attrib, err := f.getCStringWithFallback(prop.AttributesVMAddr, "property attributes", allowSwift)
		if err != nil {
			return nil, fmt.Errorf("failed to read prop attributes cstring: %v", err)
		}
		objcProperties = append(objcProperties, objc.Property{
			PropertyT:         prop,
			Name:              name,
			EncodedAttributes: attrib,
		})
	}

	return objcProperties, nil
}

// GetObjCClassReferences returns a map of classes to their section data virtual memory address
func (f *File) GetObjCClassReferences() (map[uint64]*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCClassReferences"); err != nil {
		return nil, err
	}

	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_classrefs"); sec != nil { // External references to other classes
				classPtrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for idx, ptr := range classPtrs {
					slotAddr := sec.Addr + uint64(idx)*f.pointerSize()
					if c, ok := f.cachedObjCClass(ptr); ok {
						clsRefs[slotAddr] = c
					} else {
						if cls, err := f.GetObjCClass(ptr); err != nil {
							if f.objcCachePointerUnavailable(ptr) {
								clsRefs[slotAddr] = &objc.Class{Name: fmt.Sprintf("<unresolved shared-cache class %#x>", ptr)}
							} else if f.HasFixups() {
								if bindName, bindErr := f.getBindNameAtAddress(slotAddr); bindErr == nil {
									clsRefs[slotAddr] = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
								} else {
									return nil, fmt.Errorf("failed to read objc_class_t at classref ptr: %#x; %w", ptr, errors.Join(err, bindErr))
								}
							}
						} else {
							clsRefs[slotAddr] = cls
							f.PutObjC(ptr, cls)
						}
					}
				}
			}
		}
	}

	return clsRefs, nil
}

// GetObjCSuperReferences returns a map of super classes to their section data virtual memory address
func (f *File) GetObjCSuperReferences() (map[uint64]*objc.Class, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCSuperReferences"); err != nil {
		return nil, err
	}

	clsRefs := make(map[uint64]*objc.Class)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_superrefs"); sec != nil { // External references to super classes
				classPtrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for idx, ptr := range classPtrs {
					slotAddr := sec.Addr + uint64(idx)*f.pointerSize()
					if c, ok := f.cachedObjCClass(ptr); ok {
						clsRefs[slotAddr] = c
					} else {
						if cls, err := f.GetObjCClass(ptr); err != nil {
							if f.objcCachePointerUnavailable(ptr) {
								clsRefs[slotAddr] = &objc.Class{Name: fmt.Sprintf("<unresolved shared-cache class %#x>", ptr)}
							} else if f.HasFixups() {
								if bindName, bindErr := f.getBindNameAtAddress(slotAddr); bindErr == nil {
									clsRefs[slotAddr] = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
								} else {
									return nil, fmt.Errorf("failed to read objc_class_t at superref ptr: %#x; %w", ptr, errors.Join(err, bindErr))
								}
							}
						} else {
							clsRefs[slotAddr] = cls
							f.PutObjC(ptr, cls)
						}
					}
				}
			}
		}
	}
	return clsRefs, nil
}

// GetObjCProtoReferences returns a map of protocol names to their section data virtual memory address
func (f *File) GetObjCProtoReferences() (map[uint64]*objc.Protocol, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCProtoReferences"); err != nil {
		return nil, err
	}

	protRefs := make(map[uint64]*objc.Protocol)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			for _, secName := range []string{"__objc_protorefs", "__objc_protolist"} { // External references to protocols and list of ObjC protocols
				if sec := f.Section(s.Name, secName); sec != nil {
					protoPtrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
					if err != nil {
						return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
					}

					for idx, protoAddr := range protoPtrs {
						slotAddr := sec.Addr + uint64(idx)*f.pointerSize()
						if f.objcCachePointerUnavailable(protoAddr) {
							protRefs[slotAddr] = &objc.Protocol{Ptr: protoAddr, Name: fmt.Sprintf("<unresolved shared-cache protocol %#x>", protoAddr)}
							continue
						}
						proto, err := f.getObjcProtocol(protoAddr)
						if err != nil {
							return nil, fmt.Errorf("failed to read protocol_t at ptr: %#x; %v", protoAddr, err)
						}
						protRefs[slotAddr] = proto
					}
				}
			}
		}
	}

	return protRefs, nil
}

// GetObjCSelectorReferences returns a map of selector names to their section data virtual memory address
func (f *File) GetObjCSelectorReferences() (map[uint64]*objc.Selector, error) {
	if err := f.ensureObjCNonFragileRuntime("GetObjCSelectorReferences"); err != nil {
		return nil, err
	}

	selRefs := make(map[uint64]*objc.Selector)

	for _, s := range f.Segments() {
		if strings.HasPrefix(s.Name, "__DATA") {
			if sec := f.Section(s.Name, "__objc_selrefs"); sec != nil { // External references to selectors
				selPtrs, err := f.readResolvedObjCPointerArrayAtAddress(sec.Addr, sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read %s.%s pointers: %w", sec.Seg, sec.Name, err)
				}

				for idx, sel := range selPtrs {
					selName, err := f.getCStringWithFallback(sel, "selector", false)
					if err != nil {
						return nil, fmt.Errorf("failed to read selector name cstring: %v", err)
					}
					selRefs[sec.Addr+uint64(idx)*f.pointerSize()] = &objc.Selector{
						VMAddr: sel,
						Name:   selName,
					}
				}
			}
		}
	}

	return selRefs, nil
}

// GetCFStrings returns the Objective-C CFStrings
func (f *File) GetCFStrings() ([]objc.CFString, error) {
	var cfstrings []objc.CFString

	for _, s := range f.Segments() {
		if sec := f.Section(s.Name, "__cfstring"); sec != nil {
			recordSize := 4 * f.pointerSize()
			if sec.Size%recordSize != 0 {
				return nil, fmt.Errorf("%s.%s size %d is not divisible by constant CFString record size %d", sec.Seg, sec.Name, sec.Size, recordSize)
			}
			count := sec.Size / recordSize
			for idx := uint64(0); idx < count; idx++ {
				recordAddr := sec.Addr + idx*recordSize
				record, err := f.readCFStringRecord(recordAddr)
				if err != nil {
					return nil, err
				}
				cfstring := objc.CFString{CFString64Type: record, Address: recordAddr}
				if bind, bindErr := f.getBindNameAtAddress(recordAddr); bindErr == nil {
					cfstring.ISA = bind
				}
				if cfstring.Data == 0 {
					return nil, fmt.Errorf("unhandled cstring parse case where data is 0") // TODO: finish this
					// uint64_t n_value;
					// const char *symbol_name = get_symbol_64(offset + offsetof(struct cfstring64_t, characters), S, info, n_value);
					// if (symbol_name == nullptr)
					//   return nullptr;
					// cfs_characters = n_value;
				}
				// Check encoding from Info field and use appropriate string reader
				if cfstring.CFString64Type.IsUTF16() {
					cfstring.Name, err = f.getUTF16String(cfstring.Data, cfstring.Length)
				} else {
					cfstring.Name, err = f.GetCString(cfstring.Data)
				}
				if err != nil {
					return nil, fmt.Errorf("failed to read cfstring: %v", err)
				}
				if c, ok := f.cachedObjCClass(cfstring.IsaVMAddr); ok {
					cfstring.Class = c
				}
				cfstrings = append(cfstrings, cfstring)
			}
		}
	}

	return cfstrings, nil
}

// GetObjCIntObj parses the __objc_intobj section and returns a map of
func (f *File) GetObjCIntegerObjects() (map[uint64]*objc.IntObj, error) {
	if sec := f.Section("__TEXT", "__objc_intobj"); sec != nil {
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}
		var dat []byte
		if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		intObjs := make([]objc.IntObj, int(sec.Size)/binary.Size(objc.IntObj{}))
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &intObjs); err != nil {
			return nil, fmt.Errorf("failed to read %T structs: %v", intObjs, err)
		}

		intObjMap := make(map[uint64]*objc.IntObj)
		for idx, intObj := range intObjs {
			intObjMap[sec.Addr+uint64(idx*binary.Size(objc.IntObj{}))] = &intObj
		}

		return intObjMap, nil
	}

	return nil, fmt.Errorf("macho does not contain __objc_intobj section: %w", ErrObjcSectionNotFound)
}

// GetObjCStubs returns the Objective-C stubs
func (f *File) GetObjCStubs(parse func(uint64, []byte) (map[uint64]*objc.Stub, error)) (map[uint64]*objc.Stub, error) {
	if sec := f.Section("__TEXT", "__objc_stubs"); sec != nil {
		if err := f.cr.SeekToAddr(sec.Addr); err != nil {
			return nil, fmt.Errorf("failed to seek to %s addr %#x: %v", sec.Name, sec.Addr, err)
		}
		var dat []byte
		if err := readDataFrom(f.cr, sec.Size, &dat); err != nil {
			return nil, fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}
		return parse(sec.Addr, dat)
	}

	return nil, fmt.Errorf("macho does not contain __objc_stubs section: %w", ErrObjcSectionNotFound)
}
