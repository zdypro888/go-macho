package macho

import (
	"bytes"
	"encoding/binary"
	"github.com/zdypro888/go-macho/types"
	"testing"
)

// 旧kext只有本地重定位可无符号表；普通镜像及有符号引用的损坏kext仍拒绝。
func TestLegacyKextDysymtabWithoutSymtab(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     types.HeaderFileType
		modify  func(*types.DysymtabCmd)
		wantErr bool
	}{
		{"empty kext", types.MH_KEXT_BUNDLE, func(*types.DysymtabCmd) {}, false},
		{"local relocation", types.MH_KEXT_BUNDLE, func(d *types.DysymtabCmd) { d.Nlocrel = 1; d.Locreloff = 112 }, false},
		{"ordinary executable", types.MH_EXECUTE, func(*types.DysymtabCmd) {}, true},
		{"undefined", types.MH_KEXT_BUNDLE, func(d *types.DysymtabCmd) { d.Nundefsym = 1 }, true},
		{"index", types.MH_KEXT_BUNDLE, func(d *types.DysymtabCmd) { d.Ilocalsym = 1 }, true},
		{"indirect", types.MH_KEXT_BUNDLE, func(d *types.DysymtabCmd) { d.Nindirectsyms = 1 }, true},
		{"external relocation", types.MH_KEXT_BUNDLE, func(d *types.DysymtabCmd) { d.Nextrel = 1 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			h := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: tc.typ, NCommands: 1, SizeCommands: 80}
			d := types.DysymtabCmd{LoadCmd: types.LC_DYSYMTAB, Len: 80}
			tc.modify(&d)
			for _, v := range []any{h, d, [8]byte{}} {
				if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
					t.Fatal(err)
				}
			}
			f, err := NewFile(bytes.NewReader(b.Bytes()))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantError=%v", err, tc.wantErr)
			}
			if err == nil {
				defer f.Close()
				if f.Dysymtab == nil || len(f.Dysymtab.InternalRelocs) != int(d.Nlocrel) {
					t.Fatal("relocations lost")
				}
			}
		})
	}
}
