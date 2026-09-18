package macho

import "testing"

func TestExportedSegmentMemsz(t *testing.T) {
	for _, test := range []struct {
		name                          string
		filesz, origFilesz, origMemsz uint64
		want                          uint64
	}{
		// unchanged from the previous formula
		{"no zerofill", 0x4000, 0x4000, 0x4000, 0x4000},
		{"no zerofill, grown", 0x8000, 0x5a60, 0x5a60, 0x8000},
		{"pure zerofill segment", 0, 0, 0x64000, 0x64000},
		{"aligned data with bss", 0x4000, 0x4000, 0xc000, 0xc000},
		{"rebuilt smaller", 0x4000, 0x8000, 0xc000, 0x8000},
		// alignment padding used to be counted twice (0xa5a0 for /bin/ls)
		{"__LINKEDIT of /bin/ls", 0x8000, 0x5a60, 0x8000, 0x8000},
		{"padding exceeds the gap", 0xc000, 0x5a60, 0x8000, 0xc000},
	} {
		if got := exportedSegmentMemsz(test.filesz, test.origFilesz, test.origMemsz); got != test.want {
			t.Errorf("%s: got %#x want %#x", test.name, got, test.want)
		}
	}
}
