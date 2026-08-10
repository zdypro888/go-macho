package macho

import "testing"

func TestNextObjCMethodListOffsetAllowsFinalUnpaddedList(t *testing.T) {
	const sectionSize = 0x5194

	next, atEnd, err := nextObjCMethodListOffset(sectionSize, sectionSize, 8)
	if err != nil {
		t.Fatal(err)
	}
	if next != sectionSize || !atEnd {
		t.Fatalf("got next=%#x atEnd=%t, want %#x true", next, atEnd, sectionSize)
	}
}

func TestNextObjCMethodListOffsetAlignsOnlyWhenAnotherListCanFollow(t *testing.T) {
	next, atEnd, err := nextObjCMethodListOffset(0x2c, 0x80, 8)
	if err != nil {
		t.Fatal(err)
	}
	if next != 0x30 || atEnd {
		t.Fatalf("got next=%#x atEnd=%t, want 0x30 false", next, atEnd)
	}

	if _, _, err := nextObjCMethodListOffset(0x7c, 0x7f, 8); err == nil {
		t.Fatal("expected alignment past section end to fail")
	}
}
