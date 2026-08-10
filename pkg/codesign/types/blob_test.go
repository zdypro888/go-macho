package types

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSuperBlobLengthMatchesEncodingForEveryBlobCount(t *testing.T) {
	for count := 0; count <= 5; count++ {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			super := NewSuperBlob(MAGIC_EMBEDDED_SIGNATURE)
			for index := 0; index < count; index++ {
				super.AddBlob(SlotType(index), NewBlob(MAGIC_BLOBWRAPPER, bytes.Repeat([]byte{byte(index + 1)}, index+1)))
			}

			var encoded bytes.Buffer
			if err := super.Write(&encoded, binary.BigEndian); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if super.Size() != encoded.Len() || int(super.Length) != encoded.Len() {
				t.Fatalf("size=%d length=%d encoded=%d", super.Size(), super.Length, encoded.Len())
			}
			var header SbHeader
			if err := binary.Read(bytes.NewReader(encoded.Bytes()), binary.BigEndian, &header); err != nil {
				t.Fatalf("read header: %v", err)
			}
			if header.Count != uint32(count) || int(header.Length) != encoded.Len() {
				t.Fatalf("header count=%d length=%d, want %d/%d", header.Count, header.Length, count, encoded.Len())
			}
			offset := uint32(binary.Size(SbHeader{}) + count*binary.Size(BlobIndex{}))
			for index := range count {
				if super.Index[index].Offset != offset {
					t.Fatalf("index %d offset=%d, want %d", index, super.Index[index].Offset, offset)
				}
				offset += super.Blobs[index].Length
			}
			if offset != header.Length {
				t.Fatalf("final offset=%d, want length=%d", offset, header.Length)
			}
		})
	}
}
