package macho

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/zdypro888/go-macho/types"
)

// findSegmentCommand returns the offset of the LC_SEGMENT_64 named name.
func findSegmentCommand(data []byte, name string) int {
	if len(data) < 32 || binary.LittleEndian.Uint32(data) != uint32(types.Magic64) {
		return -1
	}
	ncmds := binary.LittleEndian.Uint32(data[16:])
	off := 32
	for i := uint32(0); i < ncmds && off+72 <= len(data); i++ {
		if types.LoadCmd(binary.LittleEndian.Uint32(data[off:])) == types.LC_SEGMENT_64 &&
			string(bytes.TrimRight(data[off+8:off+24], "\x00")) == name {
			return off
		}
		off += int(binary.LittleEndian.Uint32(data[off+4:]))
	}
	return -1
}

// A segment filesize is copied straight from the load command. Export and
// SaveBuffer used to pre-grow the output buffer and make() the segment by that
// size: a negative Grow count panicked, anything smaller was allocated.
func TestExportAndSaveBoundSegmentFilesize(t *testing.T) {
	src := thinSystemBinary(t)
	le := binary.LittleEndian

	for _, tt := range []struct {
		name    string
		segment string
		filesz  uint64
	}{
		{"__LINKEDIT 8 GiB", "__LINKEDIT", 8 << 30},
		{"__LINKEDIT int overflow", "__LINKEDIT", 0xffffffffffff0000},
		{"__LINKEDIT 2^63", "__LINKEDIT", 1 << 63},
		{"__TEXT 8 GiB", "__TEXT", 8 << 30},
		{"__DATA_CONST 64 GiB", "__DATA_CONST", 64 << 30},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Clone(src)
			off := findSegmentCommand(data, tt.segment)
			if off < 0 {
				t.Skipf("no %s in the seed binary", tt.segment)
			}
			le.PutUint64(data[off+48:], tt.filesz) // segment_command_64.filesize

			t.Run("Export", func(t *testing.T) {
				f, err := NewFile(bytes.NewReader(data))
				if err != nil {
					t.Skipf("NewFile already rejects the input: %v", err)
				}
				defer f.Close()
				out := filepath.Join(t.TempDir(), "out")
				bounded(t, func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("Export panicked: %v", r)
						}
					}()
					if err := f.Export(out, nil, 0, nil); err == nil {
						t.Error("Export accepted a segment larger than the file")
					}
				})
			})
			t.Run("SaveBuffer", func(t *testing.T) {
				f, err := NewFile(bytes.NewReader(data))
				if err != nil {
					t.Skipf("NewFile already rejects the input: %v", err)
				}
				defer f.Close()
				bounded(t, func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("SaveBuffer panicked: %v", r)
						}
					}()
					var buf bytes.Buffer
					if err := f.SaveBuffer(&buf); err == nil {
						t.Error("SaveBuffer accepted a segment larger than the file")
					}
				})
			})
		})
	}
}

// Sizes at and above safeAllocChunk take the chunked path; the bytes written
// must not depend on which path was taken.
func TestExportLargeSegmentMatchesSmallPath(t *testing.T) {
	src := thinSystemBinary(t)
	off := findSegmentCommand(src, "__LINKEDIT")
	if off < 0 {
		t.Skip("no __LINKEDIT in the seed binary")
	}
	le := binary.LittleEndian
	// Append zero bytes to the file and extend __LINKEDIT over them, once
	// staying below the threshold and once crossing it. The exported file
	// must be the input plus page alignment in both cases.
	for _, extra := range []uint64{1 << 20, safeAllocChunk + (1 << 20)} {
		data := append(bytes.Clone(src), make([]byte, extra)...)
		fileoff := le.Uint64(data[off+40:])
		le.PutUint64(data[off+48:], uint64(len(data))-fileoff)
		le.PutUint64(data[off+32:], pageAlign(uint64(len(data))-fileoff, 0x4000)) // vmsize

		f, err := NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("NewFile: %v", err)
		}
		var saved bytes.Buffer
		if err := f.SaveBuffer(&saved); err != nil {
			t.Fatalf("SaveBuffer(extra=%#x): %v", extra, err)
		}
		f.Close()
		if !bytes.Equal(saved.Bytes(), data) {
			t.Fatalf("SaveBuffer(extra=%#x) does not reproduce the input (%d vs %d bytes)", extra, saved.Len(), len(data))
		}
	}
}
