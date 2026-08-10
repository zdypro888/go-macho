package trie

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"

	"github.com/zdypro888/go-macho/types"
)

type Node struct {
	Offset uint64
	Data   []byte
}

type TrieExport struct {
	Name         string
	ReExport     string
	Flags        types.ExportFlag
	Other        uint64
	Address      uint64
	FoundInDylib string
}

func (e TrieExport) Type() string {
	if e.Flags.ReExport() {
		if len(e.ReExport) == 0 {
			return fmt.Sprintf("from %s", filepath.Base(e.FoundInDylib))
		} else {
			return fmt.Sprintf("%s re-exported from %s", e.ReExport, filepath.Base(e.FoundInDylib))
		}
	} else if e.Flags.StubAndResolver() {
		return fmt.Sprintf("resolver=%#8x", e.Other)
	}
	return e.Flags.String()
}

func (e TrieExport) String() string {
	return fmt.Sprintf("%#09x:\t(%s)\t%s", e.Address, e.Type(), e.Name)
}

func ReadUleb128(r *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint64

	for byteIndex := 0; ; byteIndex++ {
		b, err := r.ReadByte()
		if err == io.EOF {
			return 0, err
		}
		if err != nil {
			return 0, fmt.Errorf("could not parse ULEB128 value: %v", err)
		}

		if byteIndex == 9 && b > 1 {
			return 0, fmt.Errorf("ULEB128 value overflows uint64")
		}
		if byteIndex >= 10 {
			return 0, fmt.Errorf("ULEB128 value exceeds 10 bytes")
		}
		result |= uint64(b&0x7f) << shift

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

func ReadSleb128(r *bytes.Reader) (int64, error) {
	var result int64
	var shift uint64

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return 0, err
		}
		if err != nil {
			return 0, fmt.Errorf("could not parse SLEB128 value: %v", err)
		}

		result |= int64((int64(b) & 0x7f) << shift)
		shift += 7

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			if (shift < 64) && ((b & 0x40) > 0) {
				result |= -(1 << shift)
			}

			break
		}
	}

	return result, nil
}

func ReadUleb128FromBuffer(buf *bytes.Buffer) (uint64, int, error) {

	var (
		result uint64
		shift  uint64
		length int
	)

	if buf.Len() == 0 {
		return 0, 0, nil
	}

	for {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, 0, fmt.Errorf("could not parse ULEB128 value: %v", err)
		}
		length++

		result |= uint64((uint(b) & 0x7f) << shift)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, length, nil
}

// EncodeUleb128 encodes input to the Unsigned Little Endian Base 128 format
func EncodeUleb128(out io.ByteWriter, x uint64) {
	for {
		b := byte(x & 0x7f)
		x = x >> 7
		if x != 0 {
			b = b | 0x80
		}
		out.WriteByte(b)
		if x == 0 {
			break
		}
	}
}

// EncodeSleb128 encodes input to the Signed Little Endian Base 128 format
func EncodeSleb128(out io.ByteWriter, x int64) {
	for {
		b := byte(x & 0x7f)
		x >>= 7

		signb := b & 0x40

		last := false
		if (x == 0 && signb == 0) || (x == -1 && signb != 0) {
			last = true
		} else {
			b = b | 0x80
		}
		out.WriteByte(b)

		if last {
			break
		}
	}
}

func ReadExport(r *bytes.Reader, symbol string, loadAddress uint64) (*TrieExport, error) {
	symFlagInt, err := ReadUleb128(r)
	if err != nil {
		return nil, fmt.Errorf("could not parse ULEB128 symbol flag value: %v", err)
	}

	flags := types.ExportFlag(symFlagInt)
	export := &TrieExport{Name: symbol, Flags: flags}

	if flags.ReExport() {
		export.Other, err = ReadUleb128(r)
		if err != nil {
			return nil, fmt.Errorf("could not parse ULEB128 re-export dylib ordinal: %v", err)
		}
		var name []byte
		for {
			s, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("could not parse re-export import name: %w", err)
			}
			if s == '\x00' {
				break
			}
			name = append(name, s)
		}
		export.ReExport = string(name)
		return export, nil
	}

	export.Address, err = ReadUleb128(r)
	if err != nil {
		return nil, fmt.Errorf("could not parse ULEB128 symbol value: %v", err)
	}
	if flags.Regular() || flags.ThreadLocal() {
		export.Address += loadAddress
	}

	if flags.StubAndResolver() {
		export.Other, err = ReadUleb128(r)
		if err != nil {
			return nil, fmt.Errorf("could not parse ULEB128 resolver value: %v", err)
		}
		export.Other += loadAddress
	}

	return export, nil
}

func ParseTrieExports(r *bytes.Reader, loadAddress uint64) ([]TrieExport, error) {
	var exports []TrieExport

	nodes, err := ParseTrie(r)
	if err != nil {
		return nil, fmt.Errorf("could not parse trie: %v", err)
	}

	for _, node := range nodes {
		if _, err := r.Seek(int64(node.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("could not seek to trie node: %v", err)
		}
		export, err := ReadExport(r, string(node.Data), loadAddress)
		if err != nil {
			return nil, fmt.Errorf("could not read trie export metadata: %v", err)
		}
		exports = append(exports, *export)
	}

	return exports, nil
}

func ParseTrie(r *bytes.Reader) ([]Node, error) {
	data := make([]byte, 0, 32768)
	return parseTrie(r, 0, data, make(map[uint64]bool))
}

func parseTrie(r *bytes.Reader, pos uint64, cummulativeString []byte, ancestors map[uint64]bool) ([]Node, error) {

	var output []Node
	if pos >= uint64(r.Size()) {
		return nil, fmt.Errorf("trie node offset %#x exceeds size %#x", pos, r.Size())
	}
	if ancestors[pos] {
		return nil, fmt.Errorf("trie child offset %#x forms a cycle", pos)
	}
	ancestors[pos] = true
	defer delete(ancestors, pos)

	if _, err := r.Seek(int64(pos), io.SeekStart); err != nil {
		return nil, fmt.Errorf("could not seek to trie node %#x: %v", pos, err)
	}

	terminalSize, err := ReadUleb128(r)
	if err != nil {
		return nil, fmt.Errorf("could not parse ULEB128 terminalSize value: %v", err)
	}

	terminalOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("could not get terminal offset: %v", err)
	}
	if terminalSize > uint64(r.Size()-terminalOffset) {
		return nil, fmt.Errorf("terminal payload at %#x has size %#x beyond trie size %#x", terminalOffset, terminalSize, r.Size())
	}
	if terminalSize != 0 {
		output = append(output, Node{
			Offset: uint64(terminalOffset),
			Data:   append([]byte{}, cummulativeString...),
		})
	}

	childrenOffset := uint64(terminalOffset) + terminalSize
	if _, err := r.Seek(int64(childrenOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("could not seek to trie children at %#x: %v", childrenOffset, err)
	}

	childrenRemaining, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("could not read childrenRemaining value: %v", err)
	}

	for i := 0; i < int(childrenRemaining); i++ {
		tmp := make([]byte, 0, 100)
		for {
			s, err := r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("could not read child %d edge: %w", i, err)
			}
			if s == '\x00' {
				break
			}
			tmp = append(tmp, s)
		}

		childNodeOffset, err := ReadUleb128(r)
		if err != nil {
			return nil, fmt.Errorf("could not parse ULEB128 childNodeOffset value: %v", err)
		}

		curr, _ := r.Seek(0, io.SeekCurrent)

		nodes, err := parseTrie(r, childNodeOffset, append(cummulativeString, tmp...), ancestors)
		if err != nil {
			return nil, fmt.Errorf("could not parse trie (recursive call): %v", err)
		}

		r.Seek(curr, io.SeekStart) // reset the reader

		output = append(output, nodes...)
	}

	return output, nil
}

func WalkTrie(r *bytes.Reader, symbol string) (uint64, error) {

	var strIndex int
	var offset, nodeOffset uint64

	for {
		if offset >= uint64(r.Size()) {
			return 0, fmt.Errorf("trie node offset %#x exceeds size %#x", offset, r.Size())
		}
		if _, err := r.Seek(int64(offset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to trie node %#x: %v", offset, err)
		}

		terminalSize, err := ReadUleb128(r)
		if err != nil {
			return 0, fmt.Errorf("failed to read terminalSize value: %v", err)
		}
		terminalOffset, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, fmt.Errorf("failed to get terminal payload offset: %v", err)
		}
		if terminalSize > uint64(r.Size()-terminalOffset) {
			return 0, fmt.Errorf("terminal payload at %#x has size %#x beyond trie size %#x", terminalOffset, terminalSize, r.Size())
		}

		if int(strIndex) == len(symbol) && (terminalSize != 0) {
			return uint64(terminalOffset), nil
		}

		childrenOffset := uint64(terminalOffset) + terminalSize
		if _, err := r.Seek(int64(childrenOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to trie children at %#x: %v", childrenOffset, err)
		}

		childrenRemaining, err := r.ReadByte()
		if err == io.EOF {
			break
		}

		nodeOffset = 0

		for i := childrenRemaining; i > 0; i-- {
			searchStrIndex := strIndex
			wrongEdge := false

			for {
				c, err := r.ReadByte()
				if err == io.EOF {
					break
				}
				if err != nil {
					return 0, fmt.Errorf("could not read trie character: %v", err)
				}
				if c == '\x00' {
					break
				}
				if !wrongEdge {
					if searchStrIndex != len(symbol) && c != symbol[searchStrIndex] {
						wrongEdge = true
					}
					searchStrIndex++
					if searchStrIndex > len(symbol) {
						return offset, fmt.Errorf("symbol not in trie")
					}
				}
			}

			if wrongEdge { // advance to next child
				// skip over last byte of uleb128
				_, err = ReadUleb128(r)
				if err != nil {
					return 0, fmt.Errorf("failed to skip ULEB128 value: %v", err)
				}
			} else { // the symbol so far matches this edge (child)
				// so advance to the child's node
				nodeOffset, err = ReadUleb128(r)
				if err != nil {
					return 0, fmt.Errorf("failed to read ULEB128 nodeOffset value: %v", err)
				}

				strIndex = searchStrIndex
				break
			}
		}

		if nodeOffset != 0 {
			offset = nodeOffset
		} else {
			break
		}
	}

	return offset, fmt.Errorf("symbol not in trie")
}
