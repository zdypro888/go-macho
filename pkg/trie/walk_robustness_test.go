package trie

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func walkWithTimeout(t *testing.T, data []byte, symbol string) (uint64, error) {
	t.Helper()
	type result struct {
		off uint64
		err error
	}
	done := make(chan result, 1)
	go func() {
		off, err := WalkTrie(bytes.NewReader(data), symbol)
		done <- result{off, err}
	}()
	select {
	case r := <-done:
		return r.off, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("WalkTrie did not terminate")
		return 0, nil
	}
}

func TestWalkTrieRejectsNonAdvancingCycles(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty edge to self", []byte{
			0x00, 0x01, 0x00, 0x04, // root: "" -> 4
			0x00, 0x01, 0x00, 0x04, // 4:    "" -> 4
		}},
		{"empty edge two node loop", []byte{
			0x00, 0x01, 0x00, 0x04, // root: "" -> 4
			0x00, 0x01, 0x00, 0x08, // 4:    "" -> 8
			0x00, 0x01, 0x00, 0x04, // 8:    "" -> 4
		}},
		{"loop entered after a matched prefix", []byte{
			0x00, 0x01, '_', 0x00, 0x05, // root: "_" -> 5
			0x00, 0x01, 0x00, 0x09, //      5:    ""  -> 9
			0x00, 0x01, 0x00, 0x05, //      9:    ""  -> 5
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := walkWithTimeout(t, tt.data, "_main")
			if err == nil {
				t.Fatal("cyclic trie was accepted")
			}
		})
	}
}

// A valid trie may share nodes between edges (a DAG) and may contain
// empty-label forward edges; neither may be mistaken for a cycle.
func TestWalkTrieValidSharedAndEmptyEdges(t *testing.T) {
	data := []byte{
		// 0: root, no terminal, 3 children
		0x00, 0x03,
		'_', 'a', 0x00, 0x10, // "_a" -> 0x10
		'_', 'b', 0x00, 0x10, // "_b" -> 0x10 (shared node)
		0x00, 0x14, //           ""   -> 0x14 (never reached: "_a"/"_b" are tried first for those symbols)
		0x00, 0x00, 0x00, 0x00,
		// 0x10: terminal of size 2, no children
		0x02, 0x00, 0x08, 0x00,
		// 0x14: no terminal, 1 child "" -> 0x18
		0x00, 0x01, 0x00, 0x18,
		// 0x18: no terminal, 1 child "_c" -> 0x1e
		0x00, 0x01, '_', 'c', 0x00, 0x1e,
		// 0x1e: terminal of size 1
		0x01, 0x00, 0x00,
	}
	tests := []struct {
		symbol  string
		want    uint64
		wantErr string
	}{
		{"_a", 0x11, ""},
		{"_b", 0x11, ""},
		{"_c", 0x1f, ""},
		{"_d", 0, "symbol not in trie"},
		{"_ab", 0, "symbol not in trie"},
	}
	for _, tt := range tests {
		t.Run(tt.symbol, func(t *testing.T) {
			got, err := walkWithTimeout(t, data, tt.symbol)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("WalkTrie(%q): %v", tt.symbol, err)
			}
			if got != tt.want {
				t.Fatalf("WalkTrie(%q) = %#x, want %#x", tt.symbol, got, tt.want)
			}
		})
	}
}
