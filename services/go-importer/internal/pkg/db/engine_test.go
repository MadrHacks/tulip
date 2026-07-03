package db

import (
	"bytes"
	"testing"
)

func TestTopmostPrefersDeepestChain(t *testing.T) {
	chunks := []kindChunk{
		{"raw", []byte("RAW")},
		{"raw -> b64decode", []byte("DECODED")},
	}
	if got := topmost(chunks); !bytes.Equal(got, []byte("DECODED")) {
		t.Errorf("topmost = %q, want DECODED", got)
	}
}

func TestTopmostPrefersDecryptedRoot(t *testing.T) {
	// A decrypted root beats a deeper raw chain: b64decode of ciphertext is junk.
	chunks := []kindChunk{
		{"raw", []byte("CIPHER")},
		{"raw -> b64decode", []byte("junk")},
		{"decrypted", []byte("PLAINTEXT")},
	}
	if got := topmost(chunks); !bytes.Equal(got, []byte("PLAINTEXT")) {
		t.Errorf("topmost = %q, want PLAINTEXT", got)
	}
}

func TestTopmostDeepestDecryptedChain(t *testing.T) {
	chunks := []kindChunk{
		{"decrypted", []byte("A")},
		{"decrypted -> websockets", []byte("B")},
		{"decrypted -> websockets -> b64decode", []byte("C")},
	}
	if got := topmost(chunks); !bytes.Equal(got, []byte("C")) {
		t.Errorf("topmost = %q, want C", got)
	}
}

func TestTopmostConcatenatesInOrder(t *testing.T) {
	// All chunks of the chosen kind are concatenated in arrival order.
	chunks := []kindChunk{
		{"raw", []byte("x")},
		{"raw -> b64decode", []byte("one ")},
		{"raw", []byte("y")},
		{"raw -> b64decode", []byte("two")},
	}
	if got := topmost(chunks); !bytes.Equal(got, []byte("one two")) {
		t.Errorf("topmost = %q, want 'one two'", got)
	}
}

func TestTopmostRawOnly(t *testing.T) {
	chunks := []kindChunk{{"raw", []byte("hello")}}
	if got := topmost(chunks); !bytes.Equal(got, []byte("hello")) {
		t.Errorf("topmost = %q, want hello", got)
	}
	if got := topmost(nil); got != nil {
		t.Errorf("topmost(nil) = %q, want nil", got)
	}
}
