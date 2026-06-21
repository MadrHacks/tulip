package mine

import (
	"bytes"
	"testing"
)

const (
	testUUID = "550e8400-e29b-41d4-a716-446655440000"
	testJWT  = "eyJhbGciOiJI.eyJzdWIiOiIxMjM0.dozjgNryP4J3jV"
	testHex  = "0123456789abcdef0123456789abcdef"
)

func has(toks [][]byte, want string) bool {
	for _, t := range toks {
		if bytes.Equal(t, []byte(want)) {
			return true
		}
	}
	return false
}

func TestExtractTokensSplitsOnPunctuation(t *testing.T) {
	data := []byte("user=" + testUUID + "; auth=" + testJWT)
	toks := ExtractTokens(data)
	if !has(toks, testUUID) {
		t.Errorf("expected uuid extracted, got %q", toks)
	}
	if !has(toks, testJWT) {
		t.Errorf("expected jwt extracted, got %q", toks)
	}
	if has(toks, "user") || has(toks, "auth") {
		t.Errorf("low-entropy keys should not be tokens: %q", toks)
	}
}

func TestExtractTokensIgnoresPathAndVersion(t *testing.T) {
	toks := ExtractTokens([]byte("GET /api/v1/health HTTP/1.1 from 10.254.1.36"))
	if len(toks) != 0 {
		t.Errorf("expected no tokens in structural noise, got %q", toks)
	}
}

func TestExtractTokensStripsPadding(t *testing.T) {
	// The same value with and without base64 '=' padding extracts identically,
	// so a producer and consumer that differ only in padding still match.
	padded := ExtractTokens([]byte("t=" + testHex + "=="))
	bare := ExtractTokens([]byte("t=" + testHex))
	if len(padded) != 1 || len(bare) != 1 || !bytes.Equal(padded[0], bare[0]) {
		t.Errorf("padding should not change the token: %q vs %q", padded, bare)
	}
}

func TestExtractTokensTrimsTrailingDot(t *testing.T) {
	toks := ExtractTokens([]byte("token is " + testHex + "."))
	if !has(toks, testHex) {
		t.Errorf("trailing sentence dot should be trimmed, got %q", toks)
	}
}

func TestExtractTokensDedups(t *testing.T) {
	toks := ExtractTokens([]byte(testUUID + " " + testUUID + " " + testUUID))
	if len(toks) != 1 {
		t.Errorf("expected 1 distinct token, got %d: %q", len(toks), toks)
	}
}

func TestExtractTokensDoesNotAliasInput(t *testing.T) {
	data := []byte("v=" + testHex)
	toks := ExtractTokens(data)
	if len(toks) != 1 {
		t.Fatalf("expected 1 token, got %q", toks)
	}
	for i := range data {
		data[i] = 'X'
	}
	if !bytes.Equal(toks[0], []byte(testHex)) {
		t.Errorf("token aliases input buffer: %q", toks[0])
	}
}
