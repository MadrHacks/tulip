package mine

import (
	"bytes"
	"regexp"
	"testing"
)

func TestNormalizeCollapsesAttackVariants(t *testing.T) {
	flagRe := regexp.MustCompile(`[A-Z0-9]{31}=`)
	flagIDs := []string{"deadbeefcafe1234"}
	a := []byte("GET /api/note/42?token=deadbeefcafe1234 HTTP/1.1\r\nHost: a\r\nDate: Mon\r\nX-Exploit: 1\r\n\r\n")
	b := []byte("GET /api/note/99?token=deadbeefcafe1234 HTTP/1.1\r\nHost: b\r\nDate: Tue\r\nX-Exploit: 1\r\n\r\n")
	ca := Normalize(a, flagRe, buildFlagIDRegex(flagIDs))
	cb := Normalize(b, flagRe, buildFlagIDRegex(flagIDs))
	if !bytes.Equal(ca, cb) {
		t.Errorf("variants should canon-equal:\n a=%q\n b=%q", ca, cb)
	}
	if bytes.Contains(ca, []byte("deadbeefcafe1234")) {
		t.Error("flagId not masked")
	}
	if bytes.Contains(ca, []byte("42")) || bytes.Contains(ca, []byte("99")) {
		t.Error("numeric path segment not templated")
	}
	if bytes.Contains(ca, []byte("Date")) {
		t.Error("volatile header not dropped")
	}
}

func TestNormalizeMasksFlag(t *testing.T) {
	flagRe := regexp.MustCompile(`[A-Z0-9]{31}=`)
	in := []byte("POST /submit HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 32\r\n\r\nABCDEFGHIJKLMNOPQRSTUVWXYZ012345=")
	out := Normalize(in, flagRe, nil)
	if bytes.Contains(out, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345=")) {
		t.Errorf("flag not masked: %q", out)
	}
}

func TestNormalizeNonHTTPPassthrough(t *testing.T) {
	in := []byte{0x00, 0x01, 'h', 'e', 'l', 'l', 'o', 0xff}
	if out := Normalize(in, nil, nil); !bytes.Equal(out, in) {
		t.Errorf("non-HTTP should pass through, got %q", out)
	}
}

func TestPathTemplate(t *testing.T) {
	cases := map[string]string{
		"/api/note/42":        "/api/note/{}",
		"/users/deadbeefcafe": "/users/{}",
		"/static/app.js":      "/static/app.js",
		"/":                   "/",
	}
	for in, want := range cases {
		if got := pathTemplate(in); got != want {
			t.Errorf("pathTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}
