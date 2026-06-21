package mine

import (
	"regexp"
	"testing"
)

func TestSynthesizeExtractRecoversValue(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=DEADBEEFCAFE; Path=/\r\n\r\nok")
	value := []byte("DEADBEEFCAFE")

	pattern := synthesizeExtract(response, value)
	if pattern == "" {
		t.Fatal("expected a pattern")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("pattern does not compile: %q: %v", pattern, err)
	}
	m := re.FindSubmatch(response)
	if m == nil || string(m[1]) != "DEADBEEFCAFE" {
		t.Fatalf("pattern %q captured %q, want DEADBEEFCAFE", pattern, m)
	}
}

func TestSynthesizeExtractMissing(t *testing.T) {
	if got := synthesizeExtract([]byte("nothing here"), []byte("ABC123")); got != "" {
		t.Errorf("expected empty pattern for absent value, got %q", got)
	}
}

func TestSynthesizeExtractAnchorIsDiscriminating(t *testing.T) {
	// The anchor should pin the capture to the right field even when another
	// value of the same charclass appears earlier.
	response := []byte("nonce=AAAABBBBCCCC\r\ntoken=DEADBEEFCAFE\r\n")
	pattern := synthesizeExtract(response, []byte("DEADBEEFCAFE"))
	re := regexp.MustCompile(pattern)
	m := re.FindSubmatch(response)
	if m == nil || string(m[1]) != "DEADBEEFCAFE" {
		t.Fatalf("pattern %q captured %q, want DEADBEEFCAFE", pattern, m)
	}
}

func TestFindInjectSlot(t *testing.T) {
	// Template: "GET /act?t=" <var> " HTTP/1.1"
	segs := []Segment{
		{Const: []byte("GET /act?t=")},
		{Var: true},
		{Const: []byte(" HTTP/1.1")},
	}
	tmpl := &Template{Segments: segs}
	request := []byte("GET /act?t=ABCDEF012345 HTTP/1.1")

	if got := findInjectSlot(tmpl, request, []byte("ABCDEF012345")); got != 0 {
		t.Errorf("inject slot = %d, want 0", got)
	}
	if got := findInjectSlot(tmpl, request, []byte("nope")); got != -1 {
		t.Errorf("absent value should yield -1, got %d", got)
	}
}

func TestParseClusterTag(t *testing.T) {
	service, id, ok := parseClusterTag("cluster:CCalendar:7")
	if !ok || service != "CCalendar" || id != 7 {
		t.Fatalf("got (%q, %d, %v), want (CCalendar, 7, true)", service, id, ok)
	}
	if _, _, ok := parseClusterTag("role:checker"); ok {
		t.Error("non-cluster tag should not parse")
	}
	if _, _, ok := parseClusterTag("cluster:svc:notanint"); ok {
		t.Error("non-numeric id should not parse")
	}
}

func TestCharclassPattern(t *testing.T) {
	cases := map[string]string{
		"DEADBEEFCAFE":                         "[0-9a-fA-F]",
		"550e8400-e29b-41d4-a716-446655440000": "[0-9a-fA-F-]",
		"eyJhbGciOiJI.eyJzdWIiOiIxMjM0.dozjgN": "[A-Za-z0-9._-]",
	}
	for value, want := range cases {
		if got := charclassPattern([]byte(value)); got != want {
			t.Errorf("charclassPattern(%q) = %q, want %q", value, got, want)
		}
	}
}
