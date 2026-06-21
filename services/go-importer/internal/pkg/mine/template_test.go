package mine

import (
	"bytes"
	"regexp"
	"testing"
)

func TestExtractSlotValues(t *testing.T) {
	segs := []Segment{
		{Const: []byte("GET /note/")},
		{Var: true},
		{Const: []byte(" HTTP")},
	}
	got := extractSlotValues([]byte("GET /note/42 HTTP"), segs)
	if len(got) != 1 || !bytes.Equal(got[0], []byte("42")) {
		t.Fatalf("got %q, want [42]", got)
	}

	// leading + trailing variable slots
	segs2 := []Segment{{Var: true}, {Const: []byte("|mid|")}, {Var: true}}
	got2 := extractSlotValues([]byte("left|mid|right"), segs2)
	if len(got2) != 2 || !bytes.Equal(got2[0], []byte("left")) || !bytes.Equal(got2[1], []byte("right")) {
		t.Fatalf("got %q, want [left right]", got2)
	}

	// missing anchor
	if extractSlotValues([]byte("no anchor here"), segs) != nil {
		t.Fatal("expected nil when an anchor is missing")
	}
}

func TestClassifySlot(t *testing.T) {
	flagRe := regexp.MustCompile(`[A-Z0-9]{31}=`)
	flagIDs := map[string]bool{"deadbeefcafe1234": true, "feedface00112233": true}

	cases := []struct {
		name   string
		values []string
		want   SlotType
	}{
		{"identical", []string{"x", "x"}, SlotConst},
		{"flags", []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345=", "ZYXWVUTSRQPONMLKJIHGFEDCBA543210="}, SlotFlag},
		{"flagids", []string{"deadbeefcafe1234", "feedface00112233"}, SlotFlagID},
		{"random hex", []string{"a1b2c3d4e5f60718", "0f1e2d3c4b5a6978"}, SlotRandom},
		{"small ints", []string{"1", "2", "3"}, SlotUnknown},
	}
	for _, c := range cases {
		vals := make([][]byte, len(c.values))
		for i, v := range c.values {
			vals[i] = []byte(v)
		}
		if got := classifySlot(vals, flagRe, flagIDs); got != c.want {
			t.Errorf("%s: classifySlot = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSynthesize(t *testing.T) {
	flagRe := regexp.MustCompile(`[A-Z0-9]{31}=`)
	members := [][]byte{
		[]byte("GET /note/1 HTTP"),
		[]byte("GET /note/2 HTTP"),
		[]byte("GET /note/3 HTTP"),
	}
	tpl := synthesize(members, flagRe, map[string]bool{})
	if tpl == nil {
		t.Fatal("synthesize returned nil")
	}
	if countVarSegments(tpl.Segments) != len(tpl.Slots) {
		t.Fatalf("slots %d != var segments %d", len(tpl.Slots), countVarSegments(tpl.Segments))
	}
	if len(tpl.Slots) != 1 {
		t.Fatalf("expected 1 slot, got %d", len(tpl.Slots))
	}
	if tpl.Slots[0].Type != SlotUnknown {
		t.Errorf("slot = %v, want unknown (small ints)", tpl.Slots[0].Type)
	}
}

func TestSynthesizeTooFew(t *testing.T) {
	if synthesize([][]byte{[]byte("a"), []byte("b")}, nil, nil) != nil {
		t.Error("expected nil below quorum")
	}
}
