package mine

import (
	"bytes"
	"testing"
)

// constBytes concatenates the Const segments in order.
func constBytes(segs []Segment) []byte {
	var b []byte
	for _, s := range segs {
		if !s.Var {
			b = append(b, s.Const...)
		}
	}
	return b
}

func countVar(segs []Segment) int {
	n := 0
	for _, s := range segs {
		if s.Var {
			n++
		}
	}
	return n
}

// assertNoAdjacentVar checks the alternation invariant.
func assertNoAdjacentVar(t *testing.T, segs []Segment) {
	t.Helper()
	for i := 1; i < len(segs); i++ {
		if segs[i].Var && segs[i-1].Var {
			t.Fatalf("two adjacent Var segments at %d: %#v", i, segs)
		}
	}
	for _, s := range segs {
		if s.Var && len(s.Const) != 0 {
			t.Fatalf("Var segment with non-empty Const: %#v", s)
		}
		if !s.Var && len(s.Const) == 0 {
			t.Fatalf("Const segment with empty bytes: %#v", s)
		}
	}
}

func TestAlignIdentical(t *testing.T) {
	in := []byte("GET /note/1 HTTP/1.1\r\nHost: x\r\n\r\n")
	segs := Align([][]byte{in, append([]byte(nil), in...), append([]byte(nil), in...)})
	assertNoAdjacentVar(t, segs)
	if countVar(segs) != 0 {
		t.Fatalf("expected 0 Var, got %d: %#v", countVar(segs), segs)
	}
	if len(segs) != 1 {
		t.Fatalf("expected exactly 1 segment, got %d: %#v", len(segs), segs)
	}
	if !bytes.Equal(segs[0].Const, in) {
		t.Fatalf("const mismatch:\n got %q\nwant %q", segs[0].Const, in)
	}
}

func TestAlignSingleMember(t *testing.T) {
	in := []byte("hello world")
	segs := Align([][]byte{in})
	assertNoAdjacentVar(t, segs)
	if countVar(segs) != 0 {
		t.Fatalf("expected 0 Var, got %d", countVar(segs))
	}
	if len(segs) != 1 || !bytes.Equal(segs[0].Const, in) {
		t.Fatalf("expected one const equal to input, got %#v", segs)
	}
}

func TestAlignOneURLField(t *testing.T) {
	members := [][]byte{
		[]byte("GET /note/1 HTTP"),
		[]byte("GET /note/2 HTTP"),
		[]byte("GET /note/3 HTTP"),
	}
	segs := Align(members)
	assertNoAdjacentVar(t, segs)

	if countVar(segs) != 1 {
		t.Fatalf("expected exactly 1 Var, got %d: %#v", countVar(segs), segs)
	}

	// The constant material must contain the shared prefix and suffix in order.
	cb := constBytes(segs)
	if !bytes.Contains(cb, []byte("GET /note/")) {
		t.Fatalf("missing constant prefix in %q", cb)
	}
	if !bytes.Contains(cb, []byte(" HTTP")) {
		t.Fatalf("missing constant suffix in %q", cb)
	}
	// Var must sit between the two constant runs.
	if segs[0].Var || segs[len(segs)-1].Var {
		t.Fatalf("expected const at both ends: %#v", segs)
	}
}

func TestAlignTwoVarSlots(t *testing.T) {
	members := [][]byte{
		[]byte("id=1 name=alice end"),
		[]byte("id=2 name=bob end"),
		[]byte("id=3 name=carol end"),
	}
	segs := Align(members)
	assertNoAdjacentVar(t, segs)

	if countVar(segs) != 2 {
		t.Fatalf("expected exactly 2 Var, got %d: %#v", countVar(segs), segs)
	}

	// There must be at least one Const between the two Var slots.
	firstVar, secondVar := -1, -1
	for i, s := range segs {
		if s.Var {
			if firstVar == -1 {
				firstVar = i
			} else {
				secondVar = i
			}
		}
	}
	if firstVar == -1 || secondVar == -1 || secondVar-firstVar < 2 {
		t.Fatalf("expected a Const between the two Var slots: %#v", segs)
	}

	cb := constBytes(segs)
	for _, want := range []string{"id=", "name=", "end"} {
		if !bytes.Contains(cb, []byte(want)) {
			t.Fatalf("missing constant %q in %q", want, cb)
		}
	}
}

func TestAlignInteriorExtraToken(t *testing.T) {
	// Variation only visible in a non-base member: member 1 has an extra token
	// between two tokens that are adjacent in member 0.
	members := [][]byte{
		[]byte("A B"),
		[]byte("A X B"),
		[]byte("A Y B"),
	}
	segs := Align(members)
	assertNoAdjacentVar(t, segs)
	if countVar(segs) != 1 {
		t.Fatalf("expected exactly 1 Var, got %d: %#v", countVar(segs), segs)
	}
	cb := constBytes(segs)
	if !bytes.Contains(cb, []byte("A")) || !bytes.Contains(cb, []byte("B")) {
		t.Fatalf("missing constants in %q", cb)
	}
}

func TestAlignEmpty(t *testing.T) {
	if segs := Align(nil); segs != nil {
		t.Fatalf("expected nil for no members, got %#v", segs)
	}
	if segs := Align([][]byte{{}}); segs != nil {
		t.Fatalf("expected nil for single empty member, got %#v", segs)
	}
}
