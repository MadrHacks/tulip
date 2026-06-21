package mine

import (
	"reflect"
	"testing"
)

func TestChainFormsOneSession(t *testing.T) {
	s := NewSessions(100)
	if !s.Apply(Edge{Src: "A", Dst: "B"}) {
		t.Fatal("A->B should link")
	}
	if !s.Apply(Edge{Src: "B", Dst: "C"}) {
		t.Fatal("B->C should link")
	}
	if s.Find("A") != s.Find("B") || s.Find("B") != s.Find("C") {
		t.Fatal("A, B, C should share a root")
	}
	if got := s.Members("A"); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("members = %v, want [A B C]", got)
	}
	if s.Size("A") != 3 {
		t.Fatalf("size = %d, want 3", s.Size("A"))
	}
}

func TestSeparateFlowIsOwnSession(t *testing.T) {
	s := NewSessions(100)
	s.Apply(Edge{Src: "A", Dst: "B"})
	if s.Find("D") != "D" {
		t.Fatalf("D root = %q, want D", s.Find("D"))
	}
	if got := s.Members("D"); !reflect.DeepEqual(got, []string{"D"}) {
		t.Fatalf("members = %v, want [D]", got)
	}
	if s.Find("D") == s.Find("A") {
		t.Fatal("D must not join A's session")
	}
}

func TestCapRefusesGiantComponent(t *testing.T) {
	s := NewSessions(2)
	if !s.Link("A", "B") {
		t.Fatal("A-B (size 2) should link under cap 2")
	}
	if s.Link("B", "C") {
		t.Fatal("B-C (would be size 3) should be refused under cap 2")
	}
	if s.Find("C") == s.Find("A") {
		t.Fatal("C must stay separate after refusal")
	}
	if s.Size("A") != 2 {
		t.Fatalf("A size = %d, want 2", s.Size("A"))
	}
	if s.Size("C") != 1 {
		t.Fatalf("C size = %d, want 1", s.Size("C"))
	}
	if got := s.Members("A"); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("members = %v, want [A B]", got)
	}
}

func TestLinkAlreadyConnectedIsNoOp(t *testing.T) {
	s := NewSessions(100)
	s.Link("A", "B")
	s.Link("B", "C")
	before := s.Members("A")
	if !s.Link("A", "C") {
		t.Fatal("linking already-connected nodes should return true")
	}
	if !s.Link("C", "A") {
		t.Fatal("linking already-connected nodes should return true")
	}
	if s.Size("A") != 3 {
		t.Fatalf("size changed to %d, want 3", s.Size("A"))
	}
	if got := s.Members("A"); !reflect.DeepEqual(got, before) {
		t.Fatalf("members changed: %v vs %v", got, before)
	}
}

func TestUnseenFlow(t *testing.T) {
	s := NewSessions(0)
	if s.Find("Z") != "Z" {
		t.Fatalf("unseen Find = %q, want Z", s.Find("Z"))
	}
	if s.Size("Z") != 1 {
		t.Fatalf("unseen Size = %d, want 1", s.Size("Z"))
	}
}

func TestUnboundedCap(t *testing.T) {
	s := NewSessions(0)
	prev := "n0"
	for i := 1; i < 50; i++ {
		next := "n" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		if !s.Link(prev, next) {
			t.Fatalf("link %s-%s refused under unbounded cap", prev, next)
		}
		prev = next
	}
	if s.Size("n0") != 50 {
		t.Fatalf("size = %d, want 50", s.Size("n0"))
	}
}

func TestMembersSorted(t *testing.T) {
	s := NewSessions(100)
	s.Link("C", "A")
	s.Link("A", "B")
	got := s.Members("B")
	if !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("members = %v, want sorted [A B C]", got)
	}
}
