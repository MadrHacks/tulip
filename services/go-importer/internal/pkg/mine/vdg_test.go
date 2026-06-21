package mine

import "testing"

var (
	tokA = []byte("0123456789abcdef0123456789abcdef")
	tokB = []byte("fedcba9876543210fedcba9876543210")
	tokC = []byte("a1b2c3d4e5f60718293a4b5c6d7e8f90")
)

func TestCrossFlowEdge(t *testing.T) {
	g := NewVDG(120, 8)
	if e := g.Observe("A", 1000, true, tokA); len(e) != 0 {
		t.Fatalf("producer should emit no edge, got %v", e)
	}
	e := g.Observe("B", 1010, false, tokA)
	if len(e) != 1 {
		t.Fatalf("want 1 edge, got %d: %v", len(e), e)
	}
	if e[0].Src != "A" || e[0].Dst != "B" || e[0].Vhash != hash64(tokA) {
		t.Fatalf("unexpected edge %+v", e[0])
	}
}

func TestLowEntropyNoEdge(t *testing.T) {
	g := NewVDG(120, 8)
	short := []byte("abc")
	g.Observe("A", 1000, true, short)
	if e := g.Observe("B", 1010, false, short); len(e) != 0 {
		t.Fatalf("low-entropy token must not emit edge, got %v", e)
	}
}

func TestProducerOutOfWindow(t *testing.T) {
	g := NewVDG(120, 8)
	g.Observe("A", 1000, true, tokA)
	if e := g.Observe("B", 1200, false, tokA); len(e) != 0 {
		t.Fatalf("producer out of window must not emit edge, got %v", e)
	}
}

func TestConstantExcludedByDFCap(t *testing.T) {
	g := NewVDG(120, 3)
	g.Observe("A", 1000, true, tokA)
	g.Observe("B", 1001, false, tokA)
	g.Observe("C", 1002, false, tokA)
	g.Observe("D", 1003, false, tokA)
	if e := g.Observe("E", 1004, false, tokA); len(e) != 0 {
		t.Fatalf("value over dfMax distinct flows must not emit edge, got %v", e)
	}
}

func TestSameFlowNoEdge(t *testing.T) {
	g := NewVDG(120, 8)
	g.Observe("A", 1000, true, tokB)
	if e := g.Observe("A", 1010, false, tokB); len(e) != 0 {
		t.Fatalf("same-flow produce+consume must not emit cross-flow edge, got %v", e)
	}
}

func TestNearestProducer(t *testing.T) {
	g := NewVDG(120, 8)
	g.Observe("A", 1000, true, tokC)
	g.Observe("B", 1005, true, tokC)
	e := g.Observe("D", 1010, false, tokC)
	if len(e) != 1 {
		t.Fatalf("want 1 edge, got %d: %v", len(e), e)
	}
	if e[0].Src != "B" {
		t.Fatalf("want nearest producer B, got %s", e[0].Src)
	}
}
