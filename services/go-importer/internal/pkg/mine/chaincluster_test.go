package mine

import "testing"

func TestChainClusterStore(t *testing.T) {
	cs := newChainClusterStore()

	id1, new1 := cs.Assign("login>exploit|0-1")
	if !new1 {
		t.Fatal("first signature should be new")
	}
	id2, new2 := cs.Assign("login>exploit|0-1")
	if new2 || id2 != id1 {
		t.Fatalf("same signature should reuse id: (%d,%v) vs %d", id2, new2, id1)
	}
	id3, new3 := cs.Assign("register>login>exploit|0-1,1-2")
	if !new3 || id3 == id1 {
		t.Fatalf("different signature should get a fresh id: (%d,%v)", id3, new3)
	}
}
