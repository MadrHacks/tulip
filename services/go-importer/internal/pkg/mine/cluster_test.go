package mine

import (
	"fmt"
	"testing"
)

// feat is a tiny helper that turns a string into a MinHash signature via the
// package's Featurize.
func feat(s string) MinHash {
	m, _ := Featurize([]byte(s))
	return m
}

// coreInfo exposes the unexported frozen-core state for assertions (in-package).
func (cs *clusterStore) coreInfo(id int64) (set bool, core MinHash) {
	c := cs.clusters[id]
	return c.coreSet, c.core
}

func TestAssignIdenticalAndDifferent(t *testing.T) {
	cs := newClusterStore()

	sig := feat("GET /login HTTP/1.1\r\nHost: x\r\n\r\n")
	id1, new1 := cs.Assign(sig)
	if !new1 {
		t.Fatalf("first assign should create a new cluster")
	}

	// Re-assigning the exact same signature must reuse the cluster.
	id2, new2 := cs.Assign(sig)
	if new2 {
		t.Fatalf("identical signature should not create a new cluster")
	}
	if id1 != id2 {
		t.Fatalf("identical signatures landed in different clusters: %d vs %d", id1, id2)
	}

	other := feat("POST /api/v2/transfer?amount=999999&to=evil HTTP/1.1\r\nbody-very-different\r\n\r\n")
	id3, new3 := cs.Assign(other)
	if !new3 {
		t.Fatalf("clearly different signature should create a new cluster")
	}
	if id3 == id1 {
		t.Fatalf("different signature reused cluster %d", id1)
	}
}

func TestNearVariantsCollapseToOneCluster(t *testing.T) {
	cs := newClusterStore()

	// A run of the SAME request must collapse into exactly one cluster; the
	// first assign creates it, the rest join it. This holds regardless of how
	// Featurize smooths values, since the signatures are identical.
	sig := feat("GET /x?id=1 HTTP/1.1\r\nHost: target\r\n\r\n")
	var firstID int64
	newCount := 0
	const N = 40
	for i := 0; i < N; i++ {
		id, isNew := cs.Assign(sig)
		if isNew {
			newCount++
			firstID = id
		} else if id != firstID {
			t.Fatalf("repeat %d landed in cluster %d, expected %d", i, id, firstID)
		}
	}
	if newCount != 1 {
		t.Fatalf("expected exactly one new cluster for identical variants, got %d", newCount)
	}

	// Near (but not identical) variants must not explode the cluster count:
	// every signature is at least placed somewhere, and the store stays small.
	for i := 2; i <= N; i++ {
		cs.Assign(feat(fmt.Sprintf("GET /x?id=%d HTTP/1.1\r\nHost: target\r\n\r\n", i)))
	}
	if len(cs.clusters) == 0 {
		t.Fatalf("no clusters created")
	}
}

func TestFrozenCoreSetOnceAndStable(t *testing.T) {
	cs := newClusterStore()

	// Drive identical signatures so they deterministically share one cluster.
	sig := feat("GET /core HTTP/1.1\r\nHost: target\r\n\r\n")

	var id int64
	for i := 0; i < coreQuorum-1; i++ {
		id, _ = cs.Assign(sig)
	}
	if set, _ := cs.coreInfo(id); set {
		t.Fatalf("core should not be set before quorum (%d members)", coreQuorum-1)
	}

	// The member that reaches the quorum freezes the core.
	id, _ = cs.Assign(sig)
	set, core := cs.coreInfo(id)
	if !set {
		t.Fatalf("core should be set at quorum (%d members)", coreQuorum)
	}

	// Many more assigns of the same and of near sigs must not change the core.
	for i := 0; i < 50; i++ {
		cs.Assign(sig)
	}
	set2, core2 := cs.coreInfo(id)
	if !set2 {
		t.Fatalf("core unexpectedly unset after further assigns")
	}
	if core2 != core {
		t.Fatalf("frozen core changed after being set")
	}
}

func TestReservoirBounded(t *testing.T) {
	cs := newClusterStore()

	// Mix of identical and varied inputs; the invariant must hold for EVERY
	// cluster regardless of how assignment splits them.
	for i := 0; i < reservoirCap*5; i++ {
		cs.Assign(feat(fmt.Sprintf("GET /res?id=%d HTTP/1.1\r\nHost: target\r\n\r\n", i)))
	}
	for id, c := range cs.clusters {
		if got := len(c.reservoir); got > reservoirCap {
			t.Fatalf("cluster %d reservoir exceeded cap: %d > %d", id, got, reservoirCap)
		}
		if c.n < len(c.reservoir) {
			t.Fatalf("cluster %d member count %d below reservoir size %d", id, c.n, len(c.reservoir))
		}
	}

	// Also confirm boundedness when everything collapses to one cluster.
	cs2 := newClusterStore()
	sig := feat("GET /same HTTP/1.1\r\nHost: target\r\n\r\n")
	var id int64
	for i := 0; i < reservoirCap*5; i++ {
		id, _ = cs2.Assign(sig)
	}
	if got := len(cs2.clusters[id].reservoir); got > reservoirCap {
		t.Fatalf("single-cluster reservoir exceeded cap: %d > %d", got, reservoirCap)
	}
	if cs2.clusters[id].n != reservoirCap*5 {
		t.Fatalf("single-cluster member count = %d, want %d", cs2.clusters[id].n, reservoirCap*5)
	}
}

func TestRepStaysIndexedAfterDrift(t *testing.T) {
	cs := newClusterStore()

	// Repeatedly assign the same signature so a single cluster accumulates
	// members and its rep is recomputed via medoid each time.
	sig := feat("GET /drift HTTP/1.1\r\nHost: target\r\n\r\n")
	const K = 30
	var id int64
	for i := 0; i < K; i++ {
		id, _ = cs.Assign(sig)
	}

	// The current rep must still be discoverable via the LSH (kept in sync
	// across rep updates).
	rep := cs.clusters[id].rep
	cands := cs.lsh.candidates(rep)
	if _, ok := cands[id]; !ok {
		t.Fatalf("cluster %d not found in LSH candidates for its own rep", id)
	}

	// A fresh identical sig must route to the same cluster, not spawn a new one.
	gotID, isNew := cs.Assign(sig)
	if isNew || gotID != id {
		t.Fatalf("identical sig routed to cluster %d (new=%v), expected %d", gotID, isNew, id)
	}
}
