package mine

import "testing"

func TestSessionSignatureOrderIndependent(t *testing.T) {
	flowsA := []SessionFlow{
		{Flow: "a1", ClusterID: "cluster:svc:7", T: 100},
		{Flow: "a2", ClusterID: "cluster:svc:8", T: 200},
		{Flow: "a3", ClusterID: "cluster:svc:9", T: 300},
	}
	edgesA := []Edge{
		{Src: "a1", Dst: "a2", Vhash: 1},
		{Src: "a2", Dst: "a3", Vhash: 2},
	}

	// Same shape, different input order, different flow ids/times.
	flowsB := []SessionFlow{
		{Flow: "b3", ClusterID: "cluster:svc:9", T: 999},
		{Flow: "b1", ClusterID: "cluster:svc:7", T: 111},
		{Flow: "b2", ClusterID: "cluster:svc:8", T: 555},
	}
	edgesB := []Edge{
		{Src: "b2", Dst: "b3", Vhash: 2},
		{Src: "b1", Dst: "b2", Vhash: 1},
	}

	sigA := SessionSignature(flowsA, edgesA)
	sigB := SessionSignature(flowsB, edgesB)
	if sigA != sigB {
		t.Fatalf("expected equal signatures, got %q vs %q", sigA, sigB)
	}
}

func TestSessionSignatureDifferentSequence(t *testing.T) {
	flowsA := []SessionFlow{
		{Flow: "a1", ClusterID: "cluster:svc:7", T: 1},
		{Flow: "a2", ClusterID: "cluster:svc:8", T: 2},
	}
	flowsB := []SessionFlow{
		{Flow: "b1", ClusterID: "cluster:svc:7", T: 1},
		{Flow: "b2", ClusterID: "cluster:svc:99", T: 2},
	}
	if SessionSignature(flowsA, nil) == SessionSignature(flowsB, nil) {
		t.Fatal("different cluster sequences must differ")
	}
}

func TestSessionSignatureEdgeDirection(t *testing.T) {
	flows := []SessionFlow{
		{Flow: "f0", ClusterID: "cluster:svc:1", T: 10},
		{Flow: "f1", ClusterID: "cluster:svc:2", T: 20},
	}
	sigFwd := SessionSignature(flows, []Edge{{Src: "f0", Dst: "f1"}})
	sigRev := SessionSignature(flows, []Edge{{Src: "f1", Dst: "f0"}})
	if sigFwd == sigRev {
		t.Fatalf("edge direction must matter: %q == %q", sigFwd, sigRev)
	}
}

func TestSessionSignatureIgnoresOutsideEdges(t *testing.T) {
	flows := []SessionFlow{
		{Flow: "f0", ClusterID: "cluster:svc:1", T: 10},
		{Flow: "f1", ClusterID: "cluster:svc:2", T: 20},
	}
	withInside := SessionSignature(flows, []Edge{{Src: "f0", Dst: "f1"}})
	withOutside := SessionSignature(flows, []Edge{
		{Src: "f0", Dst: "f1"},
		{Src: "f1", Dst: "outsider"},
		{Src: "ghost", Dst: "f0"},
		{Src: "x", Dst: "y"},
	})
	if withInside != withOutside {
		t.Fatalf("edges referencing outside flows must be ignored: %q vs %q", withInside, withOutside)
	}
}

func TestSessionSignatureSingleFlowEmptyTopology(t *testing.T) {
	flows := []SessionFlow{
		{Flow: "only", ClusterID: "cluster:svc:5", T: 42},
	}
	got := SessionSignature(flows, []Edge{{Src: "only", Dst: "outside"}})
	want := "cluster:svc:5|"
	if got != want {
		t.Fatalf("single-flow session: got %q, want %q", got, want)
	}
}
