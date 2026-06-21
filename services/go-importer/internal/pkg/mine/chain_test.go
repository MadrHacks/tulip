package mine

import (
	"reflect"
	"testing"
)

func TestChainAnalyzerEmitsSettledChain(t *testing.T) {
	a := newChainAnalyzer(100, 8, 16)

	// flowA mints tokA; flowB reuses it -> a producer->consumer edge.
	a.Observe("flowA", 10, 8001, "cluster:svc:1", [][]byte{tokA}, nil)
	a.Observe("flowB", 20, 8002, "cluster:svc:2", nil, [][]byte{tokA})

	// Not settled yet: the newest member is within one window of the data clock.
	if got := a.Synthesize(); len(got) != 0 {
		t.Fatalf("expected no settled chain yet, got %d", len(got))
	}

	// Advance the data clock well past the window with an unrelated flow.
	a.Observe("flowC", 200, 8003, "cluster:svc:3", [][]byte{tokB}, nil)

	chains := a.Synthesize()
	if len(chains) != 1 {
		t.Fatalf("expected 1 settled chain, got %d", len(chains))
	}
	sc := chains[0]
	if !reflect.DeepEqual(sc.Members, []string{"flowA", "flowB"}) {
		t.Errorf("members = %v, want [flowA flowB]", sc.Members)
	}
	if len(sc.Template.Steps) != 2 {
		t.Errorf("steps = %d, want 2", len(sc.Template.Steps))
	}
	if len(sc.Template.Links) != 1 {
		t.Errorf("links = %d, want 1", len(sc.Template.Links))
	}
	if sc.Template.Steps[0].ClusterID != "cluster:svc:1" {
		t.Errorf("step 0 cluster = %q, want cluster:svc:1", sc.Template.Steps[0].ClusterID)
	}
	// Step metadata runs parallel to the template steps, in (T, Flow) order.
	if !reflect.DeepEqual(sc.StepFlows, []string{"flowA", "flowB"}) {
		t.Errorf("step flows = %v, want [flowA flowB]", sc.StepFlows)
	}
	if !reflect.DeepEqual(sc.StepPorts, []int{8001, 8002}) {
		t.Errorf("step ports = %v, want [8001 8002]", sc.StepPorts)
	}
	if len(sc.LinkValues) != 1 || !reflect.DeepEqual(sc.LinkValues[0], tokA) {
		t.Errorf("link values = %q, want [%q]", sc.LinkValues, tokA)
	}

	// The session is evicted on emit, so a second pass yields nothing.
	if got := a.Synthesize(); len(got) != 0 {
		t.Errorf("emitted chain should be evicted, got %d", len(got))
	}
}

func TestChainAnalyzerIgnoresTokenlessFlows(t *testing.T) {
	a := newChainAnalyzer(100, 8, 16)
	a.Observe("flowA", 10, 8001, "cluster:svc:1", nil, nil)
	if len(a.flowMeta) != 0 {
		t.Errorf("token-less flow should not be recorded, have %d", len(a.flowMeta))
	}
	if got := a.Synthesize(); len(got) != 0 {
		t.Errorf("expected no chains, got %d", len(got))
	}
}

func TestChainAnalyzerSingleFlowNoChain(t *testing.T) {
	a := newChainAnalyzer(100, 8, 16)
	// A lone producer with no consumer is not a chain.
	a.Observe("flowA", 10, 8001, "cluster:svc:1", [][]byte{tokA}, nil)
	a.Observe("flowC", 200, 8003, "cluster:svc:3", [][]byte{tokB}, nil)
	if got := a.Synthesize(); len(got) != 0 {
		t.Errorf("a single flow is not a chain, got %d", len(got))
	}
}
