package mine

import (
	"encoding/json"
	"reflect"
	"testing"
)

func threeFlowSession() ([]SessionFlow, []Edge) {
	flows := []SessionFlow{
		{Flow: "f-login", ClusterID: "c-login", T: 100},
		{Flow: "f-token", ClusterID: "c-token", T: 200},
		{Flow: "f-use", ClusterID: "c-use", T: 300},
	}
	edges := []Edge{
		{Src: "f-login", Dst: "f-token", Vhash: 0xAA},
		{Src: "f-token", Dst: "f-use", Vhash: 0xBB},
	}
	return flows, edges
}

func TestBuildChainTemplateThreeFlow(t *testing.T) {
	flows, edges := threeFlowSession()
	got := BuildChainTemplate(flows, edges)

	wantSteps := []ChainStep{
		{ClusterID: "c-login"},
		{ClusterID: "c-token"},
		{ClusterID: "c-use"},
	}
	if !reflect.DeepEqual(got.Steps, wantSteps) {
		t.Fatalf("steps = %#v, want %#v", got.Steps, wantSteps)
	}

	wantLinks := []LinkVar{
		{Kind: "extracted", ProducerStep: 0, ConsumerStep: 1, Vhash: 0xAA},
		{Kind: "extracted", ProducerStep: 1, ConsumerStep: 2, Vhash: 0xBB},
	}
	if !reflect.DeepEqual(got.Links, wantLinks) {
		t.Fatalf("links = %#v, want %#v", got.Links, wantLinks)
	}
}

func TestBuildChainTemplateInputOrderIndependence(t *testing.T) {
	flows, edges := threeFlowSession()
	want := BuildChainTemplate(flows, edges)

	shuffledFlows := []SessionFlow{flows[2], flows[0], flows[1]}
	shuffledEdges := []Edge{edges[1], edges[0]}
	got := BuildChainTemplate(shuffledFlows, shuffledEdges)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order-dependent: got %#v, want %#v", got, want)
	}
}

func TestBuildChainTemplateIgnoresOutsideEdges(t *testing.T) {
	flows, edges := threeFlowSession()
	edges = append(edges,
		Edge{Src: "f-login", Dst: "f-outside", Vhash: 0xCC},
		Edge{Src: "f-outside", Dst: "f-use", Vhash: 0xDD},
		Edge{Src: "f-x", Dst: "f-y", Vhash: 0xEE},
	)
	got := BuildChainTemplate(flows, edges)

	if len(got.Links) != 2 {
		t.Fatalf("expected 2 links after ignoring outside edges, got %d: %#v", len(got.Links), got.Links)
	}
}

func TestBuildChainTemplateDoesNotMutate(t *testing.T) {
	flows, edges := threeFlowSession()
	flowsCopy := append([]SessionFlow(nil), flows...)
	edgesCopy := append([]Edge(nil), edges...)

	_ = BuildChainTemplate(flows, edges)

	if !reflect.DeepEqual(flows, flowsCopy) {
		t.Fatalf("flows mutated: %#v vs %#v", flows, flowsCopy)
	}
	if !reflect.DeepEqual(edges, edgesCopy) {
		t.Fatalf("edges mutated: %#v vs %#v", edges, edgesCopy)
	}
}

func TestChainTemplateJSONRoundTrip(t *testing.T) {
	flows, edges := threeFlowSession()
	tmpl := BuildChainTemplate(flows, edges)

	data, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ChainTemplate
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, tmpl) {
		t.Fatalf("round-trip mismatch: got %#v, want %#v", back, tmpl)
	}
}

func TestBuildChainTemplateSingleFlow(t *testing.T) {
	flows := []SessionFlow{{Flow: "f-only", ClusterID: "c-only", T: 42}}
	got := BuildChainTemplate(flows, nil)

	if len(got.Steps) != 1 || got.Steps[0].ClusterID != "c-only" {
		t.Fatalf("expected 1 step c-only, got %#v", got.Steps)
	}
	if len(got.Links) != 0 {
		t.Fatalf("expected 0 links, got %#v", got.Links)
	}
}
