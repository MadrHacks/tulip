package mine

import "sort"

// timedEdge is a dataflow edge tagged with when it was observed, so the chain
// analyzer can age edges out of its window.
type timedEdge struct {
	edge Edge
	t    int64
}

// settledChain is an emitted multi-step exploit chain: a settled session of
// flows linked by value reuse, ready to persist and tag. StepFlows and StepPorts
// run parallel to Template.Steps; LinkValues runs parallel to Template.Links and
// holds each link's observed value bytes, the instance data a lowering stage
// needs to synthesize extract/inject locators (kept out of the reusable
// Template).
type settledChain struct {
	ID         int64
	Signature  string
	Members    []string
	Template   ChainTemplate
	StepFlows  []string
	StepPorts  []int
	LinkValues [][]byte
}

// chainAnalyzer induces multi-step exploit sessions from cross-flow value reuse.
// Producers (server responses) and consumers (client requests) feed a value-
// dataflow graph; the resulting edges buffer for one window, and a connected
// component is emitted as a chain template once it has settled — once no future
// flow can extend it (its newest flow is older than one window on the data
// clock). Emitted and aged-out flows are evicted, bounding memory to recent
// token-bearing traffic.
type chainAnalyzer struct {
	vdg      *VDG
	clusters *chainClusterStore
	window   int64
	maxSize  int

	flowMeta map[string]SessionFlow
	flowPort map[string]int
	edges    []timedEdge
	maxT     int64
}

func newChainAnalyzer(windowSec int64, dfMax, maxSize int) *chainAnalyzer {
	return &chainAnalyzer{
		vdg:      NewVDG(windowSec, dfMax),
		clusters: newChainClusterStore(),
		window:   windowSec,
		maxSize:  maxSize,
		flowMeta: map[string]SessionFlow{},
		flowPort: map[string]int{},
	}
}

// Observe feeds one flow's produced (server->client) and consumed (client->
// server) high-entropy tokens into the value graph and records the flow's
// single-flow cluster identity and service port. Flows carrying no tokens are
// ignored.
func (a *chainAnalyzer) Observe(flow string, t int64, port int, clusterID string, produced, consumed [][]byte) {
	if len(produced) == 0 && len(consumed) == 0 {
		return
	}
	if t > a.maxT {
		a.maxT = t
	}
	a.flowMeta[flow] = SessionFlow{Flow: flow, ClusterID: clusterID, T: t}
	a.flowPort[flow] = port
	for _, v := range produced {
		a.vdg.Observe(flow, t, true, v)
	}
	for _, v := range consumed {
		for _, e := range a.vdg.Observe(flow, t, false, v) {
			a.edges = append(a.edges, timedEdge{edge: e, t: t})
		}
	}
}

// Synthesize emits every settled session, evicting it, and ages out stale
// state. The data clock is the newest token-bearing flow observed.
func (a *chainAnalyzer) Synthesize() []settledChain {
	a.evictBefore(a.maxT - 2*a.window)
	a.vdg.Sweep(a.maxT)

	s := NewSessions(a.maxSize)
	for _, te := range a.edges {
		s.Apply(te.edge)
	}

	groups := map[string][]string{}
	placed := map[string]bool{}
	for _, te := range a.edges {
		for _, f := range [2]string{te.edge.Src, te.edge.Dst} {
			if placed[f] {
				continue
			}
			placed[f] = true
			groups[s.Find(f)] = append(groups[s.Find(f)], f)
		}
	}

	settleBefore := a.maxT - a.window
	evict := map[string]bool{}
	var out []settledChain
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		flows := make([]SessionFlow, 0, len(members))
		newest := int64(0)
		complete := true
		for _, f := range members {
			meta, ok := a.flowMeta[f]
			if !ok {
				complete = false
				break
			}
			flows = append(flows, meta)
			if meta.T > newest {
				newest = meta.T
			}
		}
		if !complete || newest >= settleBefore {
			continue
		}
		sort.Strings(members)
		memberSet := make(map[string]bool, len(members))
		for _, f := range members {
			memberSet[f] = true
		}
		var edges []Edge
		for _, te := range a.edges {
			if memberSet[te.edge.Src] && memberSet[te.edge.Dst] {
				edges = append(edges, te.edge)
			}
		}
		sig := SessionSignature(flows, edges)
		id, _ := a.clusters.Assign(sig)
		tmpl := BuildChainTemplate(flows, edges)

		ordered := append([]SessionFlow(nil), flows...)
		sort.Slice(ordered, func(i, j int) bool {
			if ordered[i].T != ordered[j].T {
				return ordered[i].T < ordered[j].T
			}
			return ordered[i].Flow < ordered[j].Flow
		})
		stepFlows := make([]string, len(ordered))
		stepPorts := make([]int, len(ordered))
		for i, f := range ordered {
			stepFlows[i] = f.Flow
			stepPorts[i] = a.flowPort[f.Flow]
		}
		valueByVhash := make(map[uint64][]byte, len(edges))
		for _, e := range edges {
			valueByVhash[e.Vhash] = e.Value
		}
		linkValues := make([][]byte, len(tmpl.Links))
		for i, l := range tmpl.Links {
			linkValues[i] = valueByVhash[l.Vhash]
		}

		out = append(out, settledChain{
			ID:         id,
			Signature:  sig,
			Members:    members,
			Template:   tmpl,
			StepFlows:  stepFlows,
			StepPorts:  stepPorts,
			LinkValues: linkValues,
		})
		for _, f := range members {
			evict[f] = true
		}
	}

	if len(evict) > 0 {
		kept := a.edges[:0]
		for _, te := range a.edges {
			if evict[te.edge.Src] || evict[te.edge.Dst] {
				continue
			}
			kept = append(kept, te)
		}
		a.edges = kept
		for f := range evict {
			delete(a.flowMeta, f)
			delete(a.flowPort, f)
		}
	}
	return out
}

// evictBefore drops edges and flow metadata older than cutoff.
func (a *chainAnalyzer) evictBefore(cutoff int64) {
	if cutoff <= 0 {
		return
	}
	kept := a.edges[:0]
	for _, te := range a.edges {
		if te.t < cutoff {
			continue
		}
		kept = append(kept, te)
	}
	a.edges = kept
	for f, meta := range a.flowMeta {
		if meta.T < cutoff {
			delete(a.flowMeta, f)
			delete(a.flowPort, f)
		}
	}
}
