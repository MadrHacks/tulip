package mine

import "sort"

// ChainStep is one step of an exploit chain: a single-flow cluster.
type ChainStep struct {
	ClusterID string `json:"cluster_id"`
}

// LinkVar is a cross-flow dataflow link expressed over step indices.
type LinkVar struct {
	Kind         string `json:"kind"`
	ProducerStep int    `json:"producer_step"`
	ConsumerStep int    `json:"consumer_step"`
	Vhash        uint64 `json:"vhash"`
}

// ChainTemplate is an ordered DAG of steps plus link variables.
type ChainTemplate struct {
	Steps []ChainStep `json:"steps"`
	Links []LinkVar   `json:"links"`
}

// BuildChainTemplate builds a chain template from a session's flows and the
// dataflow edges between them. Steps are ordered by (T asc, Flow asc); links
// are the edges whose Src and Dst are both session flows, sorted by
// (ProducerStep, ConsumerStep, Vhash). Caller slices are not mutated.
func BuildChainTemplate(flows []SessionFlow, edges []Edge) ChainTemplate {
	ordered := make([]SessionFlow, len(flows))
	copy(ordered, flows)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].T != ordered[j].T {
			return ordered[i].T < ordered[j].T
		}
		return ordered[i].Flow < ordered[j].Flow
	})

	steps := make([]ChainStep, len(ordered))
	index := make(map[string]int, len(ordered))
	for i, f := range ordered {
		steps[i] = ChainStep{ClusterID: f.ClusterID}
		index[f.Flow] = i
	}

	links := make([]LinkVar, 0, len(edges))
	for _, e := range edges {
		src, srcOK := index[e.Src]
		dst, dstOK := index[e.Dst]
		if !srcOK || !dstOK {
			continue
		}
		links = append(links, LinkVar{
			Kind:         "extracted",
			ProducerStep: src,
			ConsumerStep: dst,
			Vhash:        e.Vhash,
		})
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].ProducerStep != links[j].ProducerStep {
			return links[i].ProducerStep < links[j].ProducerStep
		}
		if links[i].ConsumerStep != links[j].ConsumerStep {
			return links[i].ConsumerStep < links[j].ConsumerStep
		}
		return links[i].Vhash < links[j].Vhash
	})

	return ChainTemplate{Steps: steps, Links: links}
}
