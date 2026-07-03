package mine

import (
	"strconv"
	"strings"
)

// Request-unit shape pipeline — stage 4a: a Drain-style fixed-depth template
// miner. Faithful Go port of the Drain algorithm as used by drain3
// (stage4_group.py's ShapeGrouper), with the prototype's knee settings:
// sim_th=0.6, depth=4, max_children=100, unlimited clusters,
// parametrize_numeric_tokens=False.
//
// Unlimited clusters is deliberate: drain3's max_clusters uses an LRU cache
// that silently evicts and corrupts results, so the prototype set it to None.
// This port uses a plain map (no cap) to reproduce that.
//
// Structure: messages are grouped first by token count, then by first token
// (the fixed-depth prefix tree; depth=4 => one token level), then matched to the
// best template within that leaf at sim_th. Positions that vary across a
// cluster's members become <*> wildcards.

const drainParamStr = "<*>"

type drainNode struct {
	children   map[string]*drainNode
	clusterIDs []int
}

func newDrainNode() *drainNode {
	return &drainNode{children: map[string]*drainNode{}}
}

type drainCluster struct {
	tokens []string // the template tokens (with <*> wildcards)
	id     int
	size   int
}

// Drain is a fixed-depth template miner. Add returns a stable template id per
// message; Template / Templates expose the mined templates.
type Drain struct {
	depth        int
	maxNodeDepth int
	simTh        float64
	maxChildren  int
	root         *drainNode
	idToCluster  map[int]*drainCluster
	counter      int
}

// NewDrain builds a miner. depth must be >= 3; a non-positive maxChildren
// disables the child cap. A non-positive depth/simTh falls back to the
// prototype's knee (depth 4, sim_th 0.6).
func NewDrain(simTh float64, depth, maxChildren int) *Drain {
	if depth < 3 {
		depth = 4
	}
	if simTh <= 0 {
		simTh = 0.6
	}
	if maxChildren <= 0 {
		maxChildren = 100
	}
	return &Drain{
		depth:        depth,
		maxNodeDepth: depth - 2,
		simTh:        simTh,
		maxChildren:  maxChildren,
		root:         newDrainNode(),
		idToCluster:  map[int]*drainCluster{},
	}
}

// NewShapeGrouper builds a Drain with the prototype's default knee settings.
func NewShapeGrouper() *Drain { return NewDrain(0.6, 4, 100) }

func drainTokens(content string) []string {
	return strings.Fields(content)
}

// Add folds content into the best-matching template (or creates a new one) and
// returns that template's id. An empty message is treated as "<EMPTY>".
func (d *Drain) Add(content string) int {
	if content == "" {
		content = "<EMPTY>"
	}
	tokens := drainTokens(content)
	match := d.treeSearch(tokens)
	if match == nil {
		d.counter++
		c := &drainCluster{tokens: append([]string(nil), tokens...), id: d.counter, size: 1}
		d.idToCluster[c.id] = c
		d.addSeqToPrefixTree(c)
		return c.id
	}
	newTmpl := createTemplate(tokens, match.tokens)
	if !equalTokens(newTmpl, match.tokens) {
		match.tokens = newTmpl
	}
	match.size++
	return match.id
}

// Template returns the mined template string for id (space-joined), or "?".
func (d *Drain) Template(id int) string {
	if c, ok := d.idToCluster[id]; ok {
		return strings.Join(c.tokens, " ")
	}
	return "?"
}

// Templates returns every cluster id -> template string.
func (d *Drain) Templates() map[int]string {
	out := make(map[int]string, len(d.idToCluster))
	for id, c := range d.idToCluster {
		out[id] = strings.Join(c.tokens, " ")
	}
	return out
}

// NumClusters returns the number of live templates.
func (d *Drain) NumClusters() int { return len(d.idToCluster) }

func (d *Drain) treeSearch(tokens []string) *drainCluster {
	tokenCount := len(tokens)
	cur := d.root.children[strconv.Itoa(tokenCount)]
	if cur == nil {
		return nil
	}
	if tokenCount == 0 {
		if len(cur.clusterIDs) == 0 {
			return nil
		}
		return d.idToCluster[cur.clusterIDs[0]]
	}
	depth := 1
	for _, tok := range tokens {
		if depth >= d.maxNodeDepth {
			break
		}
		if depth == tokenCount {
			break
		}
		next := cur.children[tok]
		if next == nil {
			next = cur.children[drainParamStr]
		}
		if next == nil {
			return nil
		}
		cur = next
		depth++
	}
	return d.fastMatch(cur.clusterIDs, tokens)
}

// fastMatch selects the highest-similarity cluster (tie-break: more wildcard
// params), returning it only if similarity >= sim_th.
func (d *Drain) fastMatch(clusterIDs []int, tokens []string) *drainCluster {
	maxSim := -1.0
	maxParam := -1
	var best *drainCluster
	for _, cid := range clusterIDs {
		c := d.idToCluster[cid]
		if c == nil {
			continue
		}
		sim, params := seqDistance(c.tokens, tokens)
		if sim > maxSim || (sim == maxSim && params > maxParam) {
			maxSim = sim
			maxParam = params
			best = c
		}
	}
	if maxSim >= d.simTh {
		return best
	}
	return nil
}

// seqDistance returns (fraction of non-wildcard template tokens that match the
// message, wildcard count). include_params is always false on the add path, so
// wildcards do not count toward similarity.
func seqDistance(template, tokens []string) (float64, int) {
	if len(template) == 0 {
		return 1.0, 0
	}
	sim := 0
	params := 0
	for i := range template {
		if template[i] == drainParamStr {
			params++
			continue
		}
		if template[i] == tokens[i] {
			sim++
		}
	}
	return float64(sim) / float64(len(template)), params
}

func (d *Drain) addSeqToPrefixTree(c *drainCluster) {
	tokenCount := len(c.tokens)
	countKey := strconv.Itoa(tokenCount)
	first := d.root.children[countKey]
	if first == nil {
		first = newDrainNode()
		d.root.children[countKey] = first
	}
	cur := first
	if tokenCount == 0 {
		cur.clusterIDs = []int{c.id}
		return
	}
	depth := 1
	for _, tok := range c.tokens {
		if depth >= d.maxNodeDepth || depth >= tokenCount {
			cur.clusterIDs = append(cur.clusterIDs, c.id)
			break
		}
		if next, ok := cur.children[tok]; ok {
			cur = next
		} else {
			// parametrize_numeric_tokens is false: only the literal-token /
			// wildcard-cap branch applies.
			if _, hasWild := cur.children[drainParamStr]; hasWild {
				if len(cur.children) < d.maxChildren {
					nn := newDrainNode()
					cur.children[tok] = nn
					cur = nn
				} else {
					cur = cur.children[drainParamStr]
				}
			} else {
				switch {
				case len(cur.children)+1 < d.maxChildren:
					nn := newDrainNode()
					cur.children[tok] = nn
					cur = nn
				case len(cur.children)+1 == d.maxChildren:
					nn := newDrainNode()
					cur.children[drainParamStr] = nn
					cur = nn
				default:
					cur = cur.children[drainParamStr]
				}
			}
		}
		depth++
	}
}

// createTemplate generalizes an existing template against a new message:
// positions where the message differs from the template become wildcards.
func createTemplate(message, template []string) []string {
	out := append([]string(nil), template...)
	for i := range template {
		if message[i] != template[i] {
			out[i] = drainParamStr
		}
	}
	return out
}

func equalTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
