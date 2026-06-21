package mine

// Edge is a cross-flow value-dataflow link: a high-entropy value first produced
// in flow Src (a server response) and later reused in a different flow Dst (a
// client request). Vhash identifies the value.
type Edge struct {
	Src   string
	Dst   string
	Vhash uint64
}

// occ is a single in-window observation of a value in some flow.
type occ struct {
	flow     string
	t        int64
	produced bool
}

// vstate is the per-vhash sliding-window state.
type vstate struct {
	occs   []occ
	flowDF map[string]int // distinct flow -> count of live occurrences in that flow
}

// VDG tracks high-entropy values across flows and emits produced->consumed edges
// within a bounded recent time window. Values carried by too many distinct flows
// are treated as framework constants and excluded.
type VDG struct {
	window int64 // seconds
	dfMax  int
	states map[uint64]*vstate
}

// NewVDG returns a VDG with the given window (seconds) and distinct-flow cap.
func NewVDG(windowSec int64, dfMax int) *VDG {
	return &VDG{
		window: windowSec,
		dfMax:  dfMax,
		states: make(map[uint64]*vstate),
	}
}

// Observe records that value was seen in flow at tSec (produced if it is a server
// response). It returns at most one Edge: the link from the nearest in-window
// producer in a different flow to this consuming flow.
func (g *VDG) Observe(flow string, tSec int64, produced bool, value []byte) []Edge {
	if !IsHighEntropyToken(value) {
		return nil
	}

	h := hash64(value)
	st := g.states[h]
	if st == nil {
		st = &vstate{flowDF: make(map[string]int)}
		g.states[h] = st
	}

	g.evict(st, tSec)

	if len(st.flowDF) > g.dfMax {
		return nil
	}

	var edges []Edge
	if !produced {
		bestT := int64(0)
		bestFlow := ""
		found := false
		for _, o := range st.occs {
			if !o.produced || o.flow == flow || o.t > tSec {
				continue
			}
			if !found || o.t > bestT {
				bestT = o.t
				bestFlow = o.flow
				found = true
			}
		}
		if found {
			edges = []Edge{{Src: bestFlow, Dst: flow, Vhash: h}}
		}
	}

	st.occs = append(st.occs, occ{flow: flow, t: tSec, produced: produced})
	st.flowDF[flow]++

	return edges
}

// evict drops occurrences older than tSec-window and keeps the distinct-flow set
// in sync, removing flows that no longer have any live occurrence.
func (g *VDG) evict(st *vstate, tSec int64) {
	cutoff := tSec - g.window
	kept := st.occs[:0]
	for _, o := range st.occs {
		if o.t < cutoff {
			if st.flowDF[o.flow] <= 1 {
				delete(st.flowDF, o.flow)
			} else {
				st.flowDF[o.flow]--
			}
			continue
		}
		kept = append(kept, o)
	}
	st.occs = kept
}
