package mine

import "sort"

const (
	defaultMergeThreshold = 0.82 // min Jaccard to join a cluster (overridable)
	reservoirCap          = 64   // bounded sample per cluster for medoid
	coreQuorum            = 3    // freeze the identity anchor at this many members
)

// cluster is a leader-clustering group of MinHash signatures for one service shard.
type cluster struct {
	id        int64
	rep       MinHash   // medoid of the reservoir (drifts; used for matching)
	core      MinHash   // frozen identity anchor (set once at coreQuorum)
	coreSet   bool      // whether core has been frozen
	reservoir []MinHash // bounded sample (<= reservoirCap)
	n         int       // total members ever assigned
	lastSeen  int64     // newest member's flow time (unix sec), for eviction
	firstSeen int64     // oldest member's flow time — novelty signal (NAT-robust)
	flagOut   int       // members that leaked a flag (server->client) — the attack signal
}

// clusterStore keeps leader clusters indexed by an LSH over their current reps.
type clusterStore struct {
	lsh       *lshIndex
	clusters  map[int64]*cluster
	seq       int64
	threshold float64 // min Jaccard to join a cluster
}

// newClusterStore builds a shard with the given merge threshold; a non-positive
// value falls back to the default.
func newClusterStore(threshold float64) *clusterStore {
	if threshold <= 0 {
		threshold = defaultMergeThreshold
	}
	return &clusterStore{
		lsh:       newLSHIndex(),
		clusters:  make(map[int64]*cluster),
		threshold: threshold,
	}
}

// Assign places sig into the best-matching existing cluster (Jaccard >= tMerge
// against either its rep or its frozen core), or creates a new one. t is the
// flow's time, recorded for eviction. Returns the cluster id and whether the
// cluster was newly created.
func (cs *clusterStore) Assign(sig MinHash, t int64, hasFlagOut bool) (id int64, isNew bool) {
	bestID := int64(-1)
	bestJ := 0.0
	for cid := range cs.lsh.candidates(sig) {
		c := cs.clusters[cid]
		if c == nil {
			continue
		}
		j := c.rep.Jaccard(sig)
		if c.coreSet {
			if cj := c.core.Jaccard(sig); cj > j {
				j = cj
			}
		}
		if j >= cs.threshold && j > bestJ {
			bestJ = j
			bestID = cid
		}
	}

	if bestID >= 0 {
		cs.addMember(cs.clusters[bestID], sig, t, hasFlagOut)
		return bestID, false
	}

	cs.seq++
	c := &cluster{id: cs.seq, rep: sig, reservoir: []MinHash{sig}, n: 1, lastSeen: t, firstSeen: t}
	if hasFlagOut {
		c.flagOut = 1
	}
	cs.clusters[cs.seq] = c
	cs.lsh.add(sig, cs.seq)
	return cs.seq, true
}

// addMember folds sig into c, updates the bounded reservoir and medoid rep, and
// freezes the identity core once the quorum is reached.
func (cs *clusterStore) addMember(c *cluster, sig MinHash, t int64, hasFlagOut bool) {
	c.n++
	if t > c.lastSeen {
		c.lastSeen = t
	}
	if hasFlagOut {
		c.flagOut++
	}

	full := len(c.reservoir) >= reservoirCap
	if full {
		c.reservoir[c.n%reservoirCap] = sig // deterministic, randomness-free
	} else {
		c.reservoir = append(c.reservoir, sig)
	}

	if !c.coreSet && c.n >= coreQuorum {
		c.core = medoid(c.reservoir)
		c.coreSet = true
	}

	// Appending a copy of the current rep cannot move the medoid; skip the
	// recompute on that hot path. An eviction (full) can, so never skip then.
	if !full && sig == c.rep {
		return
	}

	oldRep := c.rep
	c.rep = medoid(c.reservoir)
	if c.rep != oldRep {
		cs.lsh.remove(oldRep, c.id)
		cs.lsh.add(c.rep, c.id)
	}
}

// evictStale removes clusters whose newest member is older than before, freeing
// their memory and LSH entries. Returns the evicted ids so the engine can drop
// their persisted rows and template state. Flows older than the horizon are not
// even read, so their clusters can leave RAM without losing live matches.
func (cs *clusterStore) evictStale(before int64) []int64 {
	var gone []int64
	for id, c := range cs.clusters {
		if c.lastSeen < before {
			cs.lsh.remove(c.rep, id)
			delete(cs.clusters, id)
			gone = append(gone, id)
		}
	}
	return gone
}

// evictToCap enforces a hard per-shard cap, removing the least-recently-seen
// clusters until at most max remain. A cap <= 0 is unbounded. Returns evicted ids.
func (cs *clusterStore) evictToCap(max int) []int64 {
	if max <= 0 || len(cs.clusters) <= max {
		return nil
	}
	ids := make([]int64, 0, len(cs.clusters))
	for id := range cs.clusters {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return cs.clusters[ids[i]].lastSeen < cs.clusters[ids[j]].lastSeen
	})
	gone := ids[:len(cs.clusters)-max]
	for _, id := range gone {
		cs.lsh.remove(cs.clusters[id].rep, id)
		delete(cs.clusters, id)
	}
	return gone
}

// medoid returns the element of sigs minimizing the summed distance (1 - Jaccard)
// to all others, with a deterministic first-minimal-index tie-break. O(k^2).
func medoid(sigs []MinHash) MinHash {
	if len(sigs) == 1 {
		return sigs[0]
	}
	bestIdx := 0
	bestSum := -1.0
	for i := range sigs {
		sum := 0.0
		for j := range sigs {
			if i != j {
				sum += 1.0 - sigs[i].Jaccard(sigs[j])
			}
		}
		if bestSum < 0 || sum < bestSum {
			bestSum = sum
			bestIdx = i
		}
	}
	return sigs[bestIdx]
}

// clusterSnapshot is the durable identity of a cluster (enough to match new
// flows after a restart). The reservoir sample is not persisted; it re-seeds
// from rep on restore.
type clusterSnapshot struct {
	id       int64
	rep      MinHash
	core     MinHash
	coreSet  bool
	n        int
	lastSeen int64
}

func (cs *clusterStore) snapshot() []clusterSnapshot {
	out := make([]clusterSnapshot, 0, len(cs.clusters))
	for _, c := range cs.clusters {
		out = append(out, clusterSnapshot{c.id, c.rep, c.core, c.coreSet, c.n, c.lastSeen})
	}
	return out
}

// restoreClusterStore rebuilds a shard, skipping clusters last seen before floor
// so a restart after downtime does not reload long-dead clusters into RAM.
func restoreClusterStore(snaps []clusterSnapshot, floor int64, threshold float64) *clusterStore {
	cs := newClusterStore(threshold)
	for _, s := range snaps {
		if s.lastSeen < floor {
			continue
		}
		cs.clusters[s.id] = &cluster{
			id: s.id, rep: s.rep, core: s.core, coreSet: s.coreSet,
			reservoir: []MinHash{s.rep}, n: s.n, lastSeen: s.lastSeen,
		}
		cs.lsh.add(s.rep, s.id)
		if s.id > cs.seq {
			cs.seq = s.id
		}
	}
	return cs
}
