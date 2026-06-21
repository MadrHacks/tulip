package mine

const (
	tMerge       = 0.82 // min Jaccard to join an existing cluster
	reservoirCap = 64   // bounded sample per cluster for medoid
	coreQuorum   = 3    // freeze the identity anchor at this many members
)

// cluster is a leader-clustering group of MinHash signatures for one service shard.
type cluster struct {
	id        int64
	rep       MinHash   // medoid of the reservoir (drifts; used for matching)
	core      MinHash   // frozen identity anchor (set once at coreQuorum)
	coreSet   bool      // whether core has been frozen
	reservoir []MinHash // bounded sample (<= reservoirCap)
	n         int       // total members ever assigned
}

// clusterStore keeps leader clusters indexed by an LSH over their current reps.
type clusterStore struct {
	lsh      *lshIndex
	clusters map[int64]*cluster
	seq      int64
}

func newClusterStore() *clusterStore {
	return &clusterStore{
		lsh:      newLSHIndex(),
		clusters: make(map[int64]*cluster),
	}
}

// Assign places sig into the best-matching existing cluster (Jaccard >= tMerge
// against either its rep or its frozen core), or creates a new one. It returns
// the cluster id and whether the cluster was newly created.
func (cs *clusterStore) Assign(sig MinHash) (id int64, isNew bool) {
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
		if j >= tMerge && j > bestJ {
			bestJ = j
			bestID = cid
		}
	}

	if bestID >= 0 {
		cs.addMember(cs.clusters[bestID], sig)
		return bestID, false
	}

	cs.seq++
	c := &cluster{id: cs.seq, rep: sig, reservoir: []MinHash{sig}, n: 1}
	cs.clusters[cs.seq] = c
	cs.lsh.add(sig, cs.seq)
	return cs.seq, true
}

// addMember folds sig into c, updates the bounded reservoir and medoid rep, and
// freezes the identity core once the quorum is reached.
func (cs *clusterStore) addMember(c *cluster, sig MinHash) {
	c.n++

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
