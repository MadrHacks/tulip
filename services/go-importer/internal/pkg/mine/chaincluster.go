package mine

// chainClusterStore gives each distinct session signature a durable id, so
// sessions of the same multi-step exploit (same chain pattern) share a
// chain-cluster id. This is the second clustering level, above per-flow clusters.
type chainClusterStore struct {
	ids map[string]int64
	seq int64
}

func newChainClusterStore() *chainClusterStore {
	return &chainClusterStore{ids: map[string]int64{}}
}

// Assign returns the chain-cluster id for a session signature and whether it was
// newly created.
func (cs *chainClusterStore) Assign(signature string) (int64, bool) {
	if id, ok := cs.ids[signature]; ok {
		return id, false
	}
	cs.seq++
	cs.ids[signature] = cs.seq
	return cs.seq, true
}
