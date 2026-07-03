package mine

// Streaming support for the Drain miner (drain.go), used by ShapeStore's
// snapshot/restore and eviction. These are ADDITIVE lifecycle helpers; the
// mining algorithm in drain.go is unchanged.

// reinsert restores a template under a FIXED id, re-seeding the prefix tree and
// idToCluster and advancing the counter so later Add calls never reuse a
// restored id. This is what keeps shape ids stable across a minecore restart:
// the same skeleton routes to the same restored template. Empty tokens are
// treated as the "<EMPTY>" template, matching Add.
func (d *Drain) reinsert(id int, tokens []string, size int) {
	if len(tokens) == 0 {
		tokens = []string{"<EMPTY>"}
	}
	c := &drainCluster{tokens: append([]string(nil), tokens...), id: id, size: size}
	d.idToCluster[id] = c
	d.addSeqToPrefixTree(c)
	if id > d.counter {
		d.counter = id
	}
}

// forget drops a template's cluster from the live set so an evicted shape stops
// matching and frees its memory. The counter stays monotonic so the id is never
// reused; a stale reference left in the prefix tree is a dangling id that
// fastMatch already skips (its idToCluster lookup returns nil).
func (d *Drain) forget(id int) {
	delete(d.idToCluster, id)
}
