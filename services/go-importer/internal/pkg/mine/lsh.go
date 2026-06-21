package mine

// Banded LSH over MinHash signatures: O(1) candidate-neighbour lookup so cluster
// assignment never goes pairwise. The 128 MinHash positions split into 32 bands
// of 4 rows; two signatures share a band bucket iff they are MinHash-near (the
// (bands, rows) S-curve detects most pairs above Jaccard ~0.6). One index lives
// per service shard.

const (
	lshBands = 32
	lshRows  = 4
)

// compile-time invariant: every MinHash position is covered by exactly one band.
var _ = [1]struct{}{}[lshBands*lshRows-minhashN]

type lshIndex struct {
	bands [lshBands]map[uint64]map[int64]struct{}
}

func newLSHIndex() *lshIndex {
	idx := &lshIndex{}
	for b := range idx.bands {
		idx.bands[b] = make(map[uint64]map[int64]struct{})
	}
	return idx
}

func bandKey(sig MinHash, band int) uint64 {
	h := uint64(1469598103934665603)
	for r := 0; r < lshRows; r++ {
		v := sig[band*lshRows+r]
		for s := 0; s < 8; s++ {
			h ^= (v >> (8 * uint(s))) & 0xff
			h *= 1099511628211
		}
	}
	return h
}

func (idx *lshIndex) add(sig MinHash, id int64) {
	for b := 0; b < lshBands; b++ {
		k := bandKey(sig, b)
		bucket := idx.bands[b][k]
		if bucket == nil {
			bucket = make(map[int64]struct{})
			idx.bands[b][k] = bucket
		}
		bucket[id] = struct{}{}
	}
}

func (idx *lshIndex) remove(sig MinHash, id int64) {
	for b := 0; b < lshBands; b++ {
		k := bandKey(sig, b)
		if bucket := idx.bands[b][k]; bucket != nil {
			delete(bucket, id)
			if len(bucket) == 0 {
				delete(idx.bands[b], k)
			}
		}
	}
}

// candidates returns the ids sharing at least one band bucket with sig.
func (idx *lshIndex) candidates(sig MinHash) map[int64]struct{} {
	out := make(map[int64]struct{})
	for b := 0; b < lshBands; b++ {
		for id := range idx.bands[b][bandKey(sig, b)] {
			out[id] = struct{}{}
		}
	}
	return out
}
