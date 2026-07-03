package mine

// Similarity features over a normalized request: a MinHash signature (Jaccard
// estimator, drives LSH + cluster assignment) and a SimHash fingerprint (compact
// near-dup check). Each shingle is hashed once; the 128 MinHash minima are
// derived by cheap multiply-add, so cost is O(shingles), not O(shingles*128
// hashes). Constants are fixed (deterministic seed) so signatures are stable
// across restarts and across processes.

const (
	shingleK = 8
	minhashN = 128

	// maxFeatureBytes caps the input to Featurize. A request's shape is captured
	// by its first several KB (method, path, headers, body start); truncating
	// there keeps MinHash cost bounded on large bodies without hurting clustering.
	maxFeatureBytes = 8192
)

var (
	mhA [minhashN]uint64
	mhB [minhashN]uint64
)

func init() {
	s := uint64(0x9E3779B97F4A7C15)
	next := func() uint64 {
		s += 0x9E3779B97F4A7C15
		z := s
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	for i := 0; i < minhashN; i++ {
		mhA[i] = next() | 1
		mhB[i] = next()
	}
}

type MinHash [minhashN]uint64

// Featurize computes the MinHash + SimHash of a normalized request.
func Featurize(data []byte) (MinHash, uint64) {
	sh := shingleHashes(data, shingleK)
	return computeMinHash(sh), computeSimHash(sh)
}

func shingleHashes(data []byte, k int) map[uint64]struct{} {
	set := make(map[uint64]struct{})
	if len(data) == 0 {
		return set
	}
	if len(data) <= k {
		set[hash64(data)] = struct{}{}
		return set
	}
	for i := 0; i+k <= len(data); i++ {
		set[hash64(data[i:i+k])] = struct{}{}
	}
	return set
}

func hash64(b []byte) uint64 {
	h := uint64(1469598103934665603)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func computeMinHash(shingles map[uint64]struct{}) MinHash {
	var sig MinHash
	for i := range sig {
		sig[i] = ^uint64(0)
	}
	for s := range shingles {
		for j := 0; j < minhashN; j++ {
			if v := mhA[j]*s + mhB[j]; v < sig[j] {
				sig[j] = v
			}
		}
	}
	return sig
}

// Jaccard estimates the Jaccard similarity of two signatures (fraction of equal
// positions).
func (a MinHash) Jaccard(b MinHash) float64 {
	eq := 0
	for i := range a {
		if a[i] == b[i] {
			eq++
		}
	}
	return float64(eq) / float64(minhashN)
}

func computeSimHash(shingles map[uint64]struct{}) uint64 {
	var v [64]int
	for s := range shingles {
		for i := 0; i < 64; i++ {
			if s&(uint64(1)<<uint(i)) != 0 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var sim uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			sim |= uint64(1) << uint(i)
		}
	}
	return sim
}
