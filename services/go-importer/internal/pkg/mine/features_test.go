package mine

import "testing"

func TestMinHashIdenticalAndDeterministic(t *testing.T) {
	a := []byte("GET /api/users?id=1 HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n")
	m1, s1 := Featurize(a)
	m2, s2 := Featurize(a)
	if m1 != m2 || s1 != s2 {
		t.Fatal("Featurize is not deterministic")
	}
	if j := m1.Jaccard(m2); j != 1.0 {
		t.Fatalf("identical Jaccard = %v, want 1.0", j)
	}
}

func TestMinHashSimilarVsDifferent(t *testing.T) {
	base, _ := Featurize([]byte("GET /api/users?id=1 HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n"))
	similar, _ := Featurize([]byte("GET /api/users?id=2 HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n"))
	different, _ := Featurize([]byte("POST /login/session/create plus an entirely unrelated body payload"))

	if j := base.Jaccard(similar); j < 0.5 {
		t.Errorf("similar Jaccard = %v, want > 0.5", j)
	}
	if j := base.Jaccard(different); j > 0.3 {
		t.Errorf("different Jaccard = %v, want < 0.3", j)
	}
}

func TestSimHashHammingTracksSimilarity(t *testing.T) {
	_, base := Featurize([]byte("GET /api/users?id=1 HTTP/1.1\r\nHost: target\r\n\r\n"))
	_, similar := Featurize([]byte("GET /api/users?id=2 HTTP/1.1\r\nHost: target\r\n\r\n"))
	_, different := Featurize([]byte("totally different content with no overlap at all here"))
	if hamming(base, similar) >= hamming(base, different) {
		t.Errorf("expected similar closer than different (sim=%d diff=%d)",
			hamming(base, similar), hamming(base, different))
	}
}

func hamming(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		n++
		x &= x - 1
	}
	return n
}
