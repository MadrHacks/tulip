package mine

import "testing"

func TestLSHRecallAndRemove(t *testing.T) {
	idx := newLSHIndex()
	a, _ := Featurize([]byte("GET /api/users?id=1 HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n"))
	b, _ := Featurize([]byte("GET /api/users?id=2 HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n"))
	idx.add(a, 1)

	if _, ok := idx.candidates(b)[1]; !ok {
		t.Error("near-identical signature should be a candidate of id 1")
	}
	idx.remove(a, 1)
	if _, ok := idx.candidates(b)[1]; ok {
		t.Error("removed id should no longer be a candidate")
	}
}

func TestLSHNoFalseShare(t *testing.T) {
	idx := newLSHIndex()
	var x, y MinHash
	for i := range x {
		x[i] = uint64(i)
		y[i] = uint64(i) + 1000
	}
	idx.add(x, 1)
	if len(idx.candidates(y)) != 0 {
		t.Error("fully distinct signatures must not share a bucket")
	}
}
