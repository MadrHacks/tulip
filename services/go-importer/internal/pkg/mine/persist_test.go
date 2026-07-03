package mine

import "testing"

func TestMinhashByteRoundtrip(t *testing.T) {
	m, _ := Featurize([]byte("GET /x?id=7 HTTP/1.1\r\nHost: target\r\n\r\n"))
	if got := minhashFromBytes(minhashBytes(m)); got != m {
		t.Fatal("minhash byte round-trip mismatch")
	}
}

func TestSnapshotRestorePreservesMatching(t *testing.T) {
	cs := newClusterStore(0)
	a, _ := Featurize([]byte("GET /a?id=1 HTTP/1.1\r\nHost: t\r\n\r\n"))
	b, _ := Featurize([]byte("POST /b/login HTTP/1.1\r\nHost: t\r\n\r\nuser=x"))
	idA, _ := cs.Assign(a, 1000)
	idB, _ := cs.Assign(b, 1000)
	for i := 0; i < 5; i++ {
		cs.Assign(a, 1000)
	}

	restored := restoreClusterStore(cs.snapshot(), 0, 0)
	if len(restored.clusters) != len(cs.clusters) {
		t.Fatalf("restored %d clusters, want %d", len(restored.clusters), len(cs.clusters))
	}
	if id, isNew := restored.Assign(a, 1000); isNew || id != idA {
		t.Errorf("restored A assign = (%d,%v), want (%d,false)", id, isNew, idA)
	}
	if id, isNew := restored.Assign(b, 1000); isNew || id != idB {
		t.Errorf("restored B assign = (%d,%v), want (%d,false)", id, isNew, idB)
	}

	// seq is restored, so a brand-new signature gets a fresh id beyond existing.
	c, _ := Featurize([]byte("DELETE /c/wipe/everything HTTP/1.1\r\nHost: t\r\n\r\n"))
	if id, isNew := restored.Assign(c, 1000); !isNew || id <= idB {
		t.Errorf("new signature assign = (%d,%v), want a new id > %d", id, isNew, idB)
	}
}
