package mine

import "testing"

// mkHTTP builds an HTTP request unit from a raw request string.
func mkHTTP(idx int, raw string) RequestUnit {
	return RequestUnit{Svc: "svc", Proto: "http", Index: idx, Client: []byte(raw)}
}

func shapeByID(ss *ShapeStore, svc string, id int) (Shape, bool) {
	sh := ss.shards[svc]
	if sh == nil {
		return Shape{}, false
	}
	st := sh.shapes[id]
	if st == nil {
		return Shape{}, false
	}
	return st.shape, true
}

// TestShapeStoreObserveGroupsAndAggregates: same-skeleton units share a shape
// id, a structurally different unit gets its own, signals aggregate, and the
// session shape is the ordered id sequence.
func TestShapeStoreObserveGroupsAndAggregates(t *testing.T) {
	ss := NewShapeStore(0)
	// u0,u1 share the skeleton "GET api status"; u2 is a different skeleton.
	u0 := mkHTTP(0, "GET /api/status HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")
	u1 := mkHTTP(1, "GET /api/status HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")
	u2 := mkHTTP(2, "POST /api/login HTTP/1.1\r\nHost: t\r\nUser-Agent: python-urllib3/2.7.0\r\n"+
		"Content-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"password\":\"y\",\"user\":\"x\"}")
	feats := []RespFeatures{
		{}, // u0: no flag
		{FlagPresent: true, ContentLengthBucket: 5}, // u1: response leaked a flag
		{}, // u2: no flag
	}

	res := ss.Observe("svc", []RequestUnit{u0, u1, u2}, feats, false, 8080, 1000)

	if len(res.ShapeIDs) != 3 {
		t.Fatalf("shape ids = %v, want 3", res.ShapeIDs)
	}
	if res.ShapeIDs[0] != res.ShapeIDs[1] {
		t.Errorf("same-skeleton units got different ids: %v", res.ShapeIDs)
	}
	if res.ShapeIDs[2] == res.ShapeIDs[0] {
		t.Errorf("different-skeleton unit collapsed into the same shape: %v", res.ShapeIDs)
	}
	if want := SessionShape(res.ShapeIDs); res.SessionShape != want {
		t.Errorf("session shape = %q, want %q (ordered id sequence)", res.SessionShape, want)
	}

	getShape, ok := shapeByID(ss, "svc", res.ShapeIDs[0])
	if !ok {
		t.Fatalf("shape %d missing", res.ShapeIDs[0])
	}
	if getShape.Members != 2 {
		t.Errorf("GET shape members = %d, want 2", getShape.Members)
	}
	if getShape.Signals.FlagPresent != 1 {
		t.Errorf("flag_present = %d, want 1 (only u1's response leaked)", getShape.Signals.FlagPresent)
	}
	if getShape.Signals.SizeBucketSum != 5 {
		t.Errorf("size_bucket_sum = %d, want 5", getShape.Signals.SizeBucketSum)
	}
	if getShape.Signals.Actors["checker"] != 2 {
		t.Errorf("actors = %v, want checker:2", getShape.Signals.Actors)
	}
	if getShape.Template != "GET api status" {
		t.Errorf("template = %q, want %q", getShape.Template, "GET api status")
	}

	postShape, _ := shapeByID(ss, "svc", res.ShapeIDs[2])
	if postShape.Template != "POST api login json{password,user}" {
		t.Errorf("POST template = %q", postShape.Template)
	}
	if postShape.Signals.Actors["python-urllib3/2.7.0"] != 1 {
		t.Errorf("POST actors = %v", postShape.Signals.Actors)
	}

	// flag_in is a flow-level signal carried onto every unit's shape.
	res2 := ss.Observe("svc", []RequestUnit{u0}, []RespFeatures{{}}, true, 8080, 1001)
	getShape, _ = shapeByID(ss, "svc", res2.ShapeIDs[0])
	if getShape.Signals.FlagIn != 1 {
		t.Errorf("flag_in = %d, want 1", getShape.Signals.FlagIn)
	}
	if getShape.Members != 3 {
		t.Errorf("members after 2nd observe = %d, want 3", getShape.Members)
	}
}

// TestShapeStoreSnapshotRestoreStableIDs: a snapshot round-trips shapes and their
// signals, and the restored store maps the same skeleton to the same shape id.
func TestShapeStoreSnapshotRestoreStableIDs(t *testing.T) {
	ss := NewShapeStore(0)
	u0 := mkHTTP(0, "GET /api/status HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")
	u1 := mkHTTP(1, "POST /api/login HTTP/1.1\r\nHost: t\r\nUser-Agent: wget\r\n"+
		"Content-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"password\":\"y\",\"user\":\"x\"}")
	res := ss.Observe("svc", []RequestUnit{u0, u1}, []RespFeatures{{FlagPresent: true, ContentLengthBucket: 3}, {}}, false, 8080, 1000)
	idGet, idPost := res.ShapeIDs[0], res.ShapeIDs[1]

	restored := restoreShapeStore(ss.snapshot(), 0)

	if restored.ShapeCount("svc") != ss.ShapeCount("svc") {
		t.Fatalf("restored %d shapes, want %d", restored.ShapeCount("svc"), ss.ShapeCount("svc"))
	}
	// Signals round-trip.
	rGet, ok := shapeByID(restored, "svc", idGet)
	if !ok || rGet.Members != 1 || rGet.Signals.FlagPresent != 1 || rGet.Signals.Actors["checker"] != 1 {
		t.Errorf("restored GET shape = %+v", rGet)
	}
	if rGet.Template != "GET api status" {
		t.Errorf("restored GET template = %q", rGet.Template)
	}

	// Same skeleton maps to the same id after restart, without creating a new shape.
	before := restored.ShapeCount("svc")
	again := restored.Observe("svc", []RequestUnit{u0}, []RespFeatures{{}}, false, 8080, 1002)
	if again.ShapeIDs[0] != idGet {
		t.Errorf("restored assign of GET = %d, want stable %d", again.ShapeIDs[0], idGet)
	}
	if restored.ShapeCount("svc") != before {
		t.Errorf("restored re-observe created a new shape (%d -> %d)", before, restored.ShapeCount("svc"))
	}

	// A brand-new skeleton gets a fresh id beyond the restored max (no reuse).
	uNew := mkHTTP(0, "DELETE /admin/wipe/everything HTTP/1.1\r\nHost: t\r\n\r\n")
	newRes := restored.Observe("svc", []RequestUnit{uNew}, []RespFeatures{{}}, false, 8080, 1003)
	if newRes.ShapeIDs[0] == idGet || newRes.ShapeIDs[0] == idPost {
		t.Errorf("new skeleton reused an existing id: %d", newRes.ShapeIDs[0])
	}
	if newRes.ShapeIDs[0] <= idPost {
		t.Errorf("new id %d not beyond restored max %d", newRes.ShapeIDs[0], idPost)
	}
}

// TestShapeStoreRecordsRepresentativePort: a shape records its members' ports as
// a histogram whose mode is the shape's representative REPLAY port; that mode
// rides the snapshot into mine.shape.port, is surfaced by FlagShapes, and is
// re-seeded on restore so it stays stable.
func TestShapeStoreRecordsRepresentativePort(t *testing.T) {
	ss := NewShapeStore(0)
	u := func() RequestUnit { return mkHTTP(0, "GET /api/item?id=1 HTTP/1.1\r\nHost: t\r\n\r\n") }
	// Same skeleton -> one shape; member ports 80 (x2) and 9999 (x1). Mode = 80.
	res := ss.Observe("svc", []RequestUnit{u()}, []RespFeatures{{FlagPresent: true}}, false, 80, 1000)
	ss.Observe("svc", []RequestUnit{u()}, []RespFeatures{{}}, false, 9999, 1001)
	ss.Observe("svc", []RequestUnit{u()}, []RespFeatures{{}}, false, 80, 1002)

	if ss.ShapeCount("svc") != 1 {
		t.Fatalf("shapes = %d, want 1 (same skeleton collapses them)", ss.ShapeCount("svc"))
	}
	id := res.ShapeIDs[0]
	if got := ss.shards["svc"].shapes[id].repPort(); got != 80 {
		t.Errorf("repPort = %d, want 80 (most-common member port)", got)
	}

	// The representative port rides the snapshot into mine.shape.port.
	snapPort := -1
	for _, s := range ss.snapshot()["svc"] {
		if s.ShapeID == id {
			snapPort = s.Port
		}
	}
	if snapPort != 80 {
		t.Errorf("snapshot port = %d, want 80", snapPort)
	}

	// FlagShapes surfaces the flag_present shape with its representative port.
	fs := ss.FlagShapes("svc")
	if len(fs) != 1 || fs[0].ID != id || fs[0].Port != 80 {
		t.Fatalf("FlagShapes = %+v, want one {ID:%d Port:80}", fs, id)
	}

	// Restore re-seeds the histogram from the persisted port so the mode holds
	// even though the raw histogram is not persisted.
	restored := restoreShapeStore(ss.snapshot(), 0)
	if got := restored.shards["svc"].shapes[id].repPort(); got != 80 {
		t.Errorf("restored repPort = %d, want 80 (re-seeded from persisted port)", got)
	}
}

// TestFlagShapesSelectsOnlyFlaggedShapes: FlagShapes — the neutral SOURCE the
// detection pass pursues — returns only shapes whose flag_present SIGNAL is > 0,
// each with its representative port, and nil for an unknown service.
func TestFlagShapesSelectsOnlyFlaggedShapes(t *testing.T) {
	ss := NewShapeStore(0)
	// Shape A's response leaked a flag; shape B's never did.
	a := ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /flag HTTP/1.1\r\nHost: t\r\n\r\n")},
		[]RespFeatures{{FlagPresent: true}}, false, 1337, 1000)
	ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /benign HTTP/1.1\r\nHost: t\r\n\r\n")},
		[]RespFeatures{{}}, false, 1337, 1001)

	got := ss.FlagShapes("svc")
	if len(got) != 1 {
		t.Fatalf("FlagShapes = %+v, want exactly the flag_present shape", got)
	}
	if got[0].ID != a.ShapeIDs[0] {
		t.Errorf("FlagShapes id = %d, want %d (the flag_present shape)", got[0].ID, a.ShapeIDs[0])
	}
	if got[0].Port != 1337 {
		t.Errorf("FlagShapes port = %d, want 1337", got[0].Port)
	}
	if ss.FlagShapes("nope") != nil {
		t.Error("FlagShapes on an unknown service should be nil")
	}
}

// TestShapeStoreEvictToCap: the store caps each shard and drops the
// least-recently-seen shapes, freeing them from the Drain too.
func TestShapeStoreEvictToCap(t *testing.T) {
	ss := NewShapeStore(2)
	// Three structurally distinct skeletons, observed at increasing times.
	ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /alpha HTTP/1.1\r\nHost: t\r\n\r\n")}, []RespFeatures{{}}, false, 8080, 1000)
	res2 := ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /beta HTTP/1.1\r\nHost: t\r\n\r\n")}, []RespFeatures{{}}, false, 8080, 1001)
	res3 := ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /gamma HTTP/1.1\r\nHost: t\r\n\r\n")}, []RespFeatures{{}}, false, 8080, 1002)

	if ss.ShapeCount("svc") != 3 {
		t.Fatalf("pre-evict shapes = %d, want 3", ss.ShapeCount("svc"))
	}

	gone := ss.EvictToCap()
	if len(gone["svc"]) != 1 {
		t.Fatalf("evicted = %v, want exactly 1 (least-recently-seen)", gone["svc"])
	}
	if ss.ShapeCount("svc") != 2 {
		t.Errorf("post-evict shapes = %d, want 2", ss.ShapeCount("svc"))
	}
	// The two most-recently-seen shapes (beta, gamma) survive.
	if _, ok := shapeByID(ss, "svc", res2.ShapeIDs[0]); !ok {
		t.Errorf("beta shape %d was evicted, want kept", res2.ShapeIDs[0])
	}
	if _, ok := shapeByID(ss, "svc", res3.ShapeIDs[0]); !ok {
		t.Errorf("gamma shape %d was evicted, want kept", res3.ShapeIDs[0])
	}
	// Evicting frees the Drain's live template too (heavy state released).
	if n := ss.shards["svc"].drain.NumClusters(); n != 2 {
		t.Errorf("drain live templates = %d, want 2 after eviction", n)
	}
}
