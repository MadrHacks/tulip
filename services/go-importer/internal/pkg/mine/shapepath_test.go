package mine

import (
	"strconv"
	"strings"
	"testing"

	"go-importer/internal/pkg/db"
)

// TestRefinedSplitDrivesTagsFlagShapesAndRows is the crispness-pillar contract at
// the LIVE granularity: when Drain over-merges several endpoints onto one parent
// shape ("GET api <*> ?id"), the cardinality refinement un-merges them, and that
// crisp granularity must drive the deployed path end to end — the flow tags, the
// FlagShapes the detector pursues, and the persisted mine.shape rows the candidate
// reader consumes. It pins that the boomerang IDOR is its OWN tag, its OWN
// flag-carrying shape, and its OWN persisted row with a replay body, distinct from
// the byte-adjacent benign /user endpoint that never leaks a flag.
func TestRefinedSplitDrivesTagsFlagShapesAndRows(t *testing.T) {
	store := NewShapeStore(0)
	obs := func(endpoint, id string, flag bool) ObserveResult {
		u := mkHTTP(0, "GET /api/"+endpoint+"?id="+id+" HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")
		return store.Observe("svc", []RequestUnit{u}, []RespFeatures{{FlagPresent: flag}}, false, 8080, 1000)
	}
	// boomerang leaks a flag on every id (the IDOR); user never does. Enough
	// distinct ids each to reach synthesis quorum for the replay body.
	var boomRefined, userRefined int64
	for i := 1; i <= 5; i++ {
		r := obs("boomerang", strconv.Itoa(i), true)
		boomRefined = r.RefinedIDs[0]
	}
	for i := 1; i <= 5; i++ {
		r := obs("user", strconv.Itoa(100+i), false)
		userRefined = r.RefinedIDs[0]
	}

	// Drain over-merged the endpoint to a single parent shape...
	if store.ShapeCount("svc") != 1 {
		t.Fatalf("parent shapes = %d, want 1 (endpoint merged to <*>)", store.ShapeCount("svc"))
	}
	// ...but the crisp ids the two endpoints tag at are DISTINCT.
	if boomRefined == userRefined {
		t.Fatalf("boomerang and user tagged the same refined id %d (over-merge leaked to the live tags)", boomRefined)
	}

	// The detector's candidate SOURCE is the crisp flag shape — boomerang only.
	fs := store.RefinedFlagShapes("svc")
	if len(fs) != 1 {
		t.Fatalf("RefinedFlagShapes = %+v, want exactly the boomerang shape", fs)
	}
	if fs[0].ID != boomRefined {
		t.Errorf("flag shape id = %d, want the boomerang refined id %d", fs[0].ID, boomRefined)
	}

	// The persisted rows: two distinct crisp shapes, boomerang flag-carrying with a
	// replay body, user benign; and NO row keeps a <*> at the (now resolved)
	// structural endpoint position.
	snaps := store.refinedSnapshots(testFlagRe, map[string]bool{})["svc"]
	var boom, user *shapeSnapshot
	for i := range snaps {
		if strings.Contains(snaps[i].Template, "<*>") {
			t.Errorf("refined row still has a low-card <*>: %q", snaps[i].Template)
		}
		switch int64(snaps[i].ShapeID) {
		case boomRefined:
			boom = &snaps[i]
		case userRefined:
			user = &snaps[i]
		}
	}
	if boom == nil || user == nil {
		t.Fatalf("want distinct boomerang+user rows; got %d rows", len(snaps))
	}
	if boom.Template != "GET api boomerang ?id" {
		t.Errorf("boomerang row template = %q, want the crisp endpoint", boom.Template)
	}
	if boom.FlagPresent != 5 || boom.Members != 5 {
		t.Errorf("boomerang row = members %d flag %d, want 5/5", boom.Members, boom.FlagPresent)
	}
	if len(boom.TemplateBody) == 0 {
		t.Errorf("boomerang row has no replay body (candidate needs template_body)")
	}
	if user.FlagPresent != 0 {
		t.Errorf("user row flag_present = %d, want 0 (benign endpoint)", user.FlagPresent)
	}

	// The flow tags name the crisp interaction-kinds (checked last: buildShapeTags
	// folds a member into the store).
	boomTags := buildShapeTags(store, "svc", []db.FlowMessage{
		{FromClient: true, Data: []byte("GET /api/boomerang?id=42 HTTP/1.1\r\nHost: t\r\n\r\n")},
	}, false, 8080, 2000)
	if want := "shape:svc:" + strconv.FormatInt(boomRefined, 10); !hasTag(boomTags, want) {
		t.Errorf("boomerang flow tags %v missing crisp %q", boomTags, want)
	}
	if bad := "shape:svc:" + strconv.FormatInt(userRefined, 10); hasTag(boomTags, bad) {
		t.Errorf("boomerang flow wrongly carried the user shape tag %q", bad)
	}
}

// hasTag reports whether tags contains want.
func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestBuildShapeTagsDrivesShapePath drives a couple of flows through the same
// path handle() uses (SegmentMessages -> ShapeStore.Observe -> tag building),
// without a live DB, and asserts: (1) neutral shape:/session: tags are emitted
// and NO verdict/attack tag leaks in; (2) two structurally identical flows share
// a shape id (stable clustering); (3) the store now holds shapes that would be
// persisted to mine.shape with the expected aggregated signals.
func TestBuildShapeTagsDrivesShapePath(t *testing.T) {
	store := NewShapeStore(0)

	// Flow 1: an HTTP keep-alive pair whose second response leaks a flag.
	flow1 := []db.FlowMessage{
		{FromClient: true, Data: []byte("GET /api/status HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")},
		{FromClient: false, Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")},
		{FromClient: true, Data: []byte("GET /api/note/42 HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")},
		{FromClient: false, Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\nABCDEFGHIJKLMNOPQRSTUVWXYZ01234=")},
	}
	tags1 := buildShapeTags(store, "svc", flow1, false, 8080, 1000)

	var shapeTags1 []string
	sessionTags := 0
	for _, tg := range tags1 {
		switch {
		case strings.HasPrefix(tg, "shape:svc:"):
			shapeTags1 = append(shapeTags1, tg)
		case strings.HasPrefix(tg, "session:"):
			sessionTags++
		default:
			t.Errorf("unexpected non-neutral tag %q (shape path must not emit verdicts)", tg)
		}
	}
	if len(shapeTags1) != 2 {
		t.Fatalf("shape tags = %v, want 2 (status + note)", shapeTags1)
	}
	if sessionTags != 1 {
		t.Fatalf("session tags = %d, want exactly 1", sessionTags)
	}

	// Flow 2: structurally identical to flow 1's note request (only the id and
	// the flag body differ) -> must reuse flow 1's note shape id, no new shape.
	before := store.ShapeCount("svc")
	flow2 := []db.FlowMessage{
		{FromClient: true, Data: []byte("GET /api/note/99 HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")},
		{FromClient: false, Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")},
	}
	tags2 := buildShapeTags(store, "svc", flow2, false, 8080, 1001)
	noteTag := shapeTags1[1] // "shape:svc:<noteID>"
	found := false
	for _, tg := range tags2 {
		if tg == noteTag {
			found = true
		}
	}
	if !found {
		t.Errorf("flow2 tags %v did not reuse flow1 note shape %q", tags2, noteTag)
	}
	if store.ShapeCount("svc") != before {
		t.Errorf("identical-skeleton flow minted a new shape (%d -> %d)", before, store.ShapeCount("svc"))
	}

	// The store now holds persistable CRISP mine.shape rows with aggregated
	// signals: the note refined shape has 2 members and exactly 1 flag_present
	// (flow1's leak only), keyed by the same refined id its shape:* tag names.
	snaps := store.refinedSnapshots(testFlagRe, map[string]bool{})["svc"]
	if len(snaps) == 0 {
		t.Fatalf("refined snapshot produced no mine.shape rows")
	}
	noteID := strings.TrimPrefix(noteTag, "shape:svc:")
	var note *shapeSnapshot
	for i := range snaps {
		if strconv.Itoa(snaps[i].ShapeID) == noteID {
			note = &snaps[i]
		}
	}
	if note == nil {
		t.Fatalf("note shape %s absent from snapshot", noteID)
	}
	if note.Members != 2 {
		t.Errorf("note shape members = %d, want 2 (flow1 note + flow2)", note.Members)
	}
	if note.FlagPresent != 1 {
		t.Errorf("note shape flag_present = %d, want 1 (only flow1's response leaked)", note.FlagPresent)
	}
	if note.Actors["checker"] != 2 {
		t.Errorf("note shape actors = %v, want checker:2", note.Actors)
	}
}
