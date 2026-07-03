package mine

import (
	"strconv"
	"strings"
	"testing"

	"go-importer/internal/pkg/db"
)

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

	// The store now holds persistable mine.shape rows with aggregated signals:
	// the note shape has 2 members and exactly 1 flag_present (flow1's leak only).
	snaps := store.snapshot()["svc"]
	if len(snaps) == 0 {
		t.Fatalf("snapshot produced no mine.shape rows")
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
