package mine

import (
	"bytes"
	"regexp"
	"testing"
)

var testFlagRe = regexp.MustCompile(`[A-Z0-9]{31}=`)

// TestShapeSynthesizesReplayTemplate: a shape built from near-identical request
// units that differ ONLY in a masked value (the skeleton collapses them into one
// shape) must synthesize a REPLAY template whose sole variable position is a Var
// slot, with the shared request bytes preserved as Const segments.
func TestShapeSynthesizesReplayTemplate(t *testing.T) {
	ss := NewShapeStore(0)

	// Same endpoint + query KEY, different query VALUE. NormalizeUnit masks the
	// value (keeps only "?id"), so all three land in one shape; canonical() keeps
	// the concrete value, so alignment can recover it as a slot.
	for i, v := range []string{"1041", "2072", "3093"} {
		u := mkHTTP(0, "GET /api/item?id="+v+" HTTP/1.1\r\nHost: t\r\nUser-Agent: checker\r\n\r\n")
		ss.Observe("svc", []RequestUnit{u}, []RespFeatures{{}}, false, int64(1000+i))
	}
	if ss.ShapeCount("svc") != 1 {
		t.Fatalf("shapes = %d, want 1 (masked value collapses them into one shape)", ss.ShapeCount("svc"))
	}

	if n := ss.SynthesizeTemplates(testFlagRe, map[string]bool{}); n != 1 {
		t.Fatalf("synthesized %d templates, want 1", n)
	}
	shapes := ss.Shapes("svc")
	tpl := ss.ShapeTemplate("svc", shapes[0].TemplateID)
	if tpl == nil {
		t.Fatal("no replay template synthesized for the shape")
	}

	// The single varying position is a Var slot; everything else stays Const.
	if got := countVarSegments(tpl.Segments); got != 1 {
		t.Fatalf("var segments = %d, want 1: %+v", got, tpl.Segments)
	}
	if len(tpl.Slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(tpl.Slots))
	}
	// All three values are 4 bytes long.
	if tpl.Slots[0].MinLen != 4 || tpl.Slots[0].MaxLen != 4 {
		t.Errorf("slot len = [%d,%d], want [4,4]", tpl.Slots[0].MinLen, tpl.Slots[0].MaxLen)
	}
	// The constant anchors preserve the request's shared bytes verbatim.
	var constBytes []byte
	for _, s := range tpl.Segments {
		if !s.Var {
			constBytes = append(constBytes, s.Const...)
		}
	}
	if !bytes.Contains(constBytes, []byte("GET /api/item")) || !bytes.Contains(constBytes, []byte("id=")) {
		t.Errorf("const anchors lost shared bytes: %q", constBytes)
	}
}

// TestShapeTemplateTypesFlagIDSlot: when the varying slot's values are live
// flagIds, slot-typing (reused from the cluster path) classifies it as flagid —
// so the replay scaffold knows to re-fetch it per target.
func TestShapeTemplateTypesFlagIDSlot(t *testing.T) {
	ss := NewShapeStore(0)
	ids := []string{"deadbeefcafe1234", "feedface00112233", "0123456789abcdef"}
	flagIDs := map[string]bool{}
	for _, x := range ids {
		flagIDs[x] = true
	}
	for i, x := range ids {
		u := mkHTTP(0, "GET /store?id="+x+" HTTP/1.1\r\nHost: t\r\n\r\n")
		ss.Observe("svc", []RequestUnit{u}, []RespFeatures{{}}, false, int64(1000+i))
	}
	ss.SynthesizeTemplates(testFlagRe, flagIDs)
	tpl := ss.ShapeTemplate("svc", ss.Shapes("svc")[0].TemplateID)
	if tpl == nil || len(tpl.Slots) != 1 {
		t.Fatalf("want a 1-slot template, got %+v", tpl)
	}
	if tpl.Slots[0].Type != SlotFlagID {
		t.Errorf("slot type = %v, want flagid", tpl.Slots[0].Type)
	}
}

// TestShapeTemplateBelowQuorum: a shape with fewer than the quorum of reservoir
// samples gets no template (never a partial one).
func TestShapeTemplateBelowQuorum(t *testing.T) {
	ss := NewShapeStore(0)
	ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /a?id=1 HTTP/1.1\r\nHost: t\r\n\r\n")}, []RespFeatures{{}}, false, 1)
	ss.Observe("svc", []RequestUnit{mkHTTP(0, "GET /a?id=2 HTTP/1.1\r\nHost: t\r\n\r\n")}, []RespFeatures{{}}, false, 2)
	if n := ss.SynthesizeTemplates(testFlagRe, nil); n != 0 {
		t.Fatalf("synthesized %d templates below quorum, want 0", n)
	}
	if ss.ShapeTemplate("svc", ss.Shapes("svc")[0].TemplateID) != nil {
		t.Error("template present below quorum, want nil")
	}
}

// TestShapeReservoirBounded: the per-shape reservoir never grows past its cap,
// no matter how many members a shape absorbs.
func TestShapeReservoirBounded(t *testing.T) {
	ss := NewShapeStore(0)
	for i := 0; i < 50; i++ {
		u := mkHTTP(0, "GET /api/item?id=1000 HTTP/1.1\r\nHost: t\r\n\r\n")
		ss.Observe("svc", []RequestUnit{u}, []RespFeatures{{}}, false, int64(i))
	}
	st := ss.shards["svc"].shapes[ss.Shapes("svc")[0].TemplateID]
	if len(st.samples) != shapeReservoirCap {
		t.Errorf("reservoir size = %d, want capped at %d", len(st.samples), shapeReservoirCap)
	}
	if st.shape.Members != 50 {
		t.Errorf("members = %d, want 50 (all counted even though reservoir is bounded)", st.shape.Members)
	}
}

// TestShapeTemplatePersistRoundTrip: a synthesized replay template rides the
// snapshot into template_body and is reloaded on restore (samples themselves are
// not persisted, so the template must survive on its own).
func TestShapeTemplatePersistRoundTrip(t *testing.T) {
	ss := NewShapeStore(0)
	for i, v := range []string{"1041", "2072", "3093"} {
		u := mkHTTP(0, "GET /api/item?id="+v+" HTTP/1.1\r\nHost: t\r\n\r\n")
		ss.Observe("svc", []RequestUnit{u}, []RespFeatures{{}}, false, int64(1000+i))
	}
	ss.SynthesizeTemplates(testFlagRe, map[string]bool{})
	id := ss.Shapes("svc")[0].TemplateID
	orig := ss.ShapeTemplate("svc", id)
	if orig == nil {
		t.Fatal("no template to persist")
	}

	// snapshot must carry the marshaled template body.
	var carried bool
	for _, snaps := range ss.snapshot() {
		for _, s := range snaps {
			if s.ShapeID == id && len(s.TemplateBody) > 0 {
				carried = true
			}
		}
	}
	if !carried {
		t.Fatal("snapshot did not carry the template body")
	}

	restored := restoreShapeStore(ss.snapshot(), 0)
	got := restored.ShapeTemplate("svc", id)
	if got == nil {
		t.Fatal("template lost across snapshot/restore")
	}
	if len(got.Slots) != len(orig.Slots) || countVarSegments(got.Segments) != countVarSegments(orig.Segments) {
		t.Errorf("restored template differs: got %d slots / %d vars, want %d / %d",
			len(got.Slots), countVarSegments(got.Segments), len(orig.Slots), countVarSegments(orig.Segments))
	}
}
