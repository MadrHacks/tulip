package mine

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"go-importer/internal/pkg/db"
)

// avFlagRe is the aviation/reference flag matcher ([A-Z0-9]{31}=), so these
// tests classify against genuine on-wire flag responses.
var avFlagRe = regexp.MustCompile(`[A-Z0-9]{31}=`)

// loadReproFixtures decodes testdata/repro_fixtures.json (real aviation flows
// dumped through the reference loaders) into homogeneous shape members.
func loadReproFixtures(t *testing.T) map[string][][]db.Turn {
	t.Helper()
	raw, err := os.ReadFile("testdata/repro_fixtures.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var decoded map[string][][][2]string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal fixtures: %v", err)
	}
	out := map[string][][]db.Turn{}
	for shape, insts := range decoded {
		for _, inst := range insts {
			turns := make([]db.Turn, 0, len(inst))
			for _, tv := range inst {
				data, err := base64.StdEncoding.DecodeString(tv[1])
				if err != nil {
					t.Fatalf("decode turn: %v", err)
				}
				turns = append(turns, db.Turn{FromClient: tv[0] == "C", Data: data})
			}
			out[shape] = append(out[shape], turns)
		}
	}
	return out
}

// TestReproBoomthrowEmitsMirrorLink is the headline case: register -> login ->
// GET /api/boomerang?id. The engine must reproduce it (no gate), carry the
// session Bearer token as a MIRROR link (identity, login-response -> GET), reuse
// the register credentials at login as SELFREF links, and select the flag with a
// FLAGID slot — matching the reference's classification exactly.
func TestReproBoomthrowEmitsMirrorLink(t *testing.T) {
	flows := loadReproFixtures(t)["boomthrow"]
	if len(flows) < 3 {
		t.Fatalf("need >=3 boomthrow fixtures, got %d", len(flows))
	}
	plan := synthesizeInteractivePlan("boomthrow", 8080, flows, avFlagRe)

	if plan.Unreproducible {
		t.Fatalf("boomthrow gated unexpectedly: %s", plan.Reason)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("steps = %d, want 3 (register, login, GET)", len(plan.Steps))
	}

	// A MIRROR link must carry the Bearer token from the login response (step 1)
	// into the GET request (step 2), with identity transform.
	var mirror *InteractiveLink
	selfrefs := 0
	for i := range plan.Links {
		switch plan.Links[i].Kind {
		case "mirror":
			mirror = &plan.Links[i]
		case "selfref":
			selfrefs++
		}
	}
	if mirror == nil {
		t.Fatalf("no MIRROR link emitted; links = %+v", plan.Links)
	}
	if mirror.Transform != "identity" {
		t.Errorf("mirror transform = %q, want identity", mirror.Transform)
	}
	if mirror.ConsumerStep != 2 || mirror.ProducerStep != 1 {
		t.Errorf("mirror producer=%d consumer=%d, want 1 -> 2", mirror.ProducerStep, mirror.ConsumerStep)
	}
	if selfrefs != 2 {
		t.Errorf("selfref links = %d, want 2 (username+password reused at login)", selfrefs)
	}

	// The mirror's extract regex must actually recover the Bearer token from the
	// held-out login response and that token must be what the GET request sent —
	// the DERIVED (not granted) reproduction the reference proves.
	re, err := regexp.Compile(mirror.Extract)
	if err != nil {
		t.Fatalf("mirror extract regex does not compile: %v (%q)", err, mirror.Extract)
	}
	for _, f := range flows {
		loginResp := responsesPaired(f)[1]
		m := re.FindSubmatch(loginResp)
		if m == nil {
			t.Fatalf("mirror extract did not match a login response\nregex=%q", mirror.Extract)
		}
		getReq := clientTurns(f)[2]
		if !containsSub(getReq, []byte("Bearer "+string(m[1]))) {
			t.Fatalf("extracted token %q is not the Bearer value the GET actually sent", m[1])
		}
	}

	// The GET step (2) must carry a FLAGID slot (the id selector) and the MIRROR
	// slot for the Authorization header.
	kinds := slotKinds(plan.Steps[2].Template)
	if kinds[SlotFlagID] == 0 {
		t.Errorf("GET step slots = %v, want a flagid selector", kinds)
	}
	if kinds[SlotMirror] == 0 {
		t.Errorf("GET step slots = %v, want a mirror (Bearer token)", kinds)
	}
	// The register step (0) must be pure RANDOM credentials.
	if k := slotKinds(plan.Steps[0].Template); k[SlotRandom] == 0 {
		t.Errorf("register step slots = %v, want RANDOM credentials", k)
	}
}

// TestReproCryptoGates asserts a required COMPUTED (crypto) slot GATES the plan:
// GET /api/qr?id&sig carries a server-signed hash we cannot forge, so the engine
// must mark the plan Unreproducible with a crypto reason and emit NO steps.
func TestReproCryptoGates(t *testing.T) {
	flows := loadReproFixtures(t)["crypto_qr"]
	if len(flows) < 3 {
		t.Fatalf("need >=3 crypto fixtures, got %d", len(flows))
	}
	plan := synthesizeInteractivePlan("boomthrow", 8080, flows, avFlagRe)

	if !plan.Unreproducible {
		t.Fatalf("crypto qr was NOT gated; plan = %+v", plan)
	}
	if !containsSub([]byte(plan.Reason), []byte("COMPUTED")) {
		t.Errorf("gate reason = %q, want a COMPUTED-required-slot reason", plan.Reason)
	}
	if !containsSub([]byte(plan.Reason), []byte("crypto")) {
		t.Errorf("gate reason = %q, want it to name the crypto slot", plan.Reason)
	}
	if len(plan.Steps) != 0 {
		t.Errorf("gated plan emitted %d steps, want 0 (never a broken plan)", len(plan.Steps))
	}
}

// TestReproBoomthrowClassification pins the per-slot classification to the
// reference: turn0 = 4 RANDOM, turn1 = 2 SELFREF, turn2 = FLAGID + MIRROR.
func TestReproBoomthrowClassification(t *testing.T) {
	flows := loadReproFixtures(t)["boomthrow"]
	prog := analyseShape(flows, "boomthrow", 8080, avFlagRe)
	if !prog.ok || prog.structural {
		t.Fatalf("analyse failed: %s", prog.buildFail)
	}
	want := map[[2]int]string{
		{0, 0}: "RANDOM", {0, 1}: "RANDOM", {0, 2}: "RANDOM", {0, 3}: "RANDOM",
		{1, 0}: "SELFREF", {1, 1}: "SELFREF",
		{2, 0}: "FLAGID", {2, 1}: "MIRROR",
	}
	for sv, kind := range want {
		got := prog.classes[sv]
		if got == nil || got.kind != kind {
			t.Errorf("slot %v = %v, want %s", sv, kindOf(got), kind)
		}
	}
	if prog.rti != 2 {
		t.Errorf("retrieval turn = %d, want 2", prog.rti)
	}
	if len(prog.required) != 3 {
		t.Errorf("required turns = %v, want all three", prog.required)
	}
	// The MIRROR must name the login turn (1) as its source, identity transform.
	mir := prog.classes[[2]int{2, 1}]
	if mir.kind == "MIRROR" && (mir.transform != "identity" || mir.sourceTurn != 1) {
		t.Errorf("mirror transform=%q source=%d, want identity from turn 1", mir.transform, mir.sourceTurn)
	}
}

func slotKinds(tpl Template) map[SlotType]int {
	m := map[SlotType]int{}
	for _, s := range tpl.Slots {
		m[s.Type]++
	}
	return m
}

func kindOf(c *slotClass) string {
	if c == nil {
		return "<nil>"
	}
	return c.kind
}

func containsSub(hay, needle []byte) bool {
	return len(needle) == 0 || indexFrom(hay, needle, 0) >= 0
}
