package mine

import (
	"bytes"
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

// TestReproBoomthrowClassification pins the per-slot classification. turn0 =
// username + password RANDOM, full_name random remnant RANDOM, and — after the
// sub-carve — the full_name tail becomes a FLAGID sub-slot (the victim boomerang
// id the attacker embedded as random + \x01 + <flagId>). turn1 = 2 SELFREF,
// turn2 = FLAGID + MIRROR.
func TestReproBoomthrowClassification(t *testing.T) {
	flows := loadReproFixtures(t)["boomthrow"]
	prog := analyseShape(flows, "boomthrow", 8080, avFlagRe)
	if !prog.ok || prog.structural {
		t.Fatalf("analyse failed: %s", prog.buildFail)
	}
	want := map[[2]int]string{
		{0, 0}: "RANDOM", {0, 1}: "RANDOM", {0, 2}: "RANDOM", {0, 3}: "FLAGID",
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

// TestReproBoomthrowFullNameSubCarve pins the sub-carve: the register full_name
// field, one aligned RANDOM slot before the fix, must split into a RANDOM remnant
// + a CONST (the \\u0001 separator, preserved faithfully) + a FLAGID sub-slot
// carrying the victim boomerang id. The plan stays reproducible and the register
// step reconstructs the captured bytes verbatim (no orphaned JSON backslash).
func TestReproBoomthrowFullNameSubCarve(t *testing.T) {
	flows := loadReproFixtures(t)["boomthrow"]
	prog := analyseShape(flows, "boomthrow", 8080, avFlagRe)
	if !prog.ok || prog.structural {
		t.Fatalf("analyse failed: %s", prog.buildFail)
	}
	plan := emitPlan(prog, "boomthrow", 8080)
	if plan.Unreproducible {
		t.Fatalf("boomthrow gated unexpectedly: %s", plan.Reason)
	}
	reg := plan.Steps[0].Template
	kinds := slotKinds(reg)
	if kinds[SlotFlagID] == 0 {
		t.Fatalf("register step carries no FLAGID sub-slot; slots = %v", kinds)
	}
	if kinds[SlotRandom] == 0 {
		t.Errorf("register step lost its RANDOM credentials; slots = %v", kinds)
	}
	// The \u0001 separator between the random name and the flagId must survive as
	// literal const bytes: a JSON escape, so a const segment must carry the whole
	// \u0001 and never orphan the backslash into a regenerated slot.
	var constBytes []byte
	for _, s := range reg.Segments {
		if !s.Var {
			constBytes = append(constBytes, s.Const...)
		}
	}
	if !containsSub(constBytes, []byte(`\u0001`)) {
		t.Errorf("register const bytes do not preserve the backslash-u0001 escape: %q", constBytes)
	}
	// Reconstruct the register turn from the template + the recorded flow-0 slot
	// values: it must be byte-identical to the captured request (proving the escape
	// and the carved boundaries lose nothing).
	row := prog.tables0[0]
	var got []byte
	vk := 0
	for _, s := range reg.Segments {
		if s.Var {
			got = append(got, row[vk]...)
			vk++
			continue
		}
		got = append(got, s.Const...)
	}
	if orig := clientTurns(flows[0])[0]; !bytes.Equal(got, orig) {
		t.Errorf("register reconstruction not byte-identical\n got=%q\nwant=%q", got, orig)
	}
}

// TestMaximalMirrorCoalescesSplitToken pins Fix 2: a long server-issued token the
// token aligner split into fragments around a const delimiter must coalesce into
// ONE maximal-contiguous mirror slot, not two mirror fragments. Here a base64 '/'
// splits the bearer value into [var][const '/'][var]; the maximal-mirror merge
// grows the seed to the whole "<A>/<B>" span (the largest region that is a
// contiguous substring of the prior response) and emits it as one mirror.
func TestMaximalMirrorCoalescesSplitToken(t *testing.T) {
	priors := [][]byte{
		[]byte(`{"session":"AAAAAAAA/BBBBBBBB"}`),
		[]byte(`{"session":"CCCCCCCC/DDDDDDDD"}`),
		[]byte(`{"session":"EEEEEEEE/FFFFFFFF"}`),
	}
	pieces := []piece{
		{cb: []byte("Authorization: Bearer ")},
		{isVar: true, vv: [][]byte{[]byte("AAAAAAAA"), []byte("CCCCCCCC"), []byte("EEEEEEEE")}},
		{cb: []byte("/")},
		{isVar: true, vv: [][]byte{[]byte("BBBBBBBB"), []byte("DDDDDDDD"), []byte("FFFFFFFF")}},
		{cb: []byte("\r\n")},
	}
	out := maximalMirrorMerge(pieces, priors)

	nVar := 0
	var merged piece
	for _, p := range out {
		if p.isVar {
			nVar++
			merged = p
		}
	}
	if nVar != 1 {
		t.Fatalf("token split into %d mirror fragments, want 1 coalesced mirror", nVar)
	}
	if string(merged.vv[0]) != "AAAAAAAA/BBBBBBBB" {
		t.Errorf("merged span = %q, want the whole AAAAAAAA/BBBBBBBB token", merged.vv[0])
	}
	// The coalesced value must validate as a real (identity) mirror against the
	// prior responses, so classification types it as a single MIRROR slot.
	if mir := discoverMirror(merged.vv, priors); mir == nil {
		t.Errorf("coalesced token does not validate as a mirror against the prior responses")
	} else if mir.transform != "identity" {
		t.Errorf("coalesced mirror transform = %q, want identity", mir.transform)
	}
}

// TestMaximalMirrorLeavesWholeMirrorUntouched guards that the merge is a strict
// no-op when a token already mirrors as ONE piece (the boomthrow bearer/gzip blob):
// there is nothing to coalesce, so the piece list is returned unchanged.
func TestMaximalMirrorLeavesWholeMirrorUntouched(t *testing.T) {
	priors := [][]byte{
		[]byte(`{"token":"H4sIblobONEaaaa"}`),
		[]byte(`{"token":"H4sIblobTWObbbb"}`),
	}
	pieces := []piece{
		{cb: []byte("Authorization: Bearer ")},
		{isVar: true, vv: [][]byte{[]byte("H4sIblobONEaaaa"), []byte("H4sIblobTWObbbb")}},
		{cb: []byte("\r\n")},
	}
	out := maximalMirrorMerge(pieces, priors)
	if len(out) != len(pieces) {
		t.Fatalf("whole-mirror piece list changed: %d -> %d pieces", len(pieces), len(out))
	}
}

// TestSubCarveIsolatesOpaqueRemnant pins Fix 3's mechanism: a field carrying a
// reproducible flagId AND an opaque client-encoded blob (<flagId>.<hash>) must
// carve so the flagId is its own sub-slot and the opaque hash is a SEPARATE
// remnant sub-slot. Gating then localizes to the hash sub-slot instead of typing
// (and gating) the whole field COMPUTED, so the rest of the field/session survives.
func TestSubCarveIsolatesOpaqueRemnant(t *testing.T) {
	vals := [][]byte{
		[]byte("fc0e0b73-08e4-4e5e-a997-4527e0fc5548.aa11bb22cc33dd44"),
		[]byte("2233aa44-55bb-66cc-77dd-8899eeff0011.99aa88bb77cc66dd"),
		[]byte("aabbccdd-1122-3344-5566-77889900aabb.1122334455667788"),
	}
	flagResps := [][]byte{
		[]byte(`{"id":"fc0e0b73-08e4-4e5e-a997-4527e0fc5548","flag":"X"}`),
		[]byte(`{"id":"2233aa44-55bb-66cc-77dd-8899eeff0011","flag":"X"}`),
		[]byte(`{"id":"aabbccdd-1122-3344-5566-77889900aabb","flag":"X"}`),
	}
	priors := [][]byte{{}, {}, {}}
	earlier := [][][]byte{nil, nil, nil}
	pieces := carveVarPiece(vals, flagResps, priors, earlier)
	if pieces == nil {
		t.Fatalf("carve did not fire on <flagId>.<hash>")
	}
	flagidPiece, remnant := 0, 0
	for _, p := range pieces {
		if !p.isVar {
			continue
		}
		if string(p.vv[0]) == "fc0e0b73-08e4-4e5e-a997-4527e0fc5548" {
			flagidPiece++
		}
		if string(p.vv[0]) == "aa11bb22cc33dd44" {
			remnant++
		}
	}
	if flagidPiece != 1 {
		t.Errorf("flagId not isolated as its own sub-slot; pieces = %d", len(pieces))
	}
	if remnant != 1 {
		t.Errorf("opaque hash remnant not isolated as its own sub-slot; pieces = %d", len(pieces))
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
