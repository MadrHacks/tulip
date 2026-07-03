package mine

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"go-importer/internal/pkg/db"
)

const testFlagID = "AAAA1111BBBB2222CCCC3333DDDD444"

// engineWithFlagID builds a bare engine whose flagId matcher recognizes the
// given ids — enough to exercise template synthesis without a database.
func engineWithFlagID(ids ...string) *Engine {
	return &Engine{fidRe: buildFlagIDRegex(ids)}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestInteractiveTemplateSplitsOnFlagID(t *testing.T) {
	e := engineWithFlagID(testFlagID)
	tmpl := e.interactiveTemplate([]byte(testFlagID + "\n"))

	// A flagId match becomes a {var} segment + one flagid slot; the trailing "\n"
	// is a const segment. No leading const (the flagId starts at offset 0).
	if len(tmpl.Segments) != 2 {
		t.Fatalf("segments = %+v, want 2 (var, const)", tmpl.Segments)
	}
	if !tmpl.Segments[0].Var {
		t.Errorf("segment 0 = %+v, want var", tmpl.Segments[0])
	}
	if tmpl.Segments[1].Var || string(tmpl.Segments[1].Const) != "\n" {
		t.Errorf("segment 1 = %+v, want const \\n", tmpl.Segments[1])
	}
	if len(tmpl.Slots) != 1 || tmpl.Slots[0].Type != SlotFlagID {
		t.Fatalf("slots = %+v, want one flagid slot", tmpl.Slots)
	}
	// var-segment count must equal slot count (the instantiate contract).
	if got := countVarSegments(tmpl.Segments); got != len(tmpl.Slots) {
		t.Errorf("var segments = %d, slots = %d, must be equal", got, len(tmpl.Slots))
	}
}

func TestInteractiveTemplateFlagIDMidRun(t *testing.T) {
	e := engineWithFlagID(testFlagID)
	tmpl := e.interactiveTemplate([]byte("get " + testFlagID + " now"))

	// Literal runs on both sides of the match become const segments around the var.
	if len(tmpl.Segments) != 3 || string(tmpl.Segments[0].Const) != "get " ||
		!tmpl.Segments[1].Var || string(tmpl.Segments[2].Const) != " now" {
		t.Fatalf("segments = %+v, want [const 'get ', var, const ' now']", tmpl.Segments)
	}
	if len(tmpl.Slots) != 1 || tmpl.Slots[0].Type != SlotFlagID {
		t.Errorf("slots = %+v, want one flagid slot", tmpl.Slots)
	}
}

func TestInteractiveTemplateNoFlagID(t *testing.T) {
	e := engineWithFlagID(testFlagID)
	tmpl := e.interactiveTemplate([]byte("readflag\n"))

	// No flagId in the turn: a single const segment, no slots.
	if len(tmpl.Segments) != 1 || tmpl.Segments[0].Var || string(tmpl.Segments[0].Const) != "readflag\n" {
		t.Fatalf("segments = %+v, want single const 'readflag\\n'", tmpl.Segments)
	}
	if len(tmpl.Slots) != 0 {
		t.Errorf("slots = %+v, want none", tmpl.Slots)
	}
}

func TestInteractiveTemplateNilFidRe(t *testing.T) {
	// With no live flagIds (fidRe nil) even a flagId-looking run is plain const.
	e := &Engine{fidRe: nil}
	tmpl := e.interactiveTemplate([]byte(testFlagID))
	if len(tmpl.Segments) != 1 || tmpl.Segments[0].Var || len(tmpl.Slots) != 0 {
		t.Fatalf("segments=%+v slots=%+v, want single const and no slots", tmpl.Segments, tmpl.Slots)
	}
}

func TestPendingPromptExtraction(t *testing.T) {
	turns := []db.Turn{
		{FromClient: true, Data: []byte("signup\n")},
		{FromClient: false, Data: []byte("Welcome\nUsername: ")},
	}
	got := pendingPrompt(turns, 0)
	if got == nil || *got != "Username:" {
		t.Fatalf("pendingPrompt = %v, want 'Username:' (after last newline, trailing space trimmed)", got)
	}
}

func TestPendingPromptNilWhenNoServerFollows(t *testing.T) {
	turns := []db.Turn{
		{FromClient: true, Data: []byte("a\n")},
		{FromClient: true, Data: []byte("b\n")}, // next turn is client, not server
	}
	if got := pendingPrompt(turns, 0); got != nil {
		t.Errorf("pendingPrompt = %v, want nil (no following server turn)", got)
	}
	if got := pendingPrompt(turns, 1); got != nil {
		t.Errorf("pendingPrompt at last turn = %v, want nil", got)
	}
}

func TestPendingPromptNilWhenEmpty(t *testing.T) {
	// A server turn that is only a newline (or trailing spaces) yields no prompt.
	turns := []db.Turn{
		{FromClient: true, Data: []byte("x\n")},
		{FromClient: false, Data: []byte("banner\n")},
	}
	if got := pendingPrompt(turns, 0); got != nil {
		t.Errorf("pendingPrompt = %v, want nil (empty after last newline)", got)
	}
}

// TestSynthesizeInteractiveThreeClientTurns is the end-to-end shape check for the
// reported example: signup / flagId / readflag with prompts between.
func TestSynthesizeInteractiveThreeClientTurns(t *testing.T) {
	e := engineWithFlagID(testFlagID)
	turns := []db.Turn{
		{FromClient: true, Data: []byte("signup\n")},
		{FromClient: false, Data: []byte("Username: ")},
		{FromClient: true, Data: []byte(testFlagID + "\n")},
		{FromClient: false, Data: []byte("> ")},
		{FromClient: true, Data: []byte("readflag\n")},
		{FromClient: false, Data: []byte("FLAG{x}")},
	}
	plan := e.synthesizeInteractive("menu", 1337, turns)

	if plan.Service != "menu" || plan.Port != 1337 {
		t.Errorf("plan endpoint = %s:%d, want menu:1337", plan.Service, plan.Port)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("steps = %d, want 3 (one per client turn)", len(plan.Steps))
	}
	if plan.Links == nil || len(plan.Links) != 0 {
		t.Errorf("links = %+v, want empty non-nil", plan.Links)
	}

	// Step 0: const "signup\n", expect "Username:".
	assertExpect(t, 0, plan.Steps[0].Expect, "Username:")
	if len(plan.Steps[0].Template.Slots) != 0 {
		t.Errorf("step 0 slots = %+v, want none", plan.Steps[0].Template.Slots)
	}
	// Step 1: flagId var + "\n" const, one flagid slot, expect ">".
	assertExpect(t, 1, plan.Steps[1].Expect, ">")
	if len(plan.Steps[1].Template.Slots) != 1 || plan.Steps[1].Template.Slots[0].Type != SlotFlagID {
		t.Errorf("step 1 slots = %+v, want one flagid slot", plan.Steps[1].Template.Slots)
	}
	// Step 2: const "readflag\n", expect the (verbatim) flag response "FLAG{x}".
	assertExpect(t, 2, plan.Steps[2].Expect, "FLAG{x}")

	// Marshaled JSON must match the exact shape the replicator consumes.
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// encoding/json HTML-escapes '>' (as the existing chain marshaling does), so
	// derive that exact escaped marker the same way rather than hardcoding it;
	// Postgres jsonb + psycopg normalize it back to '>' downstream.
	gt, _ := json.Marshal(">") // -> the escaped JSON string form of ">"
	want := `{"service":"menu","port":1337,"steps":[` +
		`{"template":{"segments":[{"const":"` + b64("signup\n") + `"}],"slots":[]},"expect":"Username:"},` +
		`{"template":{"segments":[{"var":true},{"const":"` + b64("\n") + `"}],"slots":[{"type":"flagid"}]},"expect":` + string(gt) + `},` +
		`{"template":{"segments":[{"const":"` + b64("readflag\n") + `"}],"slots":[]},"expect":"FLAG{x}"}` +
		`],"links":[]}`
	if string(raw) != want {
		t.Errorf("plan JSON mismatch\n got: %s\nwant: %s", raw, want)
	}
}

func assertExpect(t *testing.T, step int, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Errorf("step %d expect = nil, want %q", step, want)
		return
	}
	if *got != want {
		t.Errorf("step %d expect = %q, want %q", step, *got, want)
	}
}
