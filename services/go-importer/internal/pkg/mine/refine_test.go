package mine

import (
	"sort"
	"strings"
	"testing"
)

// refinedByTemplate indexes a refined shape list by template for assertions.
func refinedByTemplate(rs []RefinedShape) map[string]RefinedShape {
	m := make(map[string]RefinedShape, len(rs))
	for _, r := range rs {
		m[r.Template] = r
	}
	return m
}

// TestRefineLowCardSplitsHighCardStays is the core refinement contract: a <*>
// position that took only a FEW distinct literals (structural: an endpoint name)
// is un-merged into one sub-shape per literal, while a <*> position that took MANY
// distinct literals (a value: an id) stays wildcarded. Both live in the SAME shape
// here — "GET api <*> <*>" where position 2 is the low-card endpoint {boomerang,
// user} and position 3 is a high-card id — so the test pins that the refinement
// splits ONLY the structural position and keeps the value collapsed.
func TestRefineLowCardSplitsHighCardStays(t *testing.T) {
	st := &shapeState{
		shape: Shape{TemplateID: 7, Template: "GET api <*> <*>", Signals: ShapeSignals{Actors: map[string]int{}}},
	}
	// Position 2 (endpoint) takes 2 distinct literals => structural (<= K=4).
	// Position 3 (id) takes 10 distinct literals => value (> K=4), stays <*>.
	add := func(endpoint, id string, members, flag int) {
		st.variants = ensureVariants(st.variants)
		v := &variantAgg{members: members, flagPresent: flag, actors: map[string]int{}}
		st.variants["GET api "+endpoint+" "+id] = v
		st.shape.Members += members
		st.shape.Signals.FlagPresent += flag
	}
	// boomerang: 5 distinct ids (so joint skeletons stay under the variant cap).
	for i := 0; i < 5; i++ {
		add("boomerang", "id"+string(rune('a'+i)), 3, 1) // each leaks a flag
	}
	// user: 5 more distinct ids, no flag.
	for i := 5; i < 10; i++ {
		add("user", "id"+string(rune('a'+i)), 2, 0)
	}

	rs := st.refine(4)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Template < rs[j].Template })
	if len(rs) != 2 {
		t.Fatalf("refine produced %d shapes, want 2 (split on the low-card endpoint only): %+v", len(rs), rs)
	}
	byT := refinedByTemplate(rs)

	boom, ok := byT["GET api boomerang <*>"]
	if !ok {
		t.Fatalf("missing boomerang sub-shape; got templates %v", templatesOf(rs))
	}
	// The high-card id position stayed collapsed to <*> (NOT split into 5 shapes).
	if strings.Count(boom.Template, "<*>") != 1 {
		t.Errorf("boomerang template %q should keep exactly one <*> (the high-card id)", boom.Template)
	}
	if boom.Members != 15 { // 5 ids * 3 members
		t.Errorf("boomerang members = %d, want 15", boom.Members)
	}
	if boom.Signals.FlagPresent != 5 { // the flag_present signal follows the split exactly
		t.Errorf("boomerang flag_present = %d, want 5", boom.Signals.FlagPresent)
	}
	if boom.LowCardWild {
		t.Errorf("boomerang still flagged as having a low-card wildcard: %+v", boom)
	}

	user, ok := byT["GET api user <*>"]
	if !ok {
		t.Fatalf("missing user sub-shape; got templates %v", templatesOf(rs))
	}
	if user.Members != 10 { // 5 ids * 2 members
		t.Errorf("user members = %d, want 10", user.Members)
	}
	if user.Signals.FlagPresent != 0 {
		t.Errorf("user flag_present = %d, want 0", user.Signals.FlagPresent)
	}

	// Split re-aggregation is conservative: members sum back to the parent total.
	if boom.Members+user.Members != st.shape.Members {
		t.Errorf("refined members %d+%d != parent %d", boom.Members, user.Members, st.shape.Members)
	}
}

// TestRefineHighCardOnlyStaysMerged: a single <*> position that is purely a
// high-card value must NOT be split — the shape stays as one, wildcard intact.
func TestRefineHighCardOnlyStaysMerged(t *testing.T) {
	st := &shapeState{
		shape: Shape{TemplateID: 3, Template: "GET flights <*> picture", Signals: ShapeSignals{Actors: map[string]int{}}},
	}
	for i := 0; i < 20; i++ { // 20 distinct ids > K=4 => value
		st.variants = ensureVariants(st.variants)
		st.variants["GET flights id"+string(rune('a'+i))+" picture"] = &variantAgg{members: 1, actors: map[string]int{}}
		st.shape.Members++
	}
	rs := st.refine(4)
	if len(rs) != 1 {
		t.Fatalf("high-card-only shape split into %d, want 1 (stay merged): %v", len(rs), templatesOf(rs))
	}
	if rs[0].Template != "GET flights <*> picture" {
		t.Errorf("template = %q, want the original wildcarded template", rs[0].Template)
	}
}

// TestRefineRecursesIntoSubgroups: a position that is high-card across the whole
// shape but low-card WITHIN one endpoint's sub-group is still resolved, because
// the split recurses. Here "GET api <*> <*>": position 2 = {a,b} (structural),
// position 3 is high-card under "a" (kept <*>) but a single constant "list" under
// "b" (must un-merge).
func TestRefineRecursesIntoSubgroups(t *testing.T) {
	st := &shapeState{
		shape: Shape{TemplateID: 1, Template: "GET api <*> <*>", Signals: ShapeSignals{Actors: map[string]int{}}},
	}
	set := func(sk string) {
		st.variants = ensureVariants(st.variants)
		st.variants[sk] = &variantAgg{members: 1, actors: map[string]int{}}
		st.shape.Members++
	}
	for i := 0; i < 10; i++ { // endpoint "a" with 10 distinct high-card ids
		set("GET api a id" + string(rune('a'+i)))
	}
	set("GET api b list") // endpoint "b" always the constant sub-path "list"

	rs := st.refine(4)
	byT := refinedByTemplate(rs)
	if _, ok := byT["GET api a <*>"]; !ok {
		t.Errorf("endpoint a should keep its high-card id as <*>; got %v", templatesOf(rs))
	}
	if _, ok := byT["GET api b list"]; !ok {
		t.Errorf("endpoint b should be fully resolved to a constant; got %v", templatesOf(rs))
	}
}

// TestRefineVariantOverflowStaysMerged: once a shape exceeds the variant cap it is
// left merged (the reservoir is freed), reported via OverflowShapes, and refine
// falls back to the parent aggregate.
func TestRefineVariantOverflowStaysMerged(t *testing.T) {
	ss := NewShapeStore(0)
	ss.SetSplitParams(4, 8) // tiny variant cap to force overflow
	// 20 structurally distinct skeletons on one endpoint pattern; > cap 8.
	for i := 0; i < 20; i++ {
		raw := "GET /api/thing/w" + string(rune('a'+i)) + "z HTTP/1.1\r\nHost: t\r\n\r\n"
		ss.Observe("svc", []RequestUnit{mkHTTP(0, raw)}, []RespFeatures{{}}, false, 8080, int64(i))
	}
	if ss.OverflowShapes("svc") == 0 {
		t.Errorf("expected at least one overflowed shape at variant cap 8")
	}
	// A tiny variant cap must never crash or drop the shape: it stays merged.
	rs := ss.RefinedShapes("svc")
	if len(rs) == 0 {
		t.Fatalf("refined shapes empty after overflow")
	}
}

// TestRefinedShapesEndToEnd exercises the store path: two same-endpoint requests
// and a third on a different endpoint under one Drain shape get un-merged.
func TestRefinedShapesEndToEnd(t *testing.T) {
	ss := NewShapeStore(0)
	// All three share the skeleton token count and prefix, so Drain merges the
	// endpoint position to <*>: "GET api <*> ?id".
	ss.Observe("svc", []RequestUnit{
		mkHTTP(0, "GET /api/boomerang?id=1 HTTP/1.1\r\nHost: t\r\n\r\n"),
		mkHTTP(1, "GET /api/boomerang?id=2 HTTP/1.1\r\nHost: t\r\n\r\n"),
		mkHTTP(2, "GET /api/user?id=3 HTTP/1.1\r\nHost: t\r\n\r\n"),
	}, []RespFeatures{{FlagPresent: true}, {FlagPresent: true}, {}}, false, 8080, 1)

	if got := ss.ShapeCount("svc"); got != 1 {
		t.Fatalf("Drain shapes = %d, want 1 (endpoint merged to <*>)", got)
	}
	rs := ss.RefinedShapes("svc")
	byT := refinedByTemplate(rs)
	if _, ok := byT["GET api boomerang ?id"]; !ok {
		t.Errorf("expected a refined boomerang shape; got %v", templatesOf(rs))
	}
	if _, ok := byT["GET api user ?id"]; !ok {
		t.Errorf("expected a refined user shape; got %v", templatesOf(rs))
	}
	if boom := byT["GET api boomerang ?id"]; boom.Signals.FlagPresent != 2 || boom.Members != 2 {
		t.Errorf("boomerang refined shape = members %d flag %d, want 2/2", boom.Members, boom.Signals.FlagPresent)
	}
}

// TestRemaskTemplateUndermergeProbe: two templates that differ only in a value
// position (an id that slipped through masking) collapse under RemaskTemplate,
// while genuinely different endpoints do not.
func TestRemaskTemplateUndermergeProbe(t *testing.T) {
	if a, b := RemaskTemplate("GET flights 12345 picture"), RemaskTemplate("GET flights 67890 picture"); a != b {
		t.Errorf("numeric-id fragments should re-mask identical: %q vs %q", a, b)
	}
	if a, b := RemaskTemplate("GET api boomerang ?id"), RemaskTemplate("GET api user ?id"); a == b {
		t.Errorf("distinct endpoints must NOT re-mask identical: both %q", a)
	}
	// Existing placeholders and query/body shapes are preserved verbatim.
	if got := RemaskTemplate("POST api club <*> ?id,user"); got != "POST api club <*> ?id,user" {
		t.Errorf("placeholders/query-sets should be preserved: %q", got)
	}
}

// ensureVariants is a tiny test helper: allocate the variant map on first use.
func ensureVariants(m map[string]*variantAgg) map[string]*variantAgg {
	if m == nil {
		return map[string]*variantAgg{}
	}
	return m
}

// templatesOf lists the templates of a refined-shape slice for diagnostics and
// the crispness harness.
func templatesOf(rs []RefinedShape) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Template
	}
	return out
}
