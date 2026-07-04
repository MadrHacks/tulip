package mine

import (
	"sort"
	"strings"
)

// Request-unit shape pipeline — CARDINALITY REFINEMENT. Drain (drain.go) merges
// every position that VARIES across a template's members into a <*> wildcard.
// That single rule cannot tell a STRUCTURAL position (an opcode / verb / endpoint
// name — a handful of distinct literals) apart from a VALUE position (an id /
// token / timestamp — effectively unbounded distinct literals): both "vary", so
// both collapse to <*>. The result over-merges genuinely different interactions
// onto one shape (the boomthrow "GET api <*> ?id" defect merges the /boomerang
// IDOR with /user and /club).
//
// The fix is a cheap, PROTOCOL-AGNOSTIC observation: look at the DISTINCT literal
// values a <*> position actually took across the shape's members.
//   - LOW cardinality (<= splitCard distinct) => the position is STRUCTURAL; it
//     enumerates a small alphabet (an opcode / an endpoint name / a query-key set).
//     Un-merge: split the shape into one sub-shape per literal.
//   - HIGH cardinality (>  splitCard distinct) => the position is a VALUE; keep it
//     wildcarded (stay merged) — this is the same collapse the value-masking in
//     skeleton.go already performs, now backstopped for whatever slipped through.
//
// It makes NO protocol assumptions: it reads only the per-position literal
// alphabet, so it works identically for line-protocol opcodes, HTTP path
// segments, HTTP query-key sets, and binary opcodes. Masking runs FIRST (in
// NormalizeUnit, before Drain), and this refinement composes on top of the mined
// template — mask, then refine.
//
// The refinement is RECURSIVE over positions: after splitting on the low-card
// positions, each sub-group is re-examined, so a position that is high-card
// across the whole shape but low-card WITHIN one endpoint's sub-group is caught
// too. Termination is trivial: every recursion un-wildcards >= 1 position, so the
// wildcard count strictly decreases.
//
// This is a READ-SIDE derived view: it never mutates the Drain shape ids (which
// stay stable for tags/persistence). A shape keeps a bounded reservoir of its
// members' distinct skeletons (the variant map) so the per-position literal
// alphabet can be recovered without a DB re-fetch.

const (
	defaultSplitCard       = 4  // <= this many distinct literals at a <*> position => STRUCTURAL (split)
	defaultSplitVariantCap = 64 // per-shape cap on distinct member skeletons tracked for refinement
)

// variantAgg is the aggregated signal vector of one distinct member skeleton
// within a shape (the refinement reservoir's value). Keyed by the exact skeleton
// string, it is what lets the refinement recover the literal each <*> position
// took and re-aggregate a split sub-shape's signals exactly.
type variantAgg struct {
	members       int
	flagPresent   int
	flagIn        int
	sizeBucketSum int
	actors        map[string]int
}

// observeVariant folds one member into the shape's refinement reservoir, keyed by
// its full skeleton. The reservoir is bounded at cap distinct skeletons: a shape
// dominated by a high-card value position would otherwise mint one variant per
// value. On overflow the shape is marked and its reservoir freed — refinement
// then leaves it as-is (a high-card value dominates, so keeping it merged is the
// correct outcome anyway). Members already counted on the parent shape must be
// mirrored here for the split re-aggregation to be exact.
func (st *shapeState) observeVariant(skeleton string, f RespFeatures, flagIn bool, ua string, cap int) {
	if st.overflowed {
		return
	}
	if cap <= 0 {
		cap = defaultSplitVariantCap
	}
	v := st.variants[skeleton]
	if v == nil {
		if len(st.variants) >= cap {
			st.overflowed = true
			st.variants = nil // free the reservoir; this shape stays merged
			return
		}
		if st.variants == nil {
			st.variants = map[string]*variantAgg{}
		}
		v = &variantAgg{actors: map[string]int{}}
		st.variants[skeleton] = v
	}
	v.members++
	if f.FlagPresent {
		v.flagPresent++
	}
	if flagIn {
		v.flagIn++
	}
	v.sizeBucketSum += f.ContentLengthBucket
	if ua != "" {
		v.actors[ua]++
	}
}

// RefinedShape is a shape after cardinality refinement: one true interaction-kind.
// It is derived from a Drain shape (ParentID) by un-merging its low-cardinality
// (structural) wildcard positions back to their literals while leaving high-
// cardinality (value) positions wildcarded. Like Shape it is NEUTRAL — signals
// only, no verdict.
type RefinedShape struct {
	ParentID    int          // the Drain shape id this was refined from
	Template    string       // refined template (structural positions un-wildcarded)
	Members     int          // members that fell into this sub-shape
	Signals     ShapeSignals // re-aggregated over this sub-shape's members
	Split       bool         // true when the parent split into >1 sub-shape
	LowCardWild bool         // a <*> still sits on a low-card position (residual over-merge)
}

// refineItem pairs a member skeleton's tokens with its aggregated signals for the
// recursive split.
type refineItem struct {
	toks []string
	agg  *variantAgg
}

// refine produces the parent shape's refined sub-shapes. A shape with no reservoir
// (restored, not yet re-observed) or one that overflowed is returned unrefined.
func (st *shapeState) refine(splitCard int) []RefinedShape {
	if splitCard <= 0 {
		splitCard = defaultSplitCard
	}
	tmplTokens := strings.Fields(st.shape.Template)
	if st.overflowed || len(st.variants) == 0 || len(tmplTokens) == 0 {
		return []RefinedShape{st.unrefined(st.shape.Template)}
	}
	items := make([]refineItem, 0, len(st.variants))
	for sk, agg := range st.variants {
		toks := strings.Fields(sk)
		if len(toks) != len(tmplTokens) {
			// Drain groups by token count, so this should not happen; bail safe.
			return []RefinedShape{st.unrefined(st.shape.Template)}
		}
		items = append(items, refineItem{toks: toks, agg: agg})
	}
	var out []RefinedShape
	refineRec(st.shape.TemplateID, tmplTokens, items, splitCard, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Template < out[j].Template })
	split := len(out) > 1
	for i := range out {
		out[i].Split = split
	}
	return out
}

// refineRec splits items on every low-cardinality wildcard position, then recurses
// on each resulting group so positions that only become low-card within a sub-
// group are caught too. When no wildcard position is low-card, the group is a
// crisp interaction-kind and is emitted.
func refineRec(parentID int, tmplTokens []string, items []refineItem, splitCard int, out *[]RefinedShape) {
	structural := structuralPositions(tmplTokens, items, splitCard)
	if len(structural) == 0 {
		*out = append(*out, aggregateRefined(parentID, tmplTokens, items, splitCard))
		return
	}
	groups := map[string][]refineItem{}
	tmpls := map[string][]string{}
	order := []string{}
	for _, it := range items {
		nt := append([]string(nil), tmplTokens...)
		for _, p := range structural {
			nt[p] = it.toks[p]
		}
		key := strings.Join(nt, " ")
		if _, ok := groups[key]; !ok {
			tmpls[key] = nt
			order = append(order, key)
		}
		groups[key] = append(groups[key], it)
	}
	sort.Strings(order)
	for _, key := range order {
		refineRec(parentID, tmpls[key], groups[key], splitCard, out)
	}
}

// structuralPositions returns the wildcard positions whose distinct-literal
// cardinality over items is <= splitCard (structural), i.e. the positions to
// un-merge. Counting stops at splitCard+1 per position, so it is O(items) and
// bounded regardless of how high a value position's true cardinality is.
func structuralPositions(tmplTokens []string, items []refineItem, splitCard int) []int {
	var structural []int
	for i, t := range tmplTokens {
		if t != drainParamStr {
			continue
		}
		seen := map[string]struct{}{}
		low := true
		for _, it := range items {
			seen[it.toks[i]] = struct{}{}
			if len(seen) > splitCard {
				low = false
				break
			}
		}
		if low && len(seen) >= 1 {
			structural = append(structural, i)
		}
	}
	return structural
}

// aggregateRefined sums a leaf group's members into one RefinedShape and records
// whether any wildcard position is still low-card (LowCardWild) as an honest
// residual-over-merge check — at a proper base case this is always false.
func aggregateRefined(parentID int, tmplTokens []string, items []refineItem, splitCard int) RefinedShape {
	r := RefinedShape{
		ParentID: parentID,
		Template: strings.Join(tmplTokens, " "),
		Signals:  ShapeSignals{Actors: map[string]int{}},
	}
	for _, it := range items {
		r.Members += it.agg.members
		r.Signals.FlagPresent += it.agg.flagPresent
		r.Signals.FlagIn += it.agg.flagIn
		r.Signals.SizeBucketSum += it.agg.sizeBucketSum
		for a, c := range it.agg.actors {
			r.Signals.Actors[a] += c
		}
	}
	r.LowCardWild = len(structuralPositions(tmplTokens, items, splitCard)) > 0
	return r
}

// unrefined wraps the parent shape's own template and aggregate as a single
// RefinedShape (used when the shape has no reservoir or overflowed).
func (st *shapeState) unrefined(tmpl string) RefinedShape {
	s := st.shape
	return RefinedShape{
		ParentID: s.TemplateID,
		Template: tmpl,
		Members:  s.Members,
		Signals: ShapeSignals{
			FlagPresent:   s.Signals.FlagPresent,
			FlagIn:        s.Signals.FlagIn,
			SizeBucketSum: s.Signals.SizeBucketSum,
			Actors:        copyActors(s.Signals.Actors),
		},
	}
}

// RefinedShapes returns a service shard's shapes after cardinality refinement,
// ordered by (parent id, template). It is the crisp, un-merged view of the shard:
// one RefinedShape per true interaction-kind. Derived and read-only — the
// underlying Drain shape ids are untouched.
func (ss *ShapeStore) RefinedShapes(service string) []RefinedShape {
	sh := ss.shards[service]
	if sh == nil {
		return nil
	}
	ids := make([]int, 0, len(sh.shapes))
	for id := range sh.shapes {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var out []RefinedShape
	for _, id := range ids {
		out = append(out, sh.shapes[id].refine(ss.splitCard)...)
	}
	return out
}

// OverflowShapes counts shapes in a shard whose refinement reservoir overflowed
// the per-shape variant cap (a high-card value position dominates them); such
// shapes are left merged. Reported so the cap can be tuned if it ever bites.
func (ss *ShapeStore) OverflowShapes(service string) int {
	sh := ss.shards[service]
	if sh == nil {
		return 0
	}
	n := 0
	for _, st := range sh.shapes {
		if st.overflowed {
			n++
		}
	}
	return n
}

// RemaskTemplate re-applies the SAME value masking that normalization (skeleton.go)
// uses to every literal token of a mined/refined template, leaving existing
// placeholders (<*>, <ID>, <TOK>, ...), query-key sets (?a,b) and body shapes
// (json{...}) untouched. It is the crispness harness's UNDER-merge probe: two
// DISTINCT refined templates that collapse to the same RemaskTemplate string
// differ only in a position masking itself considers a value — i.e. a
// fragmentation that should have stayed merged.
//
// It is deliberately FAITHFUL (maskToken's thresholds), not more aggressive: the
// line-protocol opcode selector ("OP2") is a small-int STRUCTURAL slot that
// masking keeps (digits mask only at len >= 3), so distinct opcodes never
// collapse into a false under-merge. An "OP" prefix is preserved so only the
// opcode's tail is re-masked.
func RemaskTemplate(tmpl string) string {
	toks := strings.Fields(tmpl)
	for i, t := range toks {
		toks[i] = remaskToken(t)
	}
	return strings.Join(toks, " ")
}

func remaskToken(tok string) string {
	switch {
	case tok == "" || tok == drainParamStr:
		return tok
	case strings.HasPrefix(tok, "<"): // existing placeholder: <ID> <TOK> <NUM> <FLAG> ...
		return tok
	case strings.HasPrefix(tok, "?"): // query-key set
		return tok
	case strings.HasPrefix(tok, "json{"), strings.HasPrefix(tok, "form{"):
		return tok
	case strings.HasPrefix(tok, "OP"): // line-protocol opcode slot: re-mask only the tail
		return "OP" + maskToken(tok[2:])
	}
	return maskToken(tok)
}
