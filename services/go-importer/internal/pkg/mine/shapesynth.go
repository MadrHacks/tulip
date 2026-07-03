package mine

import (
	"encoding/json"
	"regexp"
)

// Per-shape REPLAY template synthesis. A shape's stored Drain skeleton (with
// <*>/<TOK>/<ID> masks) is perfect for GROUPING but is not replayable: it has
// thrown away the concrete bytes and does not say which masked positions are a
// flagId to re-fetch vs a random nonce to regenerate. This step gives each shape
// a replay template by aligning its reservoir of raw member samples, reusing the
// EXACT alignment + slot-typing the cluster path uses (synthesize in template.go
// -> Align + extractSlotValues + classifySlotInfo). The result is the same
// {segments:[{const|var}], slots:[{type,charclass,...}]} structure that
// replicator/scaffold.py consumes.

// synthesizeShapeTemplate builds a shape's replay template from its reservoir of
// raw request-unit samples. Each sample is first reduced to its canonical form
// (canonical(): HTTP structural canon, or the raw bytes for the line protocol —
// exactly what the cluster path aligns), then the samples are multiple-aligned
// into Const/Var segments with typed slots. Returns nil below coreQuorum samples
// or when the samples share no structure (never a partial template). This is a
// thin shape-side wrapper over synthesize(); it does NOT reimplement alignment.
func synthesizeShapeTemplate(samples [][]byte, flagRe *regexp.Regexp, flagIDs map[string]bool) *Template {
	if len(samples) < coreQuorum {
		return nil
	}
	canons := make([][]byte, len(samples))
	for i, s := range samples {
		canons[i] = canonical(s)
	}
	return synthesize(canons, flagRe, flagIDs)
}

// SynthesizeTemplates (re)builds the replay template for every shape that has
// reached quorum in its reservoir, stashing it on the shape so the snapshot path
// persists it. It runs purely over the in-memory reservoir (no DB re-fetch),
// aligning each shape's raw samples into typed slots. Existing templates
// are kept when a shape has too few samples or no shared shape, so a transient
// dip never erases a good template. Returns the number of shapes (re)templated.
func (ss *ShapeStore) SynthesizeTemplates(flagRe *regexp.Regexp, flagIDs map[string]bool) int {
	n := 0
	for _, sh := range ss.shards {
		for _, st := range sh.shapes {
			if tpl := synthesizeShapeTemplate(st.samples, flagRe, flagIDs); tpl != nil {
				st.template = tpl
				n++
			}
		}
	}
	return n
}

// ShapeTemplate returns a shape's synthesized replay template, or nil if it has
// not reached quorum / been synthesized yet. Read-only accessor for persistence,
// the cockpit, and tooling (cmd/shapecheck).
func (ss *ShapeStore) ShapeTemplate(service string, id int) *Template {
	sh := ss.shards[service]
	if sh == nil {
		return nil
	}
	if st := sh.shapes[id]; st != nil {
		return st.template
	}
	return nil
}

// templateBody marshals a shape's replay template to its durable jsonb form, or
// nil when the shape has no template yet.
func (st *shapeState) templateBody() []byte {
	if st.template == nil {
		return nil
	}
	body, err := json.Marshal(st.template)
	if err != nil {
		return nil
	}
	return body
}
