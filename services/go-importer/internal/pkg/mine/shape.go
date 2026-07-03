package mine

import (
	"sort"
	"strconv"
	"strings"
)

// Request-unit shape pipeline — stage 5 + grouping views: aggregate request
// units into SHAPES, split shapes by response feature, and build per-flow
// session signatures. Faithful port of stage4_group.py (session sig) and
// stage5_split_annotate.py (split).
//
// DESIGN PRINCIPLE: a Shape is NEUTRAL. There is no "attack" field. A Shape
// carries an OBSERVABLE SIGNAL VECTOR only (flag_present count, flag_in, actors,
// size). Attack/exploit status is earned later by a nop-proof or a human — never
// decided here. flag_present is a SIGNAL (these responses leaked a flag), not a
// verdict (the checker also leaks flags).

// Unit bundles one request unit's derived fields for grouping into shapes.
type Unit struct {
	Svc        string       // service shard (shapes never cross services)
	FlowIdx    int          // index of the owning flow
	UnitIndex  int          // position within the flow
	TemplateID int          // per-request shape id assigned by Drain
	UA         string       // User-Agent annotation (never a clustering token)
	Feats      RespFeatures // response signal vector
	FlagIn     bool         // the owning flow's flag_in signal, carried through
}

// ShapeSignals is a shape's aggregated observable signal vector — no verdict.
type ShapeSignals struct {
	FlagPresent   int            // members whose paired response leaked a flag (SIGNAL)
	FlagIn        int            // members whose flow carried flag_in
	Actors        map[string]int // User-Agent -> member count (annotation only)
	SizeBucketSum int            // summed content_length_bucket (coarse size signal)
}

// Shape is a neutral request template: request units Drain mapped to one
// template, plus the aggregated signal vector.
type Shape struct {
	TemplateID int
	Template   string
	Members    int
	Signals    ShapeSignals
}

// GroupShapes aggregates units by per-request template id into shapes, ordered
// by template id. templates supplies the mined template string per id.
func GroupShapes(units []Unit, templates map[int]string) []Shape {
	byID := map[int]*Shape{}
	for _, u := range units {
		s := byID[u.TemplateID]
		if s == nil {
			s = &Shape{
				TemplateID: u.TemplateID,
				Template:   templates[u.TemplateID],
				Signals:    ShapeSignals{Actors: map[string]int{}},
			}
			byID[u.TemplateID] = s
		}
		s.Members++
		s.Signals.SizeBucketSum += u.Feats.ContentLengthBucket
		if u.Feats.FlagPresent {
			s.Signals.FlagPresent++
		}
		if u.FlagIn {
			s.Signals.FlagIn++
		}
		if u.UA != "" {
			s.Signals.Actors[u.UA]++
		}
	}
	out := make([]Shape, 0, len(byID))
	for _, s := range byID {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TemplateID < out[j].TemplateID })
	return out
}

// SplitKey is the refined shape key that peels exfil off byte-identical benign
// interaction: (template id, flag_present, http_status, content_type).
// flag_present is mandatory and first; content_length_bucket is deliberately
// excluded (it fragments benign variable-size pages) and kept only as an
// annotation on the shape.
type SplitKey struct {
	TemplateID  int
	FlagPresent bool
	HTTPStatus  int
	ContentType string
}

// MakeSplitKey builds the refined key for a unit's shape id and response
// features.
func MakeSplitKey(templateID int, f RespFeatures) SplitKey {
	return SplitKey{
		TemplateID:  templateID,
		FlagPresent: f.FlagPresent,
		HTTPStatus:  f.HTTPStatus,
		ContentType: f.ContentType,
	}
}

// SplitLabel renders a human-readable response suffix ("FLAG|200|application/
// json" / "noflag|line"). flag_present always first.
func SplitLabel(f RespFeatures) string {
	parts := make([]string, 0, 3)
	if f.FlagPresent {
		parts = append(parts, "FLAG")
	} else {
		parts = append(parts, "noflag")
	}
	if f.HTTPStatus != 0 {
		parts = append(parts, strconv.Itoa(f.HTTPStatus))
	}
	if f.ContentType != "" {
		parts = append(parts, f.ContentType)
	}
	return strings.Join(parts, "|")
}

// SessionShape is the ordered sequence of a flow's per-unit shape ids rendered
// as a signature string; group flows by it. Empty flows get "<EMPTY-FLOW>".
func SessionShape(ids []int) string {
	if len(ids) == 0 {
		return "<EMPTY-FLOW>"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ">")
}
