package mine

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChainPlanStep is one runnable step: the single-flow request template plus
// where to send it.
type ChainPlanStep struct {
	Template json.RawMessage `json:"template"`
	Service  string          `json:"service"`
	Port     int             `json:"port"`
}

// ChainPlanLink carries a value from a producer step's response into a consumer
// step's request slot. Extract is a regex with one capture group applied to the
// producer response; InjectSlot is the consumer template slot to override.
type ChainPlanLink struct {
	ProducerStep int    `json:"producer_step"`
	ConsumerStep int    `json:"consumer_step"`
	Extract      string `json:"extract"`
	InjectSlot   int    `json:"inject_slot"`
}

// ChainPlan is a runnable multi-step exploit chain: exactly the shape the
// replicator's chain replayer consumes.
type ChainPlan struct {
	Steps []ChainPlanStep `json:"steps"`
	Links []ChainPlanLink `json:"links"`
}

// chainBody is the persisted chain_template body: the reusable pattern always,
// and a runnable plan when every step template and link locator could be
// synthesized.
type chainBody struct {
	Pattern ChainTemplate `json:"pattern"`
	Plan    *ChainPlan    `json:"plan,omitempty"`
}

const extractAnchorMax = 24

// charclassPattern returns the regex character class matching value's alphabet.
func charclassPattern(value []byte) string {
	switch DetectCharclass(value) {
	case ClassHex:
		return "[0-9a-fA-F]"
	case ClassBase64:
		return "[A-Za-z0-9+/=]"
	case ClassBase64URL:
		return "[A-Za-z0-9_-]"
	case ClassUUID:
		return "[0-9a-fA-F-]"
	case ClassJWT:
		return "[A-Za-z0-9._-]"
	case ClassAlnum:
		return "[A-Za-z0-9]"
	default:
		return `\S`
	}
}

// synthesizeExtract builds a regex that recovers value from a producer response:
// the literal run of bytes immediately preceding the value (anchored, capped,
// and not crossing a line break) followed by a capture group over the value's
// charclass. Returns "" if value is absent from the response.
func synthesizeExtract(response, value []byte) string {
	idx := bytes.Index(response, value)
	if idx < 0 {
		return ""
	}
	start := idx
	for start > 0 && response[start-1] != '\n' && response[start-1] != '\r' && idx-start < extractAnchorMax {
		start--
	}
	anchor := regexp.QuoteMeta(string(response[start:idx]))
	return anchor + "(" + charclassPattern(value) + "+)"
}

// findInjectSlot returns the index of the consumer template slot whose value in
// this request equals value, or -1 if none. Slot boundaries are located by the
// template's constant anchors, the same way synthesis extracted them.
func findInjectSlot(template *Template, request, value []byte) int {
	want := bytes.TrimSpace(value)
	for i, v := range extractSlotValues(request, template.Segments) {
		if bytes.Equal(bytes.TrimSpace(v), want) {
			return i
		}
	}
	return -1
}

// parseShapeTag splits a "shape:<service>:<id>" tag into its service and shape
// id. A chain step's identity is the flow's shape tag (see observeChain).
func parseShapeTag(tag string) (string, int64, bool) {
	parts := strings.SplitN(tag, ":", 3)
	if len(parts) != 3 || parts[0] != "shape" {
		return "", 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return parts[1], id, true
}

// loadShapeTemplateBody returns a shape's persisted replay template
// (mine.shape.template_body), or nil when the shape has no template yet (below
// quorum) or the row is absent.
func loadShapeTemplateBody(ctx context.Context, pool *pgxpool.Pool, service string, shapeID int64) json.RawMessage {
	var body json.RawMessage
	err := pool.QueryRow(ctx,
		`SELECT template_body FROM mine.shape WHERE service = $1 AND shape_id = $2`,
		service, shapeID).Scan(&body)
	if err != nil {
		return nil
	}
	return body
}

// lowerChain turns a settled chain into a runnable plan: each step's single-flow
// template (fetched by its shape identity) plus, per link, a regex extracting
// the carried value from the producer's response and the consumer slot to inject
// it into. Returns nil (best effort) if any step template or link locator is
// unavailable; the reusable pattern is persisted regardless.
func (e *Engine) lowerChain(ctx context.Context, sc settledChain) *ChainPlan {
	pool := e.db.Pool()
	steps := make([]ChainPlanStep, len(sc.Template.Steps))
	templates := make([]*Template, len(sc.Template.Steps))
	for i, step := range sc.Template.Steps {
		service, sid, ok := parseShapeTag(step.ClusterID)
		if !ok {
			return nil
		}
		body := loadShapeTemplateBody(ctx, pool, service, sid)
		if body == nil {
			return nil
		}
		steps[i] = ChainPlanStep{Template: body, Service: service, Port: sc.StepPorts[i]}
		var t Template
		if json.Unmarshal(body, &t) == nil {
			templates[i] = &t
		}
	}

	links := make([]ChainPlanLink, len(sc.Template.Links))
	for i, l := range sc.Template.Links {
		value := sc.LinkValues[i]
		ct := templates[l.ConsumerStep]
		if len(value) == 0 || ct == nil {
			return nil
		}
		producer, err := uuid.FromString(sc.StepFlows[l.ProducerStep])
		if err != nil {
			return nil
		}
		response, err := e.db.FlowServerData(producer)
		if err != nil {
			return nil
		}
		extract := synthesizeExtract(response, value)
		if extract == "" {
			return nil
		}
		consumer, err := uuid.FromString(sc.StepFlows[l.ConsumerStep])
		if err != nil {
			return nil
		}
		request, err := e.db.FlowClientData(consumer)
		if err != nil {
			return nil
		}
		slot := findInjectSlot(ct, request, value)
		if slot < 0 {
			return nil
		}
		links[i] = ChainPlanLink{
			ProducerStep: l.ProducerStep,
			ConsumerStep: l.ConsumerStep,
			Extract:      extract,
			InjectSlot:   slot,
		}
	}
	return &ChainPlan{Steps: steps, Links: links}
}
