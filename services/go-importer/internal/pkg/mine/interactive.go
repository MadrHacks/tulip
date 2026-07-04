package mine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"go-importer/internal/pkg/db"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InteractiveStep is one turn of a replayed session: the client request as a
// fillable template plus the server prompt to read until before the next step
// (nil -> read whatever is available). Exactly the shape the replicator's
// interactive_replay consumes.
type InteractiveStep struct {
	Template Template `json:"template"`
	Expect   *string  `json:"expect"`
}

// InteractiveLink carries a value into a later step's slot. Two kinds, ported
// from the reference engine:
//
//   - "mirror": extract a value from an earlier step's RESPONSE (Extract's
//     capture group 1) and inject it into ConsumerStep's InjectSlot. Transform
//     names the decode applied to the captured representation (identity for the
//     genuine aviation exfil attacks; base64/hex/url otherwise).
//   - "selfref": copy an earlier step's own SENT slot value (ProducerStep's
//     ProducerSlot) into ConsumerStep's InjectSlot — e.g. register credentials
//     reused at login. Extract is empty for selfref links.
type InteractiveLink struct {
	Kind         string `json:"kind,omitempty"` // "mirror" | "selfref" (empty = mirror, legacy)
	ProducerStep int    `json:"producer_step"`
	ConsumerStep int    `json:"consumer_step"`
	Extract      string `json:"extract"`
	InjectSlot   int    `json:"inject_slot"`
	Transform    string `json:"transform,omitempty"`     // mirror decode transform
	ProducerSlot int    `json:"producer_slot,omitempty"` // selfref: source client slot ordinal
}

// InteractivePlan is a runnable stateful single-connection exploit: an ordered
// list of client sends, each with the server prompt to await after it, driven
// on one persistent connection, plus the Links that carry derived values between
// steps. When a required slot is COMPUTED (crypto/session token) or the service
// is TLS/WS/opaque or the flag never appears in cleartext, the plan is marked
// Unreproducible with a Reason and carries NO steps — it is recorded (so the
// gate decision is durable) but never fanned out as a broken plan.
type InteractivePlan struct {
	Service        string            `json:"service"`
	Port           int               `json:"port"`
	Steps          []InteractiveStep `json:"steps"`
	Links          []InteractiveLink `json:"links"`
	Unreproducible bool              `json:"unreproducible,omitempty"`
	Reason         string            `json:"reason,omitempty"`
}

// synthesizeInteractive builds a runnable plan from a flow's conversation turns.
// Each CLIENT turn, in order, becomes one step: its template splits the client
// bytes on flagId matches (via e.fidRe), and its expect marker is the pending
// prompt of the immediately following server turn. Links are empty in v1.
func (e *Engine) synthesizeInteractive(service string, port int, turns []db.Turn) InteractivePlan {
	steps := make([]InteractiveStep, 0, len(turns))
	for i, turn := range turns {
		if !turn.FromClient {
			continue
		}
		steps = append(steps, InteractiveStep{
			Template: e.interactiveTemplate(turn.Data),
			Expect:   pendingPrompt(turns, i),
		})
	}
	return InteractivePlan{
		Service: service,
		Port:    port,
		Steps:   steps,
		Links:   []InteractiveLink{},
	}
}

// interactiveTemplate turns one client turn's bytes into a template: each flagId
// occurrence (located by the engine's precompiled fidRe) becomes a {"var":true}
// segment paired with a {"type":"flagid"} slot, and the literal runs between and
// around them become base64 {"const"} segments. With no fidRe or no match the
// whole turn is a single const segment and no slots. Segments/slots are always
// non-nil so they marshal to [] (never null) for the replicator.
func (e *Engine) interactiveTemplate(data []byte) Template {
	segs := []Segment{}
	slots := []Slot{}
	pos := 0
	if e.fidRe != nil {
		for _, m := range e.fidRe.FindAllIndex(data, -1) {
			start, end := m[0], m[1]
			if start > pos {
				segs = append(segs, Segment{Const: append([]byte(nil), data[pos:start]...)})
			}
			segs = append(segs, Segment{Var: true})
			slots = append(slots, Slot{Type: SlotFlagID})
			pos = end
		}
	}
	if pos < len(data) {
		segs = append(segs, Segment{Const: append([]byte(nil), data[pos:]...)})
	}
	return Template{Segments: segs, Slots: slots}
}

// pendingPrompt derives a step's expect marker from the server turn immediately
// following client turn i: the text after that turn's LAST newline (the prompt
// left waiting for input), with trailing spaces trimmed. Returns nil when there
// is no following server turn or the prompt is empty, so the replayer then reads
// whatever is available.
func pendingPrompt(turns []db.Turn, i int) *string {
	if i+1 >= len(turns) || turns[i+1].FromClient {
		return nil
	}
	// promptMarker (reprosynth.go) takes the text after the last newline and
	// strips trailing spaces + NUL bytes (jsonb cannot store NULs, and a binary-
	// protocol prompt may carry them); nil when nothing meaningful remains.
	return promptMarker(turns[i+1].Data)
}

// maybeSynthInteractiveShape attempts, at most once per shape (guarded by
// e.shapeInteractiveSynthed), to build the shape's interactive reproduction plan
// from its flag-leaking members tagged shape:<svc>:<id> and persist it to
// mine.shape_interactive. A shape carrying the flag_present SIGNAL is just a
// candidate SOURCE here; the replicator's NOP-proof stays the sole arbiter of
// whether it is a real exploit.
func (e *Engine) maybeSynthInteractiveShape(ctx context.Context, service string, id int64, port int) {
	key := fmt.Sprintf("%s:%d", service, id)
	if e.shapeInteractiveSynthed[key] {
		return
	}
	e.shapeInteractiveSynthed[key] = true

	plan := e.buildShapeInteractivePlan(ctx, service, fmt.Sprintf("shape:%s:%d", service, id), port)
	if plan == nil {
		return
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		log.Println("minecore: marshal interactive plan:", err)
		return
	}
	saveShapeInteractiveTemplate(ctx, e.db.Pool(), service, id, port, encoded,
		!plan.Unreproducible, plan.Reason)
}

// buildShapeInteractivePlan fetches the shape's flag-leaking members and runs the
// reproduction engine over them. With enough homogeneous members (>= coreQuorum)
// it ports the full reference pipeline — token-level alignment, typed-slot
// classification (FLAGID/MIRROR/SELFREF/RANDOM/LENGTH/COMPUTED), dependency
// minimization, and gating — emitting a plan with carried-value Links (or an
// Unreproducible plan with a reason when a required slot is COMPUTED or the
// service is opaque). Below quorum it falls back to the single-flow flagId-split
// template (no links) for genuinely multi-turn sessions. Returns nil when there
// is nothing to synthesize.
func (e *Engine) buildShapeInteractivePlan(ctx context.Context, service, tag string, port int) *InteractivePlan {
	ids, err := e.db.ShapeFlowIDs(tag, reproAlignSample)
	if err != nil || len(ids) == 0 {
		return nil
	}
	flows := make([][]db.Turn, 0, len(ids))
	for _, id := range ids {
		turns, err := e.db.FlowTurns(id)
		if err != nil {
			continue
		}
		flows = append(flows, turns)
	}
	if len(flows) == 0 {
		return nil
	}
	if len(flows) >= coreQuorum {
		plan := synthesizeInteractivePlan(service, port, flows, e.flagRe)
		return &plan
	}
	// Below quorum: alignment cannot separate const from variable, so fall back to
	// the single-flow flagId-split template — only for a genuinely multi-turn
	// session a single-request template cannot express.
	richest := flows[0]
	clientTurns := 0
	for _, t := range richest {
		if t.FromClient {
			clientTurns++
		}
	}
	if clientTurns < 2 {
		return nil
	}
	plan := e.synthesizeInteractive(service, port, richest)
	return &plan
}

// saveShapeInteractiveTemplate persists a synthesized plan for a shape, keeping
// the first one written for a shape (ON CONFLICT DO NOTHING). Its own table
// (mine.shape_interactive) carries the shape's replay port so the candidate
// reader can key the socket without a separate lookup, plus the reproducible flag
// + gate reason so an Unreproducible (gated) plan is recorded but never fanned
// out as a broken exploit.
func saveShapeInteractiveTemplate(ctx context.Context, pool *pgxpool.Pool, service string, id int64, port int, plan []byte, reproducible bool, reason string) {
	_, err := pool.Exec(ctx, `
		INSERT INTO mine.shape_interactive (service, shape_id, port, plan, reproducible, reason)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service, shape_id) DO NOTHING
	`, service, id, port, plan, reproducible, reason)
	if err != nil {
		log.Println("minecore: save shape interactive template:", err)
	}
}
