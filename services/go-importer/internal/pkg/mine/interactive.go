package mine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"go-importer/internal/pkg/db"

	"github.com/gofrs/uuid/v5"
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

// InteractiveLink carries a value from one step's response into a later step's
// slot. v1 never emits links, but the field is modeled so the persisted plan
// shape is stable when carried values arrive.
type InteractiveLink struct {
	ProducerStep int    `json:"producer_step"`
	ConsumerStep int    `json:"consumer_step"`
	Extract      string `json:"extract"`
	InjectSlot   int    `json:"inject_slot"`
}

// InteractivePlan is a runnable stateful single-connection exploit: an ordered
// list of client sends, each with the server prompt to await after it, driven
// on one persistent connection. Links is always [] in v1 (no carried values).
type InteractivePlan struct {
	Service string            `json:"service"`
	Port    int               `json:"port"`
	Steps   []InteractiveStep `json:"steps"`
	Links   []InteractiveLink `json:"links"`
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
	data := turns[i+1].Data
	if idx := bytes.LastIndexByte(data, '\n'); idx >= 0 {
		data = data[idx+1:]
	}
	// Strip NUL bytes: jsonb cannot store them, and a binary-protocol prompt may
	// carry them; they are never a meaningful part of a text prompt marker.
	prompt := strings.ReplaceAll(strings.TrimRight(string(data), " "), "\x00", "")
	if prompt == "" {
		return nil
	}
	return &prompt
}

// maybeSynthInteractiveShape attempts, at most once per shape (guarded by
// e.shapeInteractiveSynthed), it pulls the richest flag-leaking flow tagged
// shape:<svc>:<id> and, when that session is genuinely multi-turn, synthesizes
// and persists its interactive plan to mine.shape_interactive. A shape carrying
// the flag_present SIGNAL is just a candidate SOURCE here; the replicator's
// NOP-proof stays the sole arbiter of whether it is a real exploit.
func (e *Engine) maybeSynthInteractiveShape(ctx context.Context, service string, id int64, port int) {
	key := fmt.Sprintf("%s:%d", service, id)
	if e.shapeInteractiveSynthed[key] {
		return
	}
	e.shapeInteractiveSynthed[key] = true

	if plan := e.richestFlagFlowPlan(ctx, service, fmt.Sprintf("shape:%s:%d", service, id), port); plan != nil {
		saveShapeInteractiveTemplate(ctx, e.db.Pool(), service, id, port, plan)
	}
}

// richestFlagFlowPlan finds the RICHEST flag-leaking flow tagged `tag` (most
// client turns), and — only when that session is genuinely multi-turn (>= 2
// client turns, which a single-flow template cannot express) — synthesizes its
// interactive plan and returns the marshaled JSON. Returns nil when there is no
// such flow, the fetch fails, or the session is single-turn.
func (e *Engine) richestFlagFlowPlan(ctx context.Context, service, tag string, port int) []byte {
	var flowID uuid.UUID
	err := e.db.Pool().QueryRow(ctx,
		`SELECT fi.flow_id
		 FROM flow_item fi JOIN flow f ON f.id = fi.flow_id
		 WHERE f.tags ? $1 AND f.tags ? 'flag-out' AND fi.kind = 'raw' AND fi.direction = 'c'
		 GROUP BY fi.flow_id
		 ORDER BY count(*) DESC
		 LIMIT 1`,
		tag).Scan(&flowID)
	if err != nil {
		return nil
	}
	turns, err := e.db.FlowTurns(flowID)
	if err != nil {
		return nil
	}
	clientTurns := 0
	for _, t := range turns {
		if t.FromClient {
			clientTurns++
		}
	}
	if clientTurns < 2 {
		return nil
	}
	encoded, err := json.Marshal(e.synthesizeInteractive(service, port, turns))
	if err != nil {
		log.Println("minecore: marshal interactive plan:", err)
		return nil
	}
	return encoded
}

// saveShapeInteractiveTemplate persists a synthesized plan for a shape, keeping
// the first one written for a shape (ON CONFLICT DO NOTHING). Its own table
// (mine.shape_interactive) carries the shape's replay port so the candidate
// reader can key the socket without a separate lookup.
func saveShapeInteractiveTemplate(ctx context.Context, pool *pgxpool.Pool, service string, id int64, port int, plan []byte) {
	_, err := pool.Exec(ctx, `
		INSERT INTO mine.shape_interactive (service, shape_id, port, plan)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (service, shape_id) DO NOTHING
	`, service, id, port, plan)
	if err != nil {
		log.Println("minecore: save shape interactive template:", err)
	}
}
