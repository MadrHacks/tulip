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
	prompt := strings.TrimRight(string(data), " ")
	if prompt == "" {
		return nil
	}
	return &prompt
}

// maybeSynthInteractive attempts, at most once per cluster (guarded by
// e.interactiveSynthed), to synthesize and persist an interactive session plan
// for a detected candidate. It pulls one representative flag-leaking flow; if
// its conversation has >= 2 client turns — a genuine multi-turn session a
// single-flow template cannot express — it synthesizes the plan and upserts it.
// Fewer than 2 client turns: nothing is written and it stays a single-flow
// candidate.
func (e *Engine) maybeSynthInteractive(ctx context.Context, service string, id int64, port int) {
	key := fmt.Sprintf("%s:%d", service, id)
	if e.interactiveSynthed[key] {
		return
	}
	e.interactiveSynthed[key] = true

	tag := fmt.Sprintf("cluster:%s:%d", service, id)
	var flowID uuid.UUID
	err := e.db.Pool().QueryRow(ctx,
		`SELECT id FROM flow WHERE tags ? $1 AND tags ? 'flag-out' ORDER BY id LIMIT 1`,
		tag).Scan(&flowID)
	if err != nil {
		return
	}
	turns, err := e.db.FlowTurns(flowID)
	if err != nil {
		return
	}
	clientTurns := 0
	for _, t := range turns {
		if t.FromClient {
			clientTurns++
		}
	}
	if clientTurns < 2 {
		return
	}
	encoded, err := json.Marshal(e.synthesizeInteractive(service, port, turns))
	if err != nil {
		log.Println("minecore: marshal interactive plan:", err)
		return
	}
	saveInteractiveTemplate(ctx, e.db.Pool(), service, id, encoded)
}

// saveInteractiveTemplate persists a synthesized plan, keeping the first one
// written for a cluster (ON CONFLICT DO NOTHING).
func saveInteractiveTemplate(ctx context.Context, pool *pgxpool.Pool, service string, id int64, plan []byte) {
	_, err := pool.Exec(ctx, `
		INSERT INTO mine.interactive_template (service, cluster_id, plan)
		VALUES ($1, $2, $3)
		ON CONFLICT (service, cluster_id) DO NOTHING
	`, service, id, plan)
	if err != nil {
		log.Println("minecore: save interactive template:", err)
	}
}
