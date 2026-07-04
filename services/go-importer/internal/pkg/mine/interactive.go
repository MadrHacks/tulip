package mine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"go-importer/internal/pkg/db"

	"github.com/jackc/pgx/v5/pgxpool"
)

// stitchPoolCap bounds the candidate-issuer pool a shape draws for cross-
// connection session stitching: at most this many recent same-service
// Set-Cookie flows are materialized (see db.IssuerPoolFlows). Large enough to
// hold every login within the correlation horizon on one service port, capped
// so a busy port cannot grow the pool without bound.
const stitchPoolCap = 2000

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
		flows = e.stitchShapeSessions(service, port, flows)
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

// stitchShapeSessions re-assembles the cross-connection sessions a cookie/token-
// auth shape splits across TCP connections, so the shape can reproduce. A shape
// like dutyfree's loyalty IDOR leaks the flag on a standalone GET /user/loyalty?id
// read that merely PRESENTS a `Cookie: PHPSESSID=V` it never received on that
// connection — the login that issued V is a separate, flag-less connection absent
// from these flag-out members. Left alone the cookie types as an unreconstructable
// external session token and the whole plan gates.
//
// It draws a bounded same-service issuer pool (recent Set-Cookie flows) and hands
// it, with the shape's own members, to the validated stitchSessions primitive:
// each member that presents an EXTERNAL credential is prefixed with the pooled
// flow whose response issued that exact VALUE, so V becomes an in-session
// Set-Cookie->Cookie MIRROR. Members that established their credential in-
// connection (the shapes that already reproduce) present no external credential,
// so stitchSessions is a no-op for them; the collision guard (`avoid` = the
// shape's own same-connection skeletons) additionally leaves a session already
// present intact unstitched. On any pool error or an empty pool the members are
// returned unchanged, so the already-reproducing shapes can never regress.
func (e *Engine) stitchShapeSessions(service string, port int, flows [][]db.Turn) [][]db.Turn {
	pool, err := e.db.IssuerPoolFlows(port, e.cfg.Horizon.Seconds(), stitchPoolCap)
	if err != nil {
		log.Println("minecore: issuer pool:", err)
		return flows
	}
	if len(pool) == 0 {
		return flows
	}
	avoid := make(map[string]bool, len(flows))
	for _, f := range flows {
		avoid[flowSkeleton(f)] = true
	}
	stitched := stitchSessions(flows, pool, flowSkeleton, avoid)

	// If nothing stitched, the members are the input untouched — hand them straight
	// through so a shape that already reproduces in-connection stays byte-identical
	// (the working exfil must never be perturbed by this path).
	changed := false
	for i := range stitched {
		if len(stitched[i]) != len(flows[i]) {
			changed = true
			break
		}
	}
	if !changed {
		return flows
	}

	// Stitching prepends each read's own historical issuer, and live logins are
	// NOT uniform (a value minted by GET / vs POST /login), so the stitched members
	// can be structurally heterogeneous. analyseShape aligns a HOMOGENEOUS shape;
	// a minority login variant would ragged-out the whole set. Collapse to the one
	// dominant flow skeleton so the aligner receives a clean, reproducible sub-shape.
	return dominantSkeleton(stitched)
}

// dominantSkeleton returns the members sharing the single most-common flow
// skeleton, so a stitched set fragmented across login variants collapses to one
// structurally-homogeneous shape the token aligner can process. The largest group
// wins; ties break toward the SHORTER session (fewest client turns) — the minimal
// reproduction — then lexicographically on the skeleton for determinism.
func dominantSkeleton(flows [][]db.Turn) [][]db.Turn {
	groups := map[string][][]db.Turn{}
	order := []string{}
	for _, f := range flows {
		s := flowSkeleton(f)
		if _, ok := groups[s]; !ok {
			order = append(order, s)
		}
		groups[s] = append(groups[s], f)
	}
	best := ""
	for _, s := range order {
		if best == "" {
			best = s
			continue
		}
		g, b := groups[s], groups[best]
		if len(g) > len(b) {
			best = s
			continue
		}
		if len(g) == len(b) {
			gt, bt := len(clientTurns(g[0])), len(clientTurns(b[0]))
			if gt < bt || (gt == bt && s < best) {
				best = s
			}
		}
	}
	return groups[best]
}

// flowSkeleton renders a flow's client turns as the structural skeleton the shape
// pipeline keys on (NormalizeUnit per request unit, joined), a stable signature
// that ignores per-instance values but CHANGES when an issuer prefix is prepended.
// It backs the stitch collision guard: a stitched session whose skeleton already
// matches a same-connection member is left unstitched, so a stitched self-read
// never merges into and re-labels a shape that is already reproducing.
func flowSkeleton(turns []db.Turn) string {
	proto := "line"
	for _, t := range turns {
		if t.FromClient {
			if reReqLine.Match(t.Data) {
				proto = "http"
			}
			break
		}
	}
	var parts []string
	for _, t := range turns {
		if !t.FromClient {
			continue
		}
		units := splitLineOps(t.Data)
		if proto == "http" {
			units = splitHTTPRequests(t.Data)
		}
		for _, u := range units {
			sk, _ := NormalizeUnit(RequestUnit{Proto: proto, Client: u})
			parts = append(parts, sk)
		}
	}
	return strings.Join(parts, "|")
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
