package db

import (
	"context"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool exposes the connection pool so engine-owned schemas (e.g. minecore's
// mine.*) reuse this database without duplicating connection setup.
func (db *Database) Pool() *pgxpool.Pool { return db.pool }

// AppendDerivedItems appends derived flow items of a new Kind to an existing
// flow, reusing the single-source chunker so the search index stays consistent.
func (db *Database) AppendDerivedItems(flowId uuid.UUID, items []FlowItem) {
	if len(items) == 0 {
		return
	}
	db.batcherFlowItem.PushAll(buildItemRows(flowId, items))
	db.batcherFlowIndex.PushAll(buildIndexRows(flowId, items))
}

// kindChunk is one flow_item's kind and bytes, kept in conversation (id) order.
type kindChunk struct {
	kind string
	data []byte
}

// topmost returns the bytes of the single most-decoded representation among
// chunks, concatenated in arrival order. Tulip layers representations as a base
// kind ("raw" / "decrypted") plus converter chains named "<parent> -> <conv>"
// (e.g. "raw -> b64decode", "decrypted -> websockets -> b64decode"). The most
// decoded layer is the deepest such chain, preferring a decrypted root over a
// raw one. Choosing by this generic rule means any decoder — TLS, base64,
// websockets, or one a user wires up mid-game — feeds analysis with no change
// here. Returns nil when there are no chunks.
func topmost(chunks []kindChunk) []byte {
	best := ""
	for _, c := range chunks {
		if best == "" || lessDecoded(best, c.kind) {
			best = c.kind
		}
	}
	if best == "" {
		return nil
	}
	var out []byte
	for _, c := range chunks {
		if c.kind == best {
			out = append(out, c.data...)
		}
	}
	return out
}

// lessDecoded reports whether kind a is a lower-priority (less decoded)
// representation than b: fewer converter stages, or a raw root vs a decrypted
// one. Ties break on the kind string for determinism.
func lessDecoded(a, b string) bool {
	ra, rb := decodeRank(a), decodeRank(b)
	if ra[0] != rb[0] {
		return ra[0] < rb[0]
	}
	if ra[1] != rb[1] {
		return ra[1] < rb[1]
	}
	return a < b
}

// decodeRank scores a kind as {decrypted-root, converter-depth}.
func decodeRank(kind string) [2]int {
	root := 0
	if strings.HasPrefix(kind, "decrypted") {
		root = 1
	}
	return [2]int{root, strings.Count(kind, " -> ")}
}

// FlowAnalysisData returns the most-decoded representation of a flow's
// client->server and server->client bytes in one query, halving the per-flow
// reads on the analysis hot path. See topmost for how the layer is chosen.
func (db *Database) FlowAnalysisData(flowId uuid.UUID) (client, server []byte, err error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT direction, kind, data FROM flow_item
		WHERE flow_id = $1
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var c, s []kindChunk
	for rows.Next() {
		var dir, kind string
		var data []byte
		if err := rows.Scan(&dir, &kind, &data); err != nil {
			return nil, nil, err
		}
		switch dir {
		case "c":
			c = append(c, kindChunk{kind, data})
		case "s":
			s = append(s, kindChunk{kind, data})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return topmost(c), topmost(s), nil
}

// FlowClientData returns the most-decoded client->server bytes of a flow.
func (db *Database) FlowClientData(flowId uuid.UUID) ([]byte, error) {
	return db.flowDirectionData(flowId, "c")
}

// FlowServerData returns the most-decoded server->client bytes of a flow — the
// values a service hands out (tokens, ids), the producer side of cross-flow
// dataflow.
func (db *Database) FlowServerData(flowId uuid.UUID) ([]byte, error) {
	return db.flowDirectionData(flowId, "s")
}

func (db *Database) flowDirectionData(flowId uuid.UUID, direction string) ([]byte, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT kind, data FROM flow_item
		WHERE flow_id = $1 AND direction = $2
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId, direction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []kindChunk
	for rows.Next() {
		var kind string
		var data []byte
		if err := rows.Scan(&kind, &data); err != nil {
			return nil, err
		}
		chunks = append(chunks, kindChunk{kind, data})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return topmost(chunks), nil
}

// Turn is one side's contiguous bytes in an interactive conversation: the merged
// run of same-direction raw chunks. A flow's turns alternate client/server in
// arrival order, reconstructing the back-and-forth of a single-connection
// session for interactive-replay synthesis.
type Turn struct {
	FromClient bool
	Data       []byte
}

// FlowTurns returns a flow's verbatim (raw-kind) bytes grouped into alternating
// conversation turns: consecutive same-direction chunks are merged into one
// Turn, in id (arrival) order. Interactive replay reproduces the exact wire
// bytes, so this reads the raw representation rather than the decoded topmost
// layer. Bounds the scan by the flow's id window, mirroring FlowAnalysisData.
func (db *Database) FlowTurns(flowId uuid.UUID) ([]Turn, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT direction, data FROM flow_item
		WHERE flow_id = $1 AND kind = 'raw'
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []rawChunk
	for rows.Next() {
		var dir string
		var data []byte
		if err := rows.Scan(&dir, &data); err != nil {
			return nil, err
		}
		chunks = append(chunks, rawChunk{fromClient: dir == "c", data: data})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groupTurns(chunks), nil
}

// ShapeFlowIDs returns up to `limit` flag-out flow ids tagged `tag`, richest
// (most client raw items) first — the homogeneous shape members the interactive
// reproduction engine aligns and classifies. Ordering by client-turn count picks
// the fullest sessions, which carry the most structure to align against.
func (db *Database) ShapeFlowIDs(tag string, limit int) ([]uuid.UUID, error) {
	rows, err := db.pool.Query(context.Background(),
		`SELECT fi.flow_id
		 FROM flow_item fi JOIN flow f ON f.id = fi.flow_id
		 WHERE f.tags ? $1 AND f.tags ? 'flag-out' AND fi.kind = 'raw' AND fi.direction = 'c'
		 GROUP BY fi.flow_id
		 ORDER BY count(*) DESC
		 LIMIT $2`,
		tag, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// rawChunk is one direction-tagged raw flow_item, in id (arrival) order.
type rawChunk struct {
	fromClient bool
	data       []byte
}

// groupTurns merges consecutive same-direction chunks into alternating turns,
// so a flow's chunk stream becomes the ordered back-and-forth of a conversation.
// Each turn owns a fresh copy of its bytes (never aliasing the row buffers).
func groupTurns(chunks []rawChunk) []Turn {
	var turns []Turn
	for _, ch := range chunks {
		if n := len(turns); n > 0 && turns[n-1].FromClient == ch.fromClient {
			turns[n-1].Data = append(turns[n-1].Data, ch.data...)
		} else {
			turns = append(turns, Turn{FromClient: ch.fromClient, Data: append([]byte(nil), ch.data...)})
		}
	}
	return turns
}

// FlowMessage is one flow_item rendered in its direction's most-decoded
// representation, tagged with its direction — the ordered building block a
// segmenter pairs on. Unlike FlowAnalysisData (which collapses each direction
// into one concatenated stream) a slice of FlowMessages PRESERVES the
// client/server alternation and per-item order, so a segmenter can pair each
// request with the response that actually followed it rather than by global
// index. This is what recovers the per-op response pairing the offline shape
// prototype could not (it only had direction-concatenated bytes).
type FlowMessage struct {
	FromClient bool
	Kind       string // the selected most-decoded kind for this direction
	Data       []byte
}

// dirChunk is one direction- and kind-tagged flow_item, in id (arrival) order.
type dirChunk struct {
	fromClient bool
	kind       string
	data       []byte
}

// orderedMessages returns the chunks of each direction's most-decoded kind, in
// arrival order, tagged with direction. The best kind is chosen PER DIRECTION
// (mirroring FlowAnalysisData's topmost(c)/topmost(s) split): a client stream
// captured raw and a server stream TLS-decrypted each keep their own deepest
// layer rather than one global choice dropping a whole side. Each returned
// message owns its bytes (never aliasing the pgx row buffers).
func orderedMessages(chunks []dirChunk) []FlowMessage {
	bestC, bestS := "", ""
	for _, c := range chunks {
		if c.fromClient {
			if bestC == "" || lessDecoded(bestC, c.kind) {
				bestC = c.kind
			}
		} else {
			if bestS == "" || lessDecoded(bestS, c.kind) {
				bestS = c.kind
			}
		}
	}
	var out []FlowMessage
	for _, c := range chunks {
		best := bestS
		if c.fromClient {
			best = bestC
		}
		if best == "" || c.kind != best {
			continue
		}
		out = append(out, FlowMessage{
			FromClient: c.fromClient,
			Kind:       c.kind,
			Data:       append([]byte(nil), c.data...),
		})
	}
	return out
}

// FlowMessages returns a flow's most-decoded bytes as ordered, direction-tagged
// messages: one FlowMessage per flow_item of its direction's topmost kind, in id
// (conversation) order, bounded by the flow's id window like FlowAnalysisData.
// Read-only. The ordering is what lets a segmenter pair each request unit with
// the response that actually followed it (fixing the line-protocol interleaving
// the offline prototype lost). It does not merge same-direction chunks; callers
// that want turns can group consecutive same-direction messages themselves.
func (db *Database) FlowMessages(flowId uuid.UUID) ([]FlowMessage, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT direction, kind, data FROM flow_item
		WHERE flow_id = $1
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []dirChunk
	for rows.Next() {
		var dir, kind string
		var data []byte
		if err := rows.Scan(&dir, &kind, &data); err != nil {
			return nil, err
		}
		chunks = append(chunks, dirChunk{fromClient: dir == "c", kind: kind, data: data})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return orderedMessages(chunks), nil
}

// ClusterMemberData returns the client plaintext of up to limit recent flows
// carrying the given tag (e.g. "cluster:CCalendar:7"), within the horizon.
func (db *Database) ClusterMemberData(tag string, horizonSecs float64, limit int) ([][]byte, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT id FROM flow
		WHERE tags ? $1
			AND id > fid_pack_low(now() - make_interval(secs => $2))
		ORDER BY id DESC
		LIMIT $3
	`, tag, horizonSecs, limit)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()

	var out [][]byte
	for _, id := range ids {
		data, err := db.FlowClientData(id)
		if err == nil && len(data) > 0 {
			out = append(out, data)
		}
	}
	return out, nil
}

// IssuerPoolFlows returns the turns of up to `limit` recent flows on service
// port `port` whose SERVER side handed a session credential back to the client
// — a response `Set-Cookie:` header — as the candidate ISSUER pool for
// cross-connection session stitching. A cookie/token-auth service splits one
// logical session across separate TCP connections: the login that RECEIVES
// `Set-Cookie: PHPSESSID=V` carries NO flag, so it never appears among a shape's
// flag-out members and must be drawn from this wider same-service pool; the
// stitcher then concatenates it before the (separate) flag-leaking read that
// PRESENTS V, turning the external cookie into an in-session Set-Cookie->Cookie
// mirror.
//
// Read-only and bounded: scoped to one service port, the last `horizonSecs`
// (the engine's correlation horizon), most-recent flows first, capped at
// `limit`. The `Set-Cookie` prefilter runs in SQL so only genuine issuers are
// materialized; the stitcher's issuedCreds re-validates each pooled flow (and
// additionally recovers any response-body token), so a coincidental match is
// harmless. Turns are read verbatim like FlowTurns.
func (db *Database) IssuerPoolFlows(port int, horizonSecs float64, limit int) ([][]Turn, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT DISTINCT f.id
		FROM flow f JOIN flow_item fi ON fi.flow_id = f.id
		WHERE f.port_dst = $1
			AND f.id > fid_pack_low(now() - make_interval(secs => $2))
			AND fi.direction = 's' AND fi.kind = 'raw'
			AND position(convert_to('Set-Cookie', 'UTF8') in fi.data) > 0
		ORDER BY f.id DESC
		LIMIT $3
	`, port, horizonSecs, limit)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()

	out := make([][]Turn, 0, len(ids))
	for _, id := range ids {
		turns, err := db.FlowTurns(id)
		if err == nil && len(turns) > 0 {
			out = append(out, turns)
		}
	}
	return out, nil
}
