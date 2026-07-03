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
