package db

import (
	"context"

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

// FlowClientData returns a flow's client->server plaintext for analysis: the
// decrypted items when present, else the raw reassembled items, concatenated in
// conversation order. Derived representations are excluded.
func (db *Database) FlowClientData(flowId uuid.UUID) ([]byte, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT kind, data FROM flow_item
		WHERE flow_id = $1 AND direction = 'c' AND kind IN ('raw', 'decrypted')
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var raw, dec []byte
	for rows.Next() {
		var kind string
		var data []byte
		if err := rows.Scan(&kind, &data); err != nil {
			return nil, err
		}
		if kind == RawKind {
			raw = append(raw, data...)
		} else {
			dec = append(dec, data...)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(dec) > 0 {
		return dec, nil
	}
	return raw, nil
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
