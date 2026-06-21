package db

import (
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
