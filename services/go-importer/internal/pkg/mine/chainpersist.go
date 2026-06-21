package mine

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// loadChainClusters restores the signature->id map so chain ids stay stable
// across restarts.
func loadChainClusters(ctx context.Context, pool *pgxpool.Pool, cs *chainClusterStore) {
	rows, err := pool.Query(ctx, `SELECT signature, id FROM mine.chain_template`)
	if err != nil {
		log.Println("minecore: load chains:", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sig string
		var id int64
		if err := rows.Scan(&sig, &id); err != nil {
			log.Println("minecore: scan chain:", err)
			return
		}
		cs.restore(sig, id)
	}
}

// saveChainTemplate upserts a settled chain, bumping its occurrence count when
// the same chain pattern recurs.
func saveChainTemplate(ctx context.Context, pool *pgxpool.Pool, sc settledChain) {
	body, err := json.Marshal(sc.Template)
	if err != nil {
		log.Println("minecore: marshal chain:", err)
		return
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO mine.chain_template (signature, id, n, body)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (signature) DO UPDATE SET
			n = mine.chain_template.n + 1, body = excluded.body, updated_at = now()
	`, sc.Signature, sc.ID, body)
	if err != nil {
		log.Println("minecore: save chain:", err)
	}
}
