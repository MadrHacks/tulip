package mine

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureSchema creates minecore's engine-owned schema. Safe on every startup.
func EnsureSchema(ctx context.Context, pool *pgxpool.Pool) {
	_, err := pool.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS mine;
		CREATE TABLE IF NOT EXISTS mine.read_cursor (
			name text PRIMARY KEY,
			last_id uuid NOT NULL
		);
		CREATE TABLE IF NOT EXISTS mine.cluster (
			service text NOT NULL,
			id bigint NOT NULL,
			rep bytea NOT NULL,
			core bytea NOT NULL,
			core_set boolean NOT NULL,
			n integer NOT NULL,
			PRIMARY KEY (service, id)
		);
	`)
	if err != nil {
		log.Fatalln("minecore: ensure schema:", err)
	}
}
