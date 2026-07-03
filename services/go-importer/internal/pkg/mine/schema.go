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
			last_seen bigint NOT NULL DEFAULT 0,
			PRIMARY KEY (service, id)
		);
		ALTER TABLE mine.cluster ADD COLUMN IF NOT EXISTS last_seen bigint NOT NULL DEFAULT 0;
		UPDATE mine.cluster SET last_seen = extract(epoch from now())::bigint WHERE last_seen = 0;
		CREATE TABLE IF NOT EXISTS mine.template (
			service text NOT NULL,
			cluster_id bigint NOT NULL,
			body jsonb NOT NULL,
			version integer NOT NULL DEFAULT 1,
			updated_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (service, cluster_id)
		);
		CREATE TABLE IF NOT EXISTS mine.chain_template (
			signature text PRIMARY KEY,
			id bigint NOT NULL,
			n integer NOT NULL,
			body jsonb NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS mine.heat (
			service text PRIMARY KEY,
			our_lost integer NOT NULL,
			our_stolen integer NOT NULL,
			total_stolen integer NOT NULL,
			our_sla_ok boolean NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS mine.calibrator (
			service text NOT NULL,
			source text NOT NULL,
			count integer NOT NULL,
			flag_outs integer NOT NULL,
			last_seen bigint NOT NULL,
			has_last boolean NOT NULL,
			gap_sum double precision NOT NULL,
			gap_sq_sum double precision NOT NULL,
			gap_count integer NOT NULL,
			PRIMARY KEY (service, source)
		);
	`)
	if err != nil {
		log.Fatalln("minecore: ensure schema:", err)
	}
}
