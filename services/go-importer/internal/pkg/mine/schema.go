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
		CREATE TABLE IF NOT EXISTS mine.shape (
			service text NOT NULL,
			shape_id bigint NOT NULL,
			template text NOT NULL,
			members integer NOT NULL DEFAULT 0,
			size_bucket_sum integer NOT NULL DEFAULT 0,
			flag_present integer NOT NULL DEFAULT 0,
			flag_in integer NOT NULL DEFAULT 0,
			actors jsonb NOT NULL DEFAULT '{}'::jsonb,
			first_seen bigint NOT NULL DEFAULT 0,
			last_seen bigint NOT NULL DEFAULT 0,
			port integer NOT NULL DEFAULT 0,
			template_body jsonb,
			PRIMARY KEY (service, shape_id)
		);
			ALTER TABLE mine.shape ADD COLUMN IF NOT EXISTS template_body jsonb;
			ALTER TABLE mine.shape ADD COLUMN IF NOT EXISTS port integer NOT NULL DEFAULT 0;
		CREATE TABLE IF NOT EXISTS mine.shape_interactive (
			service text NOT NULL,
			shape_id bigint NOT NULL,
			port integer NOT NULL DEFAULT 0,
			plan jsonb NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (service, shape_id)
		);
	`)
	if err != nil {
		log.Fatalln("minecore: ensure schema:", err)
	}
}
