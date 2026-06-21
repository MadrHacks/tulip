package mine

import (
	"context"
	"encoding/json"
	"log"
	"net/netip"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

const cursorName = "minecore"

// Flow is the lean per-row projection minecore reads; item bytes are fetched
// lazily only when a stage needs them.
type Flow struct {
	Id        uuid.UUID
	DstPort   int
	DstIP     netip.Addr
	SrcIP     netip.Addr
	Tags      []string
	Flags     []string
	Flagids   []string
	Fuzzyhash string
	FlagsIn   int
	FlagsOut  int
}

// readBatch reads the next flows after cursor, never reaching past the horizon.
func (e *Engine) readBatch(ctx context.Context, cursor uuid.UUID) ([]Flow, error) {
	rows, err := e.db.Pool().Query(ctx, `
		SELECT id, port_dst, ip_dst, ip_src, tags, flags, flagids, fuzzyhash, flags_in, flags_out
		FROM flow
		WHERE id > @cursor
			AND id > fid_pack_low(now() - make_interval(secs => @horizon))
		ORDER BY id
		LIMIT @limit
	`, pgx.NamedArgs{
		"cursor":  cursor,
		"horizon": e.cfg.Horizon.Seconds(),
		"limit":   e.cfg.PollBatch,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Flow
	for rows.Next() {
		var f Flow
		var tags, flags, flagids []byte
		if err := rows.Scan(&f.Id, &f.DstPort, &f.DstIP, &f.SrcIP, &tags, &flags, &flagids,
			&f.Fuzzyhash, &f.FlagsIn, &f.FlagsOut); err != nil {
			return nil, err
		}
		json.Unmarshal(tags, &f.Tags)
		json.Unmarshal(flags, &f.Flags)
		json.Unmarshal(flagids, &f.Flagids)
		out = append(out, f)
	}
	return out, rows.Err()
}

// loadCursor returns the stored cursor, or the horizon floor on first start.
func (e *Engine) loadCursor(ctx context.Context) uuid.UUID {
	var id uuid.UUID
	err := e.db.Pool().QueryRow(ctx,
		`SELECT last_id FROM mine.read_cursor WHERE name = @name`,
		pgx.NamedArgs{"name": cursorName}).Scan(&id)
	if err == nil {
		return id
	}
	err = e.db.Pool().QueryRow(ctx,
		`SELECT fid_pack_low(now() - make_interval(secs => @horizon))`,
		pgx.NamedArgs{"horizon": e.cfg.Horizon.Seconds()}).Scan(&id)
	if err != nil {
		log.Fatalln("minecore: init cursor:", err)
	}
	return id
}

func (e *Engine) saveCursor(ctx context.Context, id uuid.UUID) {
	_, err := e.db.Pool().Exec(ctx, `
		INSERT INTO mine.read_cursor (name, last_id) VALUES (@name, @id)
		ON CONFLICT (name) DO UPDATE SET last_id = excluded.last_id
	`, pgx.NamedArgs{"name": cursorName, "id": id})
	if err != nil {
		log.Println("minecore: save cursor:", err)
	}
}
