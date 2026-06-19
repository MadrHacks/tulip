package db

// Persistence for retroactive TLS decryption: flows ingested before their
// secrets are available are queued in tls_pending and backfilled later via
// FlowBackfillDecrypted once the keys arrive.

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"math"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// TlsPendingInfo is the minimum needed to re-decrypt a flow once its key arrives:
// the client_random to match, plus the per-direction lost-bytes gap offsets.
type TlsPendingInfo struct {
	ClientRandom []byte
	ClientGap    int
	ServerGap    int
}

// TlsPendingFlow is a queued flow awaiting decryption.
type TlsPendingFlow struct {
	FlowId       uuid.UUID
	ClientRandom []byte
	ClientGap    int
	ServerGap    int
}

// EnsureTlsSchema creates the tls_pending table if it does not exist. Safe to
// call on every startup (covers both fresh and pre-existing databases).
func (db *Database) EnsureTlsSchema() {
	_, err := db.pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS tls_pending (
			flow_id uuid PRIMARY KEY,
			client_random bytea NOT NULL,
			client_gap integer NOT NULL,
			server_gap integer NOT NULL
		);
		CREATE INDEX IF NOT EXISTS tls_pending_client_random ON tls_pending (client_random);
	`)
	if err != nil {
		log.Fatalln("Unable to create tls_pending table: ", err)
	}
}

// TlsPendingInsert queues a flow for later decryption.
func (db *Database) TlsPendingInsert(flowId uuid.UUID, info *TlsPendingInfo) {
	db.workerPool.Submit(func() {
		_, err := db.pool.Exec(context.Background(), `
			INSERT INTO tls_pending (flow_id, client_random, client_gap, server_gap)
			VALUES (@flow_id, @client_random, @client_gap, @server_gap)
			ON CONFLICT (flow_id) DO NOTHING
		`, pgx.NamedArgs{
			"flow_id":       flowId,
			"client_random": info.ClientRandom,
			"client_gap":    info.ClientGap,
			"server_gap":    info.ServerGap,
		})
		if err != nil {
			log.Printf("Error queueing TLS flow %s for later decryption: %s\n", flowId, err)
		}
	})
}

// TlsPendingByClientRandoms returns queued flows whose client_random is in the
// given set (the client_randoms that just gained key-log secrets).
func (db *Database) TlsPendingByClientRandoms(clientRandoms [][]byte) ([]TlsPendingFlow, error) {
	if len(clientRandoms) == 0 {
		return nil, nil
	}
	rows, err := db.pool.Query(context.Background(), `
		SELECT flow_id, client_random, client_gap, server_gap
		FROM tls_pending
		WHERE client_random = ANY($1)
	`, clientRandoms)
	if err != nil {
		return nil, err
	}
	return scanPendingFlows(rows)
}

// TlsPendingAll returns every queued flow, for the periodic safety sweep (catches
// flows whose key arrived before the flow row committed, which the event missed).
func (db *Database) TlsPendingAll() ([]TlsPendingFlow, error) {
	rows, err := db.pool.Query(context.Background(), `
		SELECT flow_id, client_random, client_gap, server_gap
		FROM tls_pending
	`)
	if err != nil {
		return nil, err
	}
	return scanPendingFlows(rows)
}

func scanPendingFlows(rows pgx.Rows) ([]TlsPendingFlow, error) {
	defer rows.Close()
	var out []TlsPendingFlow
	for rows.Next() {
		var f TlsPendingFlow
		if err := rows.Scan(&f.FlowId, &f.ClientRandom, &f.ClientGap, &f.ServerGap); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// TlsPendingDelete removes a queued flow (decrypted, or given up on).
func (db *Database) TlsPendingDelete(flowId uuid.UUID) {
	_, err := db.pool.Exec(context.Background(), `DELETE FROM tls_pending WHERE flow_id = $1`, flowId)
	if err != nil {
		log.Printf("Error removing TLS flow %s from pending queue: %s\n", flowId, err)
	}
}

// FlowGetForReprocess reads back a stored flow's metadata and all of its flow
// items (in conversation order), so it can be decrypted and reprocessed.
func (db *Database) FlowGetForReprocess(flowId uuid.UUID) (*FlowEntry, error) {
	entry := &FlowEntry{Id: flowId}
	var portSrc, portDst int
	var tagsRaw []byte
	err := db.pool.QueryRow(context.Background(), `
		SELECT port_src, port_dst, ip_src, ip_dst, time, tags, pcap_id
		FROM flow WHERE id = $1
	`, flowId).Scan(&portSrc, &portDst, &entry.Src_ip, &entry.Dst_ip, &entry.Time, &tagsRaw, &entry.PcapId)
	if err != nil {
		return nil, err
	}
	entry.Src_port = uint16(portSrc)
	entry.Dst_port = uint16(portDst)
	_ = json.Unmarshal(tagsRaw, &entry.Tags)

	// The flow_item hypertable is partitioned on the (time-encoding) id, so we
	// constrain the scan to the flow's time window via fid_pack_low/high.
	rows, err := db.pool.Query(context.Background(), `
		SELECT kind, direction, data, time
		FROM flow_item
		WHERE flow_id = $1
			AND id > fid_pack_low((SELECT time FROM flow WHERE id = $1))
			AND id < fid_pack_high((SELECT time + duration FROM flow WHERE id = $1))
		ORDER BY id
	`, flowId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item FlowItem
		if err := rows.Scan(&item.Kind, &item.From, &item.Data, &item.Time); err != nil {
			return nil, err
		}
		entry.Flow = append(entry.Flow, item)
	}
	return entry, rows.Err()
}

// FlowBackfillDecrypted inserts the new decrypted items and their search index and
// updates the flow's derived fields (tags/flags/flagids merged race-safe with the
// enricher; counts/hash/fingerprints set).
func (db *Database) FlowBackfillDecrypted(flowId uuid.UUID, newItems []FlowItem, entry *FlowEntry) {
	// Make sure any new tags are registered.
	for _, tag := range entry.Tags {
		tag := tag
		db.workerPool.Submit(func() { db.KnownTagsUpsert(tag) })
	}

	// Insert the new flow items.
	db.batcherFlowItem.PushAll(buildItemRows(flowId, newItems))

	// Insert search-index rows for the new items (same chunking as FlowInsert).
	db.batcherFlowIndex.PushAll(buildIndexRows(flowId, newItems))

	// Fingerprints for session linking.
	fingerprints := make([]int32, len(entry.Fingerprints))
	for i, fp := range entry.Fingerprints {
		fingerprints[i] = int32(fp)
	}
	db.FingerprintsPush(fingerprints)

	db.workerPool.Submit(func() {
		tagsJson, _ := json.Marshal(entry.Tags)
		flagsJson, _ := json.Marshal(entry.Flags)
		flagidsJson, _ := json.Marshal(entry.Flagids)
		_, err := db.pool.Exec(context.Background(), `
			UPDATE flow SET
				tags = jsonb_unique(tags || @tags),
				flags = jsonb_unique(flags || @flags),
				flagids = jsonb_unique(flagids || @flagids),
				flags_in = @flags_in,
				flags_out = @flags_out,
				fuzzyhash = @fuzzyhash,
				fingerprints = @fingerprints
			WHERE id = @flow_id
		`, pgx.NamedArgs{
			"flow_id":      flowId,
			"tags":         tagsJson,
			"flags":        flagsJson,
			"flagids":      flagidsJson,
			"flags_in":     entry.Flags_In,
			"flags_out":    entry.Flags_Out,
			"fuzzyhash":    entry.Fuzzyhash,
			"fingerprints": fingerprints,
		})
		if err != nil {
			log.Printf("Error backfilling decrypted flow %s: %s\n", flowId, err)
		}
	})
}

// buildItemRows builds the COPY rows for the flow_item table. The column order
// must match batcherFlowItem's config (id, flow_id, kind, direction, data).
func buildItemRows(flowId uuid.UUID, items []FlowItem) [][]any {
	rows := make([][]any, len(items))
	for i := range items {
		rows[i] = []any{
			FidCreate(items[i].Time),
			flowId,
			items[i].Kind,
			items[i].From,
			&items[i].Data,
		}
	}
	return rows
}

// buildIndexRows chunks item data into overlapping search-index rows for the
// flow_index table.
func buildIndexRows(flowId uuid.UUID, items []FlowItem) [][]any {
	const chunkLength = 1024
	const chunkOverlap = 64
	indexes := make([][]any, 0)
	for _, item := range items {
		text := []rune(string(bytes.Replace(bytes.ToValidUTF8(item.Data, []byte{}), []byte{0}, []byte{}, -1)))
		chunkCount := int(math.Ceil(float64(len(text)) / float64(chunkLength)))
		for i := 0; i < chunkCount; i++ {
			startIndex := i * chunkLength
			endIndex := i*chunkLength + chunkLength + chunkOverlap
			if endIndex >= len(text) {
				endIndex = len(text)
			}
			indexes = append(indexes, []any{flowId, string(text[startIndex:endIndex])})
		}
	}
	return indexes
}
