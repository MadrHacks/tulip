package main

import (
	"log"
	"time"

	"go-importer/internal/converters"
	"go-importer/internal/pkg/db"
	"go-importer/internal/pkg/tlsdecrypt"
)

// Retroactive TLS decryption. Flows ingested before their secrets were available
// are queued in tls_pending; this worker decrypts and backfills them when the
// secrets arrive — driven by key-log events, a startup sweep, and a periodic
// safety sweep, all on one goroutine so flows are never reprocessed concurrently.

const tlsSweepInterval = 60 * time.Second

var tlsRetryChan chan [][]byte

func startTlsRetryWorker() {
	tlsRetryChan = make(chan [][]byte, 256)

	go func() {
		ticker := time.NewTicker(tlsSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case clientRandoms := <-tlsRetryChan:
				reprocessTlsFlows(clientRandoms)
			case <-ticker.C:
				sweepPendingTls()
			}
		}
	}()

	// Enqueue a retry for the affected client_randoms. Blocking (not dropping): the
	// producer is the slow key-log poller, and a dropped batch could strand a flow.
	g_tlskeys.SetOnNewSecrets(func(clientRandoms [][]byte) {
		tlsRetryChan <- clientRandoms
	})

	// Startup sweep: backfill flows queued by a previous run whose keys are
	// already present in the key log.
	if all := g_tlskeys.AllClientRandoms(); len(all) > 0 {
		tlsRetryChan <- all
	}
}

func reprocessTlsFlows(clientRandoms [][]byte) {
	pending, err := g_db.TlsPendingByClientRandoms(clientRandoms)
	if err != nil {
		log.Println("WARN: failed to query pending TLS flows:", err)
		return
	}
	for _, pf := range pending {
		reprocessTlsFlow(pf)
	}
}

// sweepPendingTls reprocesses every queued flow whose key is already loaded.
// Reading the small pending table is cheap; the expensive flow read + decrypt
// only happens for flows that actually have a key, so this is bounded.
func sweepPendingTls() {
	pending, err := g_db.TlsPendingAll()
	if err != nil {
		log.Println("WARN: failed to sweep pending TLS flows:", err)
		return
	}
	for _, pf := range pending {
		if g_tlskeys.Has(pf.ClientRandom) {
			reprocessTlsFlow(pf)
		}
	}
}

func reprocessTlsFlow(pf db.TlsPendingFlow) {
	// One bad flow must not take down the retry worker.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WARN: recovered from panic reprocessing TLS flow %s: %v", pf.FlowId, r)
		}
	}()

	entry, err := g_db.FlowGetForReprocess(pf.FlowId)
	if err != nil {
		// Flow not present yet (pending inserted before the flow landed) or a
		// transient read error — leave it queued for a later attempt.
		return
	}

	// Process picks out the raw (ciphertext) items itself, so the stored
	// representations (raw, raw -> ...) can be passed through as-is.
	outcome := tlsdecrypt.Process(g_tlskeys, entry.Flow, pf.ClientGap, pf.ServerGap)
	switch outcome.Status {
	case tlsdecrypt.StatusDecrypted:
		newItems := outcome.Items

		// Run converters over the decrypted plaintext only (not the raw items,
		// which were already processed at ingest), mirroring the in-line path.
		if !*disableConverters {
			temp := &db.FlowEntry{
				Src_ip:   entry.Src_ip,
				Src_port: entry.Src_port,
				Dst_ip:   entry.Dst_ip,
				Dst_port: entry.Dst_port,
				Flow:     append([]db.FlowItem(nil), outcome.Items...),
			}
			converters.RunPipeline(g_db, temp)
			// RunPipeline only appends converter outputs after the input items,
			// so anything past the original count is new.
			if len(temp.Flow) > len(outcome.Items) {
				newItems = append(newItems, temp.Flow[len(outcome.Items):]...)
			}
		}

		// Recompute the derived fields over the full flow (raw + decrypted +
		// converter outputs), exactly as if it had been decrypted at ingest.
		entry.Flow = append(entry.Flow, newItems...)
		if !contains(entry.Tags, "tls") {
			entry.Tags = append(entry.Tags, "tls")
		}
		ParseHttpFlow(g_db, entry)
		scanFlagsAndHash(entry)

		g_db.FlowBackfillDecrypted(pf.FlowId, newItems, entry)
		g_db.TlsPendingDelete(pf.FlowId)
		log.Printf("tlsdecrypt: backfilled %d decrypted item(s) for flow %s", len(newItems), pf.FlowId)

	case tlsdecrypt.StatusNeedKey:
		// Still missing the application secret; keep it queued for next time.

	default:
		// NotTLS / give-up — drop it so it doesn't linger in the queue.
		g_db.TlsPendingDelete(pf.FlowId)
	}
}
