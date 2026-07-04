package mine

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"
	"strings"

	"go-importer/internal/pkg/db"
)

// flagIDSet returns the live flagId set as a lookup map, for slot typing during
// shape replay-template synthesis.
func (e *Engine) flagIDSet() map[string]bool {
	m := make(map[string]bool, len(e.flagIDs))
	for _, id := range e.flagIDs {
		m[id] = true
	}
	return m
}

// primaryShapeTag returns the flow's first shape:<svc>:<id> tag — the single
// shape identity the chain path keys each of its steps by — or "" when the flow
// produced no shape tag.
func primaryShapeTag(tags []string) string {
	for _, t := range tags {
		if strings.HasPrefix(t, "shape:") {
			return t
		}
	}
	return ""
}

// The parallel SHAPE path: the online counterpart of the cluster path in
// handle(). For each flow it reads the ORDERED per-item messages, segments them
// into request units with true per-response pairing (SegmentMessages), folds
// them into the streaming ShapeStore, and emits NEUTRAL tags only —
// "shape:<svc>:<id>" per distinct shape and one "session:<hash>". No
// attack/verdict tag is ever emitted here: a shape is a neutral observation;
// its signals (flag_present, flag_in, actors, size) live in mine.shape. This
// runs ALONGSIDE the cluster tagging (cluster.go is untouched); the cluster
// retirement is a later step.

// buildShapeTags segments ordered messages, folds them into the store, and
// returns the flow's neutral shape/session tags. Split out from shapeTags so it
// is unit-testable without a live database. Returns nil for an empty flow.
func buildShapeTags(store *ShapeStore, service string, msgs []db.FlowMessage, flagIn bool, port int, t int64) []string {
	units := SegmentMessages(msgs)
	if len(units) == 0 {
		return nil
	}
	feats := make([]RespFeatures, len(units))
	for i := range units {
		feats[i] = ResponseFeatures(units[i].Response)
	}
	res := store.Observe(service, units, feats, flagIn, port, t)
	tags := make([]string, 0, len(res.RefinedIDs)+1)
	// Tag by CRISP refined id, so a flow's shape:<svc>:<id> tags name the real
	// interaction-kinds it exercised (the boomerang IDOR distinct from a benign
	// sibling), and the candidate/interactive lookups that key off these tags hit
	// homogeneous members.
	for _, id := range distinctRefinedIDs(res.RefinedIDs) {
		tags = append(tags, fmt.Sprintf("shape:%s:%d", service, id))
	}
	tags = append(tags, "session:"+sessionHash(res.SessionShape))
	return tags
}

// shapeTags runs the parallel shape path for one flow and returns its neutral
// tags. A failure to read the ordered messages skips only the shape path so the
// cluster path in handle() stays unaffected.
func (e *Engine) shapeTags(f *Flow, service string, t int64) []string {
	msgs, err := e.db.FlowMessages(f.Id)
	if err != nil {
		log.Println("minecore: flow messages:", err)
		return nil
	}
	return buildShapeTags(e.shapeStore, service, msgs, f.FlagsIn > 0, f.DstPort, t)
}

// snapshotShapes bounds each shape shard to the configured cap and persists two
// row classes to mine.shape:
//
//   - PARENT SEED rows (Drain shape id): keyed by the small Drain id, they carry
//     the Drain template so restoreShapeStore can re-seed the miner and keep parent
//     ids stable. They carry NO replay body, so the candidate reader never treats
//     an over-merged parent as a candidate.
//   - REFINED rows (id >= refinedIDBase): one per crisp interaction-kind, each with
//     its flag_present signal and a replay template aligned from HOMOGENEOUS
//     members. These are the vectors /candidates surfaces.
//
// Refined rows are reconciled against what this process last wrote: a refined id we
// persisted before but no longer produce (a split that merged, an evicted parent)
// is deleted, so stale crisp rows do not linger. The reconciliation only forgets
// ids written IN THIS PROCESS, so a fresh restart never wipes the pre-restart rows
// (kept as candidates) before the reservoir re-warms.
func (e *Engine) snapshotShapes(ctx context.Context) {
	pool := e.db.Pool()
	// Parent seed rows: evict past the cap (dropping evicted rows) then persist the
	// survivors so the Drain re-seeds on restart.
	for service, ids := range e.shapeStore.EvictToCap() {
		deleteShapes(ctx, pool, service, ids)
	}
	for service, snaps := range e.shapeStore.snapshot() {
		saveShapeSnapshots(ctx, pool, service, snaps)
	}
	// Crisp refined rows: the candidate vectors. Synthesized from each sub-shape's
	// own samples inside refinedSnapshots.
	for service, snaps := range e.shapeStore.refinedSnapshots(e.flagRe, e.flagIDSet()) {
		saveShapeSnapshots(ctx, pool, service, snaps)
		cur := make(map[int64]struct{}, len(snaps))
		for _, s := range snaps {
			cur[int64(s.ShapeID)] = struct{}{}
		}
		if prev := e.persistedRefined[service]; len(prev) > 0 {
			var stale []int64
			for id := range prev {
				if _, ok := cur[id]; !ok {
					stale = append(stale, id)
				}
			}
			deleteShapeIDs(ctx, pool, service, stale)
		}
		e.persistedRefined[service] = cur
	}
}

// distinctRefinedIDs de-duplicates a flow's per-unit refined ids, preserving first
// appearance so the emitted shape:* tags are deterministic.
func distinctRefinedIDs(ids []int64) []int64 {
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// sessionHash renders the (possibly long) ordered shape-id signature as a
// compact, stable hex digest for the session:* tag.
func sessionHash(sig string) string {
	h := fnv.New64a()
	h.Write([]byte(sig))
	return strconv.FormatUint(h.Sum64(), 16)
}
