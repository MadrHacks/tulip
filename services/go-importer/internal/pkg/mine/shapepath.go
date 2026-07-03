package mine

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"strconv"

	"go-importer/internal/pkg/db"
)

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
func buildShapeTags(store *ShapeStore, service string, msgs []db.FlowMessage, flagIn bool, t int64) []string {
	units := SegmentMessages(msgs)
	if len(units) == 0 {
		return nil
	}
	feats := make([]RespFeatures, len(units))
	for i := range units {
		feats[i] = ResponseFeatures(units[i].Response)
	}
	res := store.Observe(service, units, feats, flagIn, t)
	tags := make([]string, 0, len(res.ShapeIDs)+1)
	for _, id := range distinctShapeIDs(res.ShapeIDs) {
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
	return buildShapeTags(e.shapeStore, service, msgs, f.FlagsIn > 0, t)
}

// snapshotShapes bounds each shape shard to the configured cap (deleting the
// evicted rows) and persists the survivors to mine.shape — the shape-side twin
// of the cluster snapshot/eviction in maybeSnapshot.
func (e *Engine) snapshotShapes(ctx context.Context) {
	// Give settled shapes their REPLAY template before persisting: multiple-align
	// each shape's reservoir of raw samples into typed Const/Var slots (reuses the
	// cluster path's synthesize + slot-typing). The resulting {segments,slots}
	// body then rides the snapshot into mine.shape.template_body.
	e.shapeStore.SynthesizeTemplates(e.flagRe, e.flagIDSet())
	for service, ids := range e.shapeStore.EvictToCap() {
		deleteShapes(ctx, e.db.Pool(), service, ids)
	}
	for service, snaps := range e.shapeStore.snapshot() {
		saveShapeSnapshots(ctx, e.db.Pool(), service, snaps)
	}
}

// distinctShapeIDs de-duplicates a flow's per-unit shape ids, preserving first
// appearance so the emitted shape:* tags are deterministic.
func distinctShapeIDs(ids []int) []int {
	seen := make(map[int]bool, len(ids))
	out := make([]int, 0, len(ids))
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
