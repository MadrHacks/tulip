package mine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const templateSample = 12

func (e *Engine) flagIDSet() map[string]bool {
	m := make(map[string]bool, len(e.flagIDs))
	for _, id := range e.flagIDs {
		m[id] = true
	}
	return m
}

// maybeSynthesize re-synthesizes templates at most once per snapshotInterval.
func (e *Engine) maybeSynthesize(ctx context.Context) {
	if !e.lastSynthAt.IsZero() && time.Since(e.lastSynthAt) < snapshotInterval {
		return
	}
	e.synthesizeTemplates(ctx)
	e.lastSynthAt = time.Now()
}

// synthesizeTemplates (re)builds a template for every cluster at quorum, and
// again once a cluster has doubled in size since its last template.
func (e *Engine) synthesizeTemplates(ctx context.Context) {
	flagIDs := e.flagIDSet()
	for service, store := range e.shards {
		for _, c := range store.clusters {
			key := fmt.Sprintf("%s:%d", service, c.id)
			if c.n < coreQuorum || c.n < 2*e.templatedAt[key] {
				continue
			}
			members, err := e.db.ClusterMemberData("cluster:"+key, e.cfg.Horizon.Seconds(), templateSample)
			if err != nil || len(members) < coreQuorum {
				continue
			}
			canons := make([][]byte, len(members))
			for i, m := range members {
				canons[i] = canonical(m)
			}
			tpl := synthesize(canons, e.flagRe, flagIDs)
			if tpl == nil {
				continue
			}
			e.storeTemplate(ctx, service, c.id, tpl)
			e.templatedAt[key] = c.n
		}
	}
}

func (e *Engine) storeTemplate(ctx context.Context, service string, id int64, tpl *Template) {
	body, err := json.Marshal(tpl)
	if err != nil {
		log.Println("minecore: marshal template:", err)
		return
	}
	_, err = e.db.Pool().Exec(ctx, `
		INSERT INTO mine.template (service, cluster_id, body) VALUES ($1, $2, $3)
		ON CONFLICT (service, cluster_id) DO UPDATE SET
			body = excluded.body, version = mine.template.version + 1, updated_at = now()
	`, service, id, body)
	if err != nil {
		log.Println("minecore: store template:", err)
	}
}
