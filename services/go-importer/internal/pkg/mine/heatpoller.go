package mine

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// roundForTime returns the scoreboard round in effect at now, given the game
// start and tick duration. Returns -1 before the game starts or for a
// non-positive tick.
func roundForTime(start, now time.Time, tick time.Duration) int {
	if tick <= 0 {
		return -1
	}
	d := now.Sub(start)
	if d < 0 {
		return -1
	}
	return int(d / tick)
}

// pollHeatLoop periodically refreshes per-service heat from the scoreboard. It
// is a no-op (logged once) when the scoreboard URL, game start, or team id is
// unset, so simulations without scoreboard access run cleanly.
func (e *Engine) pollHeatLoop(ctx context.Context) {
	if e.scoreboardURL == "" || e.gameStart.IsZero() || e.teamID < 0 {
		log.Println("minecore: heat poller disabled (scoreboard url / start / team id unset)")
		return
	}
	interval := e.gameTick
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	log.Printf("minecore: heat poller every %s against %s", interval, e.scoreboardURL)
	for {
		e.pollHeatOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// pollHeatOnce fetches the freshest available scoreboard round and persists its
// per-service heat. It probes a few rounds back from the time-derived round so a
// not-yet-posted round falls back to the latest one that exists.
func (e *Engine) pollHeatOnce(ctx context.Context) {
	round := roundForTime(e.gameStart, time.Now(), e.gameTick)
	if round < 0 {
		return
	}
	var sb *Scoreboard
	for r := round; r >= round-3 && r >= 0; r-- {
		data, err := FetchRound(e.scoreboardURL, r)
		if err != nil {
			continue
		}
		parsed, err := ParseScoreboard(data)
		if err != nil {
			continue
		}
		sb = parsed
		break
	}
	if sb == nil {
		return
	}
	saveHeat(ctx, e.db.Pool(), ServiceHeat(sb, e.teamID))
}

// saveHeat upserts the current per-service heat snapshot.
func saveHeat(ctx context.Context, pool *pgxpool.Pool, heat map[string]Heat) {
	for service, h := range heat {
		_, err := pool.Exec(ctx, `
			INSERT INTO mine.heat (service, our_lost, our_stolen, total_stolen, our_sla_ok, updated_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (service) DO UPDATE SET
				our_lost = excluded.our_lost, our_stolen = excluded.our_stolen,
				total_stolen = excluded.total_stolen, our_sla_ok = excluded.our_sla_ok,
				updated_at = now()
		`, service, h.OurLost, h.OurStolen, h.TotalStolen, h.OurSLAOk)
		if err != nil {
			log.Println("minecore: save heat:", err)
			return
		}
	}
}
