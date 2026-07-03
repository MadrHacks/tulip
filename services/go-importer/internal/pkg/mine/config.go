package mine

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds minecore's runtime parameters. Game timing (tick duration) is
// read from the unified config, never hardcoded; see internal/pkg/config.
type Config struct {
	// Horizon bounds correlation and eviction: nothing older is read or kept.
	Horizon      time.Duration
	PollBatch    int
	PollInterval time.Duration

	// ChainWindow bounds cross-flow value reuse: a value minted in one flow can
	// link to a later flow only within this window. ChainDFMax drops values seen
	// in too many flows (framework constants); ChainMaxSize caps a session.
	ChainWindow  time.Duration
	ChainDFMax   int
	ChainMaxSize int

	// MaxClusters is the hard per-service cluster cap: the least-recently-seen
	// clusters are evicted past it, so a service that mints a cluster per flow
	// (opaque or highly variable traffic) cannot grow memory without bound.
	MaxClusters int

	// ChainDisable turns off cross-flow chain analysis entirely (a load-shed
	// switch): no per-flow token extraction, no chain shards.
	ChainDisable bool
}

func ConfigFromEnv() Config {
	return Config{
		Horizon:      envDuration("MINECORE_HORIZON", 20*time.Minute),
		PollBatch:    envInt("MINECORE_POLL_BATCH", 512),
		PollInterval: envDuration("MINECORE_POLL_INTERVAL", time.Second),
		ChainWindow:  envDuration("MINECORE_CHAIN_WINDOW", 2*time.Minute),
		ChainDFMax:   envInt("MINECORE_CHAIN_DF_MAX", 8),
		ChainMaxSize: envInt("MINECORE_CHAIN_MAX_SIZE", 16),
		MaxClusters:  envInt("MINECORE_MAX_CLUSTERS", 4000),
		ChainDisable: envBool("MINECORE_CHAIN_DISABLE", false),
	}
}

func envBool(key string, def bool) bool {
	switch os.Getenv(key) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("minecore: %s: %v", key, err)
	}
	return d
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("minecore: %s: %v", key, err)
	}
	return n
}
