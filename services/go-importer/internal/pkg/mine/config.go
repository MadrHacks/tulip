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

	// MaxShapes is the hard per-service shape cap: the least-recently-seen shapes
	// are evicted past it (EvictToCap), so a service that mints a shape per flow
	// (opaque or highly variable traffic) cannot grow memory without bound.
	MaxShapes int

	// SplitCard is the cardinality-refinement knob (refine.go): a Drain <*> position
	// with <= SplitCard distinct literals is STRUCTURAL (an opcode / endpoint / verb)
	// and gets un-merged into one sub-shape per literal; more distinct literals mark
	// it a VALUE that stays wildcarded. SplitVariantCap bounds the per-shape reservoir
	// of distinct member skeletons the refinement reads to make that decision.
	SplitCard       int
	SplitVariantCap int

	// ChainDisable turns off cross-flow chain analysis entirely (a load-shed
	// switch): no per-flow token extraction, no chain shards.
	ChainDisable bool
}

func ConfigFromEnv() Config {
	return Config{
		Horizon:         envDuration("MINECORE_HORIZON", 20*time.Minute),
		PollBatch:       envInt("MINECORE_POLL_BATCH", 512),
		PollInterval:    envDuration("MINECORE_POLL_INTERVAL", time.Second),
		ChainWindow:     envDuration("MINECORE_CHAIN_WINDOW", 2*time.Minute),
		ChainDFMax:      envInt("MINECORE_CHAIN_DF_MAX", 8),
		ChainMaxSize:    envInt("MINECORE_CHAIN_MAX_SIZE", 16),
		MaxShapes:       envInt("MINECORE_MAX_SHAPES", 2000),
		ChainDisable:    envBool("MINECORE_CHAIN_DISABLE", false),
		SplitCard:       envInt("MINECORE_SPLIT_CARD", defaultSplitCard),
		SplitVariantCap: envInt("MINECORE_SPLIT_VARIANTS", defaultSplitVariantCap),
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
