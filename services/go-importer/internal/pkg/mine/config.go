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
}

func ConfigFromEnv() Config {
	return Config{
		Horizon:      envDuration("MINECORE_HORIZON", 20*time.Minute),
		PollBatch:    envInt("MINECORE_POLL_BATCH", 512),
		PollInterval: envDuration("MINECORE_POLL_INTERVAL", time.Second),
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
