package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var configDir = "/config"

func init() {
	if d := os.Getenv("AD_INFRA_CONFIG_DIR"); d != "" {
		configDir = d
	}
}

type fileCache struct {
	mu     sync.Mutex
	path   string
	mtime  time.Time
	data   map[string]interface{}
}

func (fc *fileCache) load() map[string]interface{} {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	st, err := os.Stat(fc.path)
	if err != nil {
		return fc.data
	}
	if st.ModTime().Equal(fc.mtime) {
		return fc.data
	}

	raw, err := os.ReadFile(fc.path)
	if err != nil {
		return fc.data
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		fmt.Fprintf(os.Stderr, "config: parse %s: %v\n", fc.path, err)
		return fc.data
	}

	fc.mtime = st.ModTime()
	fc.data = data
	return data
}

var (
	gameFile    = &fileCache{path: filepath.Join(configDir, "game.yml")}
	vulnboxFile = &fileCache{path: filepath.Join(configDir, "vulnbox.yml")}
)

func getString(fc *fileCache, key string, fallback string) string {
	data := fc.load()
	if data == nil {
		return fallback
	}
	v, ok := data[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	return s
}

func getInt(fc *fileCache, key string, fallback int) int {
	data := fc.load()
	if data == nil {
		return fallback
	}
	v, ok := data[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return fallback
	}
}

// Game config

func GameStart() string       { return getString(gameFile, "start", "") }
func GameTickDurationSec() int { return getInt(gameFile, "tick_duration_sec", 120) }
func GameTickLengthMs() int    { return GameTickDurationSec() * 1000 }
func GameFlagRegex() string    { return getString(gameFile, "flag_regex", "[A-Z0-9]{31}=") }
func GameFlagLifetimeTicks() int { return getInt(gameFile, "flag_lifetime_ticks", 5) }

// Vulnbox config

func VulnboxIP() string { return getString(vulnboxFile, "ip", "") }
