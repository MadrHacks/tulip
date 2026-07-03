package config

import (
	"fmt"
	"net/url"
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
	mu    sync.Mutex
	name  string
	mtime time.Time
	data  map[string]interface{}
}

func (fc *fileCache) load() map[string]interface{} {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Resolve against configDir at load time, not at package init: init() sets
	// configDir from AD_INFRA_CONFIG_DIR only after package vars are evaluated.
	path := filepath.Join(configDir, fc.name)
	st, err := os.Stat(path)
	if err != nil {
		return fc.data
	}
	if st.ModTime().Equal(fc.mtime) {
		return fc.data
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fc.data
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		fmt.Fprintf(os.Stderr, "config: parse %s: %v\n", path, err)
		return fc.data
	}

	fc.mtime = st.ModTime()
	fc.data = data
	return data
}

var (
	gameFile     = &fileCache{name: "game.yml"}
	vulnboxFile  = &fileCache{name: "vulnbox.yml"}
	servicesFile = &fileCache{name: "services.yml"}
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

func GameStart() string          { return getString(gameFile, "start", "") }
func GameTickDurationSec() int   { return getInt(gameFile, "tick_duration_sec", 120) }
func GameTickLengthMs() int      { return GameTickDurationSec() * 1000 }
func GameFlagRegex() string      { return getString(gameFile, "flag_regex", "[A-Z0-9]{31}=") }
func GameFlagLifetimeTicks() int { return getInt(gameFile, "flag_lifetime_ticks", 5) }
func GameserverURL() string      { return getString(gameFile, "gameserver_url", "") }
func TeamID() int                { return getInt(gameFile, "team_id", -1) }

// ScoreboardBaseURL is the gameserver origin (scheme://host, without the flag
// submission port or path) where the scoreboard API lives.
func ScoreboardBaseURL() string {
	u, err := url.Parse(GameserverURL())
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Scheme + "://" + u.Hostname()
}

// Vulnbox config

func VulnboxIP() string { return getString(vulnboxFile, "ip", "") }

// Services config

// ServiceByPort maps each service port to its logical service name, from
// services.yml (ports grouped under a name), so analysis shards by service: a
// service's multiple ports collapse to one name.
func ServiceByPort() map[int]string {
	out := map[int]string{}
	list, _ := servicesFile.load()["services"].([]interface{})
	for _, item := range list {
		svc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := svc["name"].(string)
		ports, _ := svc["ports"].([]interface{})
		for _, p := range ports {
			switch n := p.(type) {
			case int:
				out[n] = name
			case float64:
				out[int(n)] = name
			}
		}
	}
	return out
}
