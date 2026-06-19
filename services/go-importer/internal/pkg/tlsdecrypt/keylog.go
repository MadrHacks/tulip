package tlsdecrypt

// NSS key-log (SSLKEYLOGFILE) ingestion. Secrets arrive out-of-band as
// "<LABEL> <client_random_hex> <secret_hex>" lines (the format Wireshark uses).
// The store is keyed by client_random — the index both TLS 1.2 and 1.3 expose in
// the ClientHello, so lookup is IP/port independent. The watcher is an
// append-ratchet over a polled file (modelled on cmd/enricher's watchEve),
// resetting the offset on truncation/rotation.

import (
	"bufio"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// KeyLog is a hot-reloaded store of TLS session secrets, keyed by
// client_random hex → label → secret.
type KeyLog struct {
	mu      sync.RWMutex
	secrets map[string]map[string][]byte

	path     string
	offsets  map[string]int64 // per-file read offset for the append ratchet
	interval time.Duration

	// Invoked (off the reload path) with the client_randoms that gained new
	// secrets, so late-arriving keys can trigger retroactive decryption.
	onNewSecrets func([][]byte)
}

// SetOnNewSecrets registers a callback fired whenever newly-loaded key-log
// lines add secrets, with the affected client_randoms. Must be set before the
// watcher does meaningful work; the initial load does not fire it.
func (k *KeyLog) SetOnNewSecrets(fn func([][]byte)) {
	k.mu.Lock()
	k.onNewSecrets = fn
	k.mu.Unlock()
}

// AllClientRandoms returns every client_random in the store, for the startup
// sweep that backfills flows queued by a previous run.
func (k *KeyLog) AllClientRandoms() [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([][]byte, 0, len(k.secrets))
	for cr := range k.secrets {
		if b, err := hex.DecodeString(cr); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// NewKeyLog loads any secrets already present at path (a file or a directory
// of key-log files) and starts a background poller that picks up appended
// secrets. A nil/empty path yields a usable but always-empty store.
func NewKeyLog(path string) *KeyLog {
	k := &KeyLog{
		secrets:  make(map[string]map[string][]byte),
		path:     path,
		offsets:  make(map[string]int64),
		interval: 2 * time.Second,
	}
	if path == "" {
		return k
	}
	k.reload()
	go k.watch()
	return k
}

// newKeyLogFromString builds an in-memory store from key-log text. Used by
// tests; does not start a watcher.
func newKeyLogFromString(data string) *KeyLog {
	k := &KeyLog{secrets: make(map[string]map[string][]byte)}
	k.ingest(strings.NewReader(data), nil)
	return k
}

// HasAny reports whether any secrets are loaded. Used to cheaply gate
// decryption attempts.
func (k *KeyLog) HasAny() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.secrets) > 0
}

// Has reports whether any secret is stored for the given client_random.
func (k *KeyLog) Has(clientRandom []byte) bool {
	key := hex.EncodeToString(clientRandom)
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.secrets[key]
	return ok
}

// Lookup returns the secret for a (client_random, label) pair.
func (k *KeyLog) Lookup(clientRandom []byte, label string) ([]byte, bool) {
	key := hex.EncodeToString(clientRandom)
	k.mu.RLock()
	defer k.mu.RUnlock()
	byLabel, ok := k.secrets[key]
	if !ok {
		return nil, false
	}
	secret, ok := byLabel[label]
	return secret, ok
}

func (k *KeyLog) watch() {
	for range time.Tick(k.interval) {
		k.reload()
	}
}

// reload reads newly-appended bytes from the key-log file(s) at path and
// notifies (once) about any client_randoms that gained secrets.
func (k *KeyLog) reload() {
	info, err := os.Stat(k.path)
	if err != nil {
		return
	}

	touched := make(map[string]struct{})
	if info.IsDir() {
		entries, err := os.ReadDir(k.path)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				k.reloadFile(filepath.Join(k.path, e.Name()), touched)
			}
		}
	} else {
		k.reloadFile(k.path, touched)
	}

	if len(touched) == 0 {
		return
	}
	k.mu.RLock()
	fn := k.onNewSecrets
	k.mu.RUnlock()
	if fn == nil {
		return
	}
	crs := make([][]byte, 0, len(touched))
	for cr := range touched {
		if b, err := hex.DecodeString(cr); err == nil {
			crs = append(crs, b)
		}
	}
	fn(crs)
}

func (k *KeyLog) reloadFile(path string, touched map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}

	k.mu.RLock()
	offset := k.offsets[path]
	k.mu.RUnlock()

	// Truncation / log rotation: start over.
	if info.Size() < offset {
		offset = 0
	}
	if info.Size() == offset {
		return
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	added := k.ingest(f, touched)
	if added > 0 {
		log.Printf("tlsdecrypt: loaded %d secret(s) from %s", added, path)
	}

	k.mu.Lock()
	k.offsets[path] = info.Size()
	k.mu.Unlock()
}

// ingest parses key-log lines from r and merges them into the store. Returns
// the number of secrets added, and records the affected client_randoms (hex)
// in touched.
func (k *KeyLog) ingest(r io.Reader, touched map[string]struct{}) int {
	added := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		label := fields[0]
		clientRandom := strings.ToLower(fields[1])
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			continue
		}

		k.mu.Lock()
		byLabel := k.secrets[clientRandom]
		if byLabel == nil {
			byLabel = make(map[string][]byte)
			k.secrets[clientRandom] = byLabel
		}
		if _, exists := byLabel[label]; !exists {
			added++
			if touched != nil {
				touched[clientRandom] = struct{}{}
			}
		}
		byLabel[label] = secret
		k.mu.Unlock()
	}
	return added
}
