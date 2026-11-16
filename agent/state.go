package main

// Stable identity, a writable state dir and the health status file the HEALTHCHECK reads.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// usableDir reports whether dir can be created and written.
func usableDir(dir string) bool {
	if os.MkdirAll(dir, 0o750) != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".wt-w-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// resolveStateDir returns dir when writable, else the first writable fallback with a loud
// warning, so a root-owned fresh volume does not stop registration.
func resolveStateDir(dir string) string {
	if usableDir(dir) {
		return dir
	}
	var fb []string
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		fb = append(fb, filepath.Join(x, "wt-agent"))
	}
	fb = append(fb, filepath.Join(os.TempDir(), "wt-agent"))
	for _, d := range fb {
		if usableDir(d) {
			slog.Warn("state_dir is not writable; using a fallback, so identity and buffers may not survive a restart. Fix the volume ownership (uid of the agent) or set state_dir", "state_dir", dir, "using", d, "uid", os.Getuid())
			return d
		}
	}
	slog.Warn("no writable state dir; identity will not persist", "state_dir", dir, "uid", os.Getuid())
	return dir
}

// machineID is a stable per-host id: the hashed machine-id file (WT_AGENT_MACHINE_ID_PATH, else
// /etc/machine-id, /host/etc/machine-id, /var/lib/dbus/machine-id), else a random id kept in <state>/machine-id. The raw
// machine-id is hashed because it is meant to stay private to the host.
func machineID(stateDir string) string {
	paths := []string{"/etc/machine-id", "/host/etc/machine-id", "/var/lib/dbus/machine-id"}
	if p := os.Getenv("WT_AGENT_MACHINE_ID_PATH"); p != "" {
		paths = []string{p}
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			sum := sha256.Sum256([]byte("wt-agent:" + strings.TrimSpace(string(b))))
			return hex.EncodeToString(sum[:16])
		}
	}
	p := filepath.Join(stateDir, "machine-id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b))
	}
	r := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, r)
	id := hex.EncodeToString(r)
	if err := writeFileAtomic(p, []byte(id), 0o640); err != nil {
		// nothing persists (read-only container, no mounts): the hostname keeps the id stable across restarts and retries
		h, _ := os.Hostname()
		sum := sha256.Sum256([]byte("wt-agent:host:" + h))
		slog.Warn("cannot persist machine-id; deriving it from the hostname", "error", err)
		return hex.EncodeToString(sum[:16])
	}
	return id
}

// Health is <state_dir>/health.json: what `wt-agent health` judges.
type Health struct {
	Registered   bool      `json:"registered"`
	AgentID      string    `json:"agent_id,omitempty"`
	LastExportOK time.Time `json:"last_export_ok_at,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

// HealthFile keeps the file current.
type HealthFile struct {
	mu  sync.Mutex
	dir string
	h   Health
}

func NewHealthFile(dir string) *HealthFile { return &HealthFile{dir: dir} }

func (f *HealthFile) update(fn func(h *Health)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.h)
	b, _ := json.Marshal(f.h)
	if err := writeFileAtomic(filepath.Join(f.dir, "health.json"), b, 0o644); err != nil {
		slog.Debug("cannot write health.json", "error", err)
	}
}

func (f *HealthFile) Registered(id string) {
	f.update(func(h *Health) { h.Registered, h.AgentID = true, id })
}

// Export records the outcome of an export attempt.
func (f *HealthFile) Export(err error) {
	f.update(func(h *Health) {
		if err != nil {
			h.LastError = err.Error()
			return
		}
		h.LastExportOK, h.LastError = time.Now().UTC(), ""
	})
}

// checkHealth returns nil when registered and an export succeeded within maxAge.
func checkHealth(dir string, maxAge time.Duration, now time.Time) error {
	b, err := os.ReadFile(filepath.Join(dir, "health.json"))
	if err != nil {
		return fmt.Errorf("no health file: %w", err)
	}
	var h Health
	if err := json.Unmarshal(b, &h); err != nil {
		return err
	}
	switch {
	case !h.Registered:
		return errors.New("not registered yet")
	case h.LastExportOK.IsZero():
		return fmt.Errorf("no successful export yet (last error: %s)", h.LastError)
	case now.Sub(h.LastExportOK) > maxAge:
		return fmt.Errorf("last successful export %s ago (last error: %s)", now.Sub(h.LastExportOK).Round(time.Second), h.LastError)
	}
	return nil
}
