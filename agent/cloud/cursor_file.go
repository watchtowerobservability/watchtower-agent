package cloud

// A BYOC agent has no Postgres, so its App Insights positions live in
// <state_dir>/cloud_pull_cursors.json, the same rule as the hosted cloud_pull_cursors table:
// written only after the sink flushed the spans, so a restart resumes and never skips rows.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// localPullID keys a BYOC pull's positions; its config carries no pull_id (that comes from the
// hosted row). Two pulls of one workspace read the same rows, so sharing the key is safe.
const localPullID = "local"

type fileCursors struct {
	path string
	out  sink.Sink
	mu   sync.Mutex
	at   map[string]time.Time
}

func newFileCursors(stateDir string, out sink.Sink) *fileCursors {
	f := &fileCursors{path: filepath.Join(stateDir, "cloud_pull_cursors.json"), out: out, at: map[string]time.Time{}}
	if b, err := os.ReadFile(f.path); err == nil {
		_ = json.Unmarshal(b, &f.at) // a damaged file starts the pulls from now, as on first run
	}
	return f
}

func (f *fileCursors) LoadCursor(_ context.Context, pull, key string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.at[pull+"/"+key]
	return at, ok
}

func (f *fileCursors) SaveCursor(_ context.Context, pull, key string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.at[pull+"/"+key] = at
	b, err := json.Marshal(f.at)
	if err != nil {
		return err
	}
	return writeAtomic(f.path, b)
}

// Flush confirms delivery when the sink can; one that cannot (no Delivering) is trusted as sent.
func (f *fileCursors) Flush(ctx context.Context) error {
	if d, ok := f.out.(sink.Delivering); ok {
		return d.Flush(ctx)
	}
	return nil
}

// writeAtomic writes via a temp file in the same directory and renames it over path.
func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
