package recv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// FileStatsConfig lists globs; every match reports size and age (`file.size`, `file.mtime`),
// and each glob its match count. Local config only (it names paths).
type FileStatsConfig struct {
	Include  []string `json:"include"`
	Interval string   `json:"interval"` // default 60s
}

const maxFileStats = 1000

// RunFileStats reports until ctx ends.
func RunFileStats(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c FileStatsConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("file_stats: %w", err)
	}
	if len(c.Include) == 0 {
		return errors.New("file_stats: include (globs) is required")
	}
	every, err := interval(c.Interval, time.Minute)
	if err != nil {
		return fmt.Errorf("file_stats: %w", err)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		EmitFileStats(out, c.Include, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// EmitFileStats stats every match of the globs (at most 1000 files in all).
func EmitFileStats(out sink.Sink, globs []string, now time.Time) {
	n := 0
	for _, g := range globs {
		ms, _ := filepath.Glob(g)
		out.Gauge("file.count", "{files}", float64(len(ms)), map[string]string{"file.glob": g}, now)
		for _, m := range ms {
			if n >= maxFileStats {
				return
			}
			st, err := os.Stat(m)
			if err != nil || st.IsDir() {
				continue
			}
			n++
			a := map[string]string{"file.path": m, "file.name": filepath.Base(m)}
			out.Gauge("file.size", "By", float64(st.Size()), a, now)
			out.Gauge("file.mtime", "s", float64(st.ModTime().Unix()), a, now)
		}
	}
}
