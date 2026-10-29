package custom

import (
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// staleAfter: a *.prom file not rewritten for this long is skipped (the job that wrote it died).
const staleAfter = 10 * time.Minute

// ReadTextfiles forwards the samples of every *.prom file in dir (the node_exporter textfile
// collector format). Files older than staleAfter are skipped and counted in the gauge
// `wt_textfile_stale_files`; unreadable or malformed files are skipped with a debug log.
func ReadTextfiles(dir string, out Sink, now time.Time) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.prom"))
	stale := 0
	emit := func(f func(string, string, float64, map[string]string, time.Time), name string, v float64, attrs map[string]string, at time.Time) {
		if !math.IsNaN(v) {
			f(name, "", v, attrs, at)
		}
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if now.Sub(fi.ModTime()) > staleAfter {
			stale++
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		fams, err := parseProm(io.LimitReader(f, maxScrapeBody))
		f.Close()
		if err != nil {
			slog.Debug("textfile", "path", p, "error", err)
			continue
		}
		for name, fam := range fams {
			for _, m := range fam.GetMetric() {
				attrs := map[string]string{}
				for _, l := range m.GetLabel() {
					attrs[l.GetName()] = l.GetValue()
				}
				forward(fam.GetType(), name, m, sink.Strip(attrs), now, out, emit)
			}
		}
	}
	out.Gauge("wt_textfile_stale_files", "", float64(stale), map[string]string{"dir": filepath.Base(dir)}, now)
}
