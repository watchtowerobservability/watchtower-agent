// Package logs collects system logs: file tails (with offsets kept per inode and multiline
// joining), journald, the Windows Event Log and a syslog receiver, all forwarded as OTLP logs.
package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Record is one log record before export.
type Record struct {
	Severity string // DEBUG, INFO, WARN or ERROR
	Body     string
	At       time.Time
	Attrs    map[string]string
	Cursor   string // journald __CURSOR
}

func (r Record) send(out sink.Sink, extra map[string]string) {
	out.Log(r.Severity, r.Body, sink.With(r.Attrs, flat(extra)...), r.At)
}

func flat(m map[string]string) []string {
	kv := make([]string, 0, 2*len(m))
	for k, v := range m {
		kv = append(kv, k, v)
	}
	return kv
}

// Config is the logs module's config. Only Enabled can be set remotely (Interval has no
// meaning here); every path, command and listen address is local-file only.
type Config struct {
	Enabled *bool       `json:"enabled"`
	Files   []TailSpec  `json:"files"`
	Journal *Journal    `json:"journald"`
	WinEvt  *WinEvent   `json:"windows_events"`
	Syslog  *SyslogConf `json:"syslog"`
	Docker  *DockerLogs `json:"docker"`
	Kafka   *KafkaLogs  `json:"kafka"`
}

// Journal enables the journald reader.
type Journal struct {
	Path string `json:"journalctl_path"` // default "journalctl"
}

// Run starts every configured source and blocks until ctx ends or one fails.
func Run(ctx context.Context, raw json.RawMessage, stateDir string, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	start := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	if len(c.Files) > 0 {
		start("tail", func() error { return RunTail(ctx, c.Files, stateDir, out) })
	}
	if c.Journal != nil {
		start("journald", func() error { return RunJournald(ctx, c.Journal.Path, stateDir, out) })
	}
	if c.WinEvt != nil {
		start("windows_events", func() error { return RunWinEvents(ctx, *c.WinEvt, out) })
	}
	if c.Syslog != nil {
		start("syslog", func() error { return RunSyslog(ctx, *c.Syslog, out) })
	}
	if c.Docker != nil {
		start("docker", func() error { return RunDocker(ctx, *c.Docker, stateDir, out) })
	}
	if c.Kafka != nil {
		start("kafka", func() error { return RunKafka(ctx, *c.Kafka, out) })
	}
	select {
	case <-ctx.Done():
	case err := <-errs:
		slog.Warn("log source stopped", "error", err)
		cancel()
		wg.Wait()
		return err
	}
	wg.Wait()
	return nil
}

// writeFileAtomic writes via a temp file in the same directory, fsyncs it and renames it over
// path, so a crash leaves the old file or the new one, never a torn one.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
