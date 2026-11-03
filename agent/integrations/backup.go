package integrations

// Backup monitoring (INF-027): when did the last good backup finish, how big was it, and is it
// older than allowed. Sources: pgBackRest (`pgbackrest info --output=json`, run from a locally
// configured path without a shell), dump files on disk (mysqldump, mongodump, pg_dump: the
// newest file matching a glob), and cloud snapshots (EBS volume and RDS instance snapshots,
// backup_cloud.go). Every source emits backup.age, backup.size and backup.ok (age within
// max_age).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	defaultMaxBackupAge = 26 * time.Hour
	maxBackupSources    = 100
	maxGlobMatches      = 10_000
)

// PgBackRest is one pgBackRest repository.
type PgBackRest struct {
	Name   string `json:"name"`
	Path   string `json:"path"`   // the pgbackrest binary
	Stanza string `json:"stanza"` // empty: every stanza
	MaxAge string `json:"max_age"`
}

// DumpFiles is a set of dump files; the newest one counts.
type DumpFiles struct {
	Name     string `json:"name"`
	Glob     string `json:"glob"`      // e.g. /backups/mysql/*.sql.gz
	Kind     string `json:"kind"`      // mysqldump, mongodump, pg_dump, ... (a label only)
	MinBytes int64  `json:"min_bytes"` // a smaller newest file is not a good backup
	MaxAge   string `json:"max_age"`
}

// BackupConfig is the backup module's config (agent file only).
type BackupConfig struct {
	Base
	PgBackRest []PgBackRest `json:"pgbackrest"`
	Files      []DumpFiles  `json:"files"`
	Snapshots  []Snapshot   `json:"snapshots"`
}

var stanzaRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func (c *BackupConfig) check() error {
	if len(c.PgBackRest)+len(c.Files)+len(c.Snapshots) > maxBackupSources {
		return errors.New("backup: too many sources")
	}
	for _, p := range c.PgBackRest {
		if p.Name == "" || p.Path == "" || p.Stanza != "" && !stanzaRe.MatchString(p.Stanza) {
			return errors.New("backup: pgbackrest needs name, path and a plain stanza name")
		}
	}
	for _, f := range c.Files {
		if f.Name == "" || f.Glob == "" {
			return errors.New("backup: files need name and glob")
		}
		if _, err := filepath.Match(f.Glob, ""); err != nil {
			return fmt.Errorf("backup: bad glob %q", f.Glob)
		}
	}
	for _, s := range c.Snapshots {
		if err := s.check(); err != nil {
			return err
		}
	}
	return nil
}

func maxAge(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return defaultMaxBackupAge
}

// emitBackup writes the three series of one backup; last is zero when none was ever found.
func emitBackup(out sink.Sink, a map[string]string, last time.Time, size float64, limit time.Duration, now time.Time) {
	ok := 0.0
	if !last.IsZero() {
		age := now.Sub(last).Seconds()
		out.Gauge("backup.age", "s", max(age, 0), a, now)
		out.Gauge("backup.size", "By", size, a, now)
		if now.Sub(last) <= limit {
			ok = 1
		}
	}
	out.Gauge("backup.ok", "1", ok, a, now)
}

type pgbrInfo []struct {
	Name   string `json:"name"`
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
	Backup []struct {
		Label     string `json:"label"`
		Type      string `json:"type"`
		Error     bool   `json:"error"`
		Timestamp struct {
			Stop int64 `json:"stop"`
		} `json:"timestamp"`
		Info struct {
			Size       float64 `json:"size"`
			Repository struct {
				Size float64 `json:"size"`
			} `json:"repository"`
		} `json:"info"`
	} `json:"backup"`
}

// EmitPgBackRest reads `pgbackrest info --output=json`: per stanza and backup type, the newest
// backup without an error.
func EmitPgBackRest(out sink.Sink, p PgBackRest, b []byte, now time.Time) error {
	var info pgbrInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return errors.New("backup: pgbackrest output is not JSON")
	}
	for _, st := range info {
		newest := map[string]int{} // type -> index of the newest good backup
		for i, bk := range st.Backup {
			if bk.Error {
				continue
			}
			if j, ok := newest[bk.Type]; !ok || bk.Timestamp.Stop > st.Backup[j].Timestamp.Stop {
				newest[bk.Type] = i
			}
		}
		base := map[string]string{"backup.name": p.Name, "backup.kind": "pgbackrest", "backup.target": st.Name}
		out.Gauge("backup.repository.ok", "1", b2f(st.Status.Code == 0), base, now)
		if len(newest) == 0 {
			emitBackup(out, sink.With(base, "backup.type", "full"), time.Time{}, 0, maxAge(p.MaxAge), now)
		}
		for typ, i := range newest {
			bk := st.Backup[i]
			emitBackup(out, sink.With(base, "backup.type", typ), time.Unix(bk.Timestamp.Stop, 0), bk.Info.Repository.Size, maxAge(p.MaxAge), now)
		}
	}
	return nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func runPgBackRest(ctx context.Context, p PgBackRest) ([]byte, error) {
	if st, err := os.Stat(p.Path); err != nil || st.IsDir() {
		return nil, errors.New("backup: pgbackrest not found at the configured path")
	}
	args := []string{"info", "--output=json"}
	if p.Stanza != "" {
		args = append(args, "--stanza="+p.Stanza)
	}
	cmd := exec.CommandContext(ctx, p.Path, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, errors.New("backup: pgbackrest info failed") // stderr may name hosts and paths
	}
	return buf.Bytes(), nil
}

// EmitDumpFiles reports the newest file matching the glob that is at least MinBytes.
func EmitDumpFiles(out sink.Sink, f DumpFiles, now time.Time) error {
	matches, err := filepath.Glob(f.Glob)
	if err != nil {
		return err
	}
	var last time.Time
	var size int64
	for i, m := range matches {
		if i >= maxGlobMatches {
			break
		}
		st, err := os.Stat(m)
		if err != nil || st.Size() < f.MinBytes {
			continue
		}
		if st.IsDir() { // mongodump writes a directory: its mtime and no size
			if st.ModTime().After(last) {
				last, size = st.ModTime(), 0
			}
			continue
		}
		if st.ModTime().After(last) {
			last, size = st.ModTime(), st.Size()
		}
	}
	kind := f.Kind
	if kind == "" {
		kind = "file"
	}
	emitBackup(out, map[string]string{"backup.name": f.Name, "backup.kind": kind, "backup.target": filepath.Dir(f.Glob)},
		last, float64(size), maxAge(f.MaxAge), now)
	return nil
}

// Backup is the backup module: every interval (default 5 min), each source is read.
func Backup(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &BackupConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if len(c.PgBackRest)+len(c.Files)+len(c.Snapshots) == 0 {
		<-ctx.Done()
		return nil
	}
	cl := newSnapshotClient()
	return Loop(ctx, "backup", c.Base, 5*time.Minute, out, func(ctx context.Context, now time.Time) error {
		var first error
		keep := func(err error) {
			if first == nil {
				first = err
			}
		}
		for _, p := range c.PgBackRest {
			b, err := runPgBackRest(ctx, p)
			if err == nil {
				err = EmitPgBackRest(out, p, b, now)
			}
			if err != nil {
				out.Gauge("backup.ok", "1", 0, map[string]string{"backup.name": p.Name, "backup.kind": "pgbackrest"}, now)
				keep(err)
			}
		}
		for _, f := range c.Files {
			if err := EmitDumpFiles(out, f, now); err != nil {
				keep(err)
			}
		}
		for _, s := range c.Snapshots {
			if err := cl.emit(ctx, out, s, now); err != nil {
				keep(err)
			}
		}
		return first
	})
}
