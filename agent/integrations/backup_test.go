package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func backupSample(r *sink.Recorder, name, k, v string) (sink.Sample, bool) {
	for _, s := range r.Samples {
		if s.Name == name && s.Attrs[k] == v {
			return s, true
		}
	}
	return sink.Sample{}, false
}

func TestPgBackRestNewestGoodBackupPerType(t *testing.T) {
	now := time.Unix(1_700_100_000, 0)
	b := []byte(`[{"name":"main","status":{"code":0},"backup":[
	 {"label":"F1","type":"full","timestamp":{"stop":1700000000},"info":{"repository":{"size":100}}},
	 {"label":"F2","type":"full","error":true,"timestamp":{"stop":1700090000},"info":{"repository":{"size":999}}},
	 {"label":"I1","type":"incr","timestamp":{"stop":1700099000},"info":{"repository":{"size":5}}}]}]`)
	rec := &sink.Recorder{}
	if err := EmitPgBackRest(rec, PgBackRest{Name: "pg", MaxAge: "24h"}, b, now); err != nil {
		t.Fatal(err)
	}
	full, ok := backupSample(rec, "backup.age", "backup.type", "full")
	if !ok || full.Value != 100_000 {
		t.Fatalf("full age %+v", full)
	}
	if s, _ := backupSample(rec, "backup.size", "backup.type", "full"); s.Value != 100 {
		t.Fatal("errored backup counted")
	}
	if s, _ := backupSample(rec, "backup.ok", "backup.type", "full"); s.Value != 0 {
		t.Fatal("27h old full should not be ok with max_age 24h")
	}
	if s, _ := backupSample(rec, "backup.ok", "backup.type", "incr"); s.Value != 1 {
		t.Fatal("recent incr should be ok")
	}
	if EmitPgBackRest(rec, PgBackRest{}, []byte("ERROR: [055]"), now) == nil {
		t.Fatal("non-JSON accepted")
	}
}

func TestDumpFilesNewestAboveMinSize(t *testing.T) {
	dir := t.TempDir()
	old, small := filepath.Join(dir, "a.sql.gz"), filepath.Join(dir, "b.sql.gz")
	if err := os.WriteFile(old, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(small, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(old, past, past)
	rec := &sink.Recorder{}
	if err := EmitDumpFiles(rec, DumpFiles{Name: "mysql", Glob: filepath.Join(dir, "*.sql.gz"), Kind: "mysqldump", MinBytes: 1024}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s, _ := backupSample(rec, "backup.size", "backup.name", "mysql"); s.Value != 2048 {
		t.Fatalf("size %v", s.Value)
	}
	if s, _ := backupSample(rec, "backup.ok", "backup.kind", "mysqldump"); s.Value != 1 {
		t.Fatal("2h old dump should be ok")
	}
	rec = &sink.Recorder{}
	_ = EmitDumpFiles(rec, DumpFiles{Name: "none", Glob: filepath.Join(dir, "*.bak")}, time.Now())
	if s, ok := backupSample(rec, "backup.ok", "backup.name", "none"); !ok || s.Value != 0 {
		t.Fatal("no backup must be not ok")
	}
	if _, ok := backupSample(rec, "backup.age", "backup.name", "none"); ok {
		t.Fatal("no age without a backup")
	}
}

func TestEBSSnapshotNewestCompleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") != "DescribeSnapshots" || r.URL.Query().Get("Filter.1.Value.1") != "vol-1" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`<DescribeSnapshotsResponse><snapshotSet>
<item><status>completed</status><startTime>2026-10-31T00:00:00.000Z</startTime><volumeSize>8</volumeSize></item>
<item><status>pending</status><startTime>2026-11-01T00:00:00.000Z</startTime><volumeSize>8</volumeSize></item>
</snapshotSet></DescribeSnapshotsResponse>`))
	}))
	defer srv.Close()
	c := &snapshotClient{hc: srv.Client(), endpoint: func(string, string) string { return srv.URL + "/" }, unsigned: true}
	rec := &sink.Recorder{}
	now := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	if err := c.emit(context.Background(), rec, Snapshot{Name: "db-vol", Provider: "aws_ebs", Region: "eu-west-1", Resource: "vol-1"}, now); err != nil {
		t.Fatal(err)
	}
	if s, _ := backupSample(rec, "backup.age", "backup.target", "vol-1"); s.Value != 25*3600 {
		t.Fatalf("age %v", s.Value)
	}
	if s, _ := backupSample(rec, "backup.ok", "backup.kind", "aws_ebs_snapshot"); s.Value != 1 {
		t.Fatal("25h snapshot is within the default 26h")
	}
	if (Snapshot{Name: "x", Provider: "aws_ebs", Region: "evil.example.com/", Resource: "vol-1"}).check() == nil {
		t.Fatal("bad region accepted")
	}
}
