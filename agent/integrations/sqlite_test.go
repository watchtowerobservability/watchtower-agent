package integrations

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// sqliteFixture writes the 100-byte header of a WAL-mode database with 4096-byte pages, 250
// pages of which 50 are free, and a WAL of 3 frames with the given checkpoint sequence and salt.
func sqliteFixture(t *testing.T, dir string, ckpt, salt uint32) string {
	t.Helper()
	h := make([]byte, 4096)
	copy(h, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(h[16:], 4096)
	h[18], h[19] = 2, 2
	binary.BigEndian.PutUint32(h[28:], 250)
	binary.BigEndian.PutUint32(h[36:], 50)
	p := filepath.Join(dir, "app.db")
	if err := os.WriteFile(p, h, 0o600); err != nil {
		t.Fatal(err)
	}
	w := make([]byte, 32+3*(4096+24))
	binary.BigEndian.PutUint32(w[0:], 0x377f0682)
	binary.BigEndian.PutUint32(w[12:], ckpt)
	binary.BigEndian.PutUint32(w[16:], salt)
	if err := os.WriteFile(p+"-wal", w, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSQLiteHeaderAndWALGeneration(t *testing.T) {
	dir := t.TempDir()
	p := sqliteFixture(t, dir, 7, 0xabc)
	gen := map[string]sqliteGen{}
	now := time.Now()
	var r sink.Recorder
	if err := CollectSQLiteFile(&r, p, gen, now); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"sqlite.pages": 250, "sqlite.freelist.ratio": 0.2, "sqlite.wal_mode": 1,
		"sqlite.wal.frames": 3, "sqlite.wal.generation_age": 0, "sqlite.page_size": 4096} {
		if v, ok := value(&r, name); !ok || v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
	var r2 sink.Recorder
	_ = CollectSQLiteFile(&r2, p, gen, now.Add(90*time.Second))
	if v, _ := value(&r2, "sqlite.wal.generation_age"); v != 90 {
		t.Fatalf("same generation age = %v", v)
	}
	sqliteFixture(t, dir, 8, 0xabd) // the WAL restarted after a checkpoint
	var r3 sink.Recorder
	_ = CollectSQLiteFile(&r3, p, gen, now.Add(120*time.Second))
	if v, _ := value(&r3, "sqlite.wal.generation_age"); v != 0 {
		t.Fatalf("new generation age = %v", v)
	}
	if _, err := ReadSQLiteHeader([]byte("not a database"), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}
