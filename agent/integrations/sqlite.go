package integrations

// SQLite as a server-side file (track A1): the `sqlite` module watches database files an app
// exposes by path and reads only their headers (the first 100 bytes of the database, the first 32
// of the WAL), never a page of data and without taking any SQLite lock, so it cannot block the
// app. Per file: size, page size and count, free pages (space VACUUM would return), journal mode,
// WAL size and frames, a leftover rollback journal, and the age of the current WAL generation.
// A WAL that keeps growing with an old generation means checkpoints are starved (a long reader
// or no checkpointer).

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// SQLiteConfig lists the database files (paths or globs, at most 100 files).
type SQLiteConfig struct {
	Base
	Paths []string `json:"paths"`
}

func (c *SQLiteConfig) check() error {
	if len(c.Paths) == 0 {
		return errors.New("sqlite: paths is required")
	}
	return nil
}

// SQLiteHeader is what the module reads from one database file and its WAL.
type SQLiteHeader struct {
	PageSize, Pages, FreePages int64
	WALMode                    bool
	WALSalt                    uint64 // checkpoint sequence and salt-1: changes when the WAL restarts
	WALSize                    int64
}

// ReadSQLiteHeader parses the database header (and WAL header when walHead is 32 bytes).
func ReadSQLiteHeader(dbHead, walHead []byte) (SQLiteHeader, error) {
	var h SQLiteHeader
	if len(dbHead) < 100 || string(dbHead[:16]) != "SQLite format 3\x00" {
		return h, errors.New("sqlite: not a database file")
	}
	h.PageSize = int64(binary.BigEndian.Uint16(dbHead[16:18]))
	if h.PageSize == 1 {
		h.PageSize = 65536
	}
	h.WALMode = dbHead[18] == 2 && dbHead[19] == 2
	h.Pages = int64(binary.BigEndian.Uint32(dbHead[28:32]))
	h.FreePages = int64(binary.BigEndian.Uint32(dbHead[36:40]))
	if len(walHead) >= 32 {
		m := binary.BigEndian.Uint32(walHead[:4])
		if m == 0x377f0682 || m == 0x377f0683 {
			h.WALSalt = uint64(binary.BigEndian.Uint32(walHead[12:16]))<<32 | uint64(binary.BigEndian.Uint32(walHead[16:20]))
		}
	}
	return h, nil
}

func readHead(path string, n int) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	b := make([]byte, n)
	k, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	return b[:k], fi.Size(), nil
}

// SQLite watches the files until ctx ends.
func SQLite(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &SQLiteConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	gen := map[string]sqliteGen{}
	return Loop(ctx, "sqlite", c.Base, 30*time.Second, out, func(_ context.Context, now time.Time) error {
		var files []string
		for _, p := range c.Paths {
			m, _ := filepath.Glob(p)
			files = append(files, m...)
		}
		if len(files) > 100 {
			files = files[:100]
		}
		if len(files) == 0 {
			return errors.New("sqlite: no file matches paths")
		}
		for _, f := range files {
			_ = CollectSQLiteFile(out, f, gen, now)
		}
		return nil
	})
}

type sqliteGen struct {
	salt uint64
	seen time.Time
}

// CollectSQLiteFile reports one database file. gen remembers when each WAL generation was first
// seen. shortcut: the age counts from when the agent first saw the generation (it under-reports
// right after an agent start); upgrade by persisting gen in the state dir.
func CollectSQLiteFile(out sink.Sink, path string, gen map[string]sqliteGen, now time.Time) error {
	dbHead, size, err := readHead(path, 100)
	if err != nil {
		return err
	}
	walHead, walSize, werr := readHead(path+"-wal", 32)
	if werr != nil {
		walHead, walSize = nil, 0
	}
	h, err := ReadSQLiteHeader(dbHead, walHead)
	if err != nil {
		return err
	}
	h.WALSize = walSize
	a := map[string]string{"db.system.name": "sqlite", "db.namespace": path}
	out.Gauge("sqlite.file.size", "By", float64(size), a, now)
	out.Gauge("sqlite.pages", "{pages}", float64(h.Pages), a, now)
	out.Gauge("sqlite.page_size", "By", float64(h.PageSize), a, now)
	out.Gauge("sqlite.freelist.pages", "{pages}", float64(h.FreePages), a, now)
	if h.Pages > 0 {
		out.Gauge("sqlite.freelist.ratio", "1", float64(h.FreePages)/float64(h.Pages), a, now)
	}
	wal := 0.0
	if h.WALMode {
		wal = 1
	}
	out.Gauge("sqlite.wal_mode", "1", wal, a, now)
	if _, jsize, err := readHead(path+"-journal", 0); err == nil {
		out.Gauge("sqlite.journal.size", "By", float64(jsize), a, now)
	}
	if !h.WALMode {
		return nil
	}
	out.Gauge("sqlite.wal.size", "By", float64(h.WALSize), a, now)
	frames := 0.0
	if h.WALSize > 32 {
		frames = float64((h.WALSize - 32) / (h.PageSize + 24))
	}
	out.Gauge("sqlite.wal.frames", "{frames}", frames, a, now)
	age := 0.0 // an empty or missing WAL is fully checkpointed
	if frames > 0 {
		g, ok := gen[path]
		if !ok || g.salt != h.WALSalt {
			g = sqliteGen{salt: h.WALSalt, seen: now}
			gen[path] = g
		}
		age = now.Sub(g.seen).Seconds()
	} else {
		delete(gen, path)
	}
	out.Gauge("sqlite.wal.generation_age", "s", age, a, now)
	return nil
}
