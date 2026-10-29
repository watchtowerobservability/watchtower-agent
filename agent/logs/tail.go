package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	tailEvery    = time.Second
	maxLine      = 64 << 10
	maxReadBytes = 1 << 20
	maxRecLines  = 500             // a multiline record is cut here
	maxRecBytes  = 256 << 10       // ... or this many bytes, whichever comes first
	forgetAfter  = 24 * time.Hour  // offsets of files not matched for this long are pruned
	maxSpecFiles = 200             // files per path pattern
	idleFlush    = 2 * time.Second // a pending multiline record is flushed after this much quiet
)

// TailSpec is one file pattern to follow. All of it comes from the agent's own config file.
type TailSpec struct {
	Path string `json:"path"` // a filepath.Glob pattern
	// MultilineStart is a regex that matches the first line of a record; lines that do not match
	// are joined to the previous record (stack traces). Empty: one line, one record.
	MultilineStart string `json:"multiline_start"`
	// Multiline is the fuller form (pattern, line cap, quiet period); see multiline.go.
	Multiline *Multiline `json:"multiline"`
	// FromBeginning reads files found at startup from their first byte (default: from the end).
	// Files that appear later are always read whole.
	FromBeginning bool              `json:"from_beginning"`
	Labels        map[string]string `json:"labels"`
	// MaxFiles raises the per-pattern file cap (default 200, at most 5000); the Kubernetes node
	// agent needs it for nodes with many containers.
	MaxFiles int `json:"max_files"`
}

type compiled struct {
	TailSpec
	re       *regexp.Regexp
	maxLines int
	maxWait  time.Duration
}

// Entry is what is remembered per file identity.
type Entry struct {
	Off   int64 `json:"off"`
	Size  int64 `json:"size"`  // size when last read
	MTime int64 `json:"mtime"` // mtime (unix ns) when last read
	Seen  int64 `json:"seen"`  // unix seconds the file was last matched
}

// State persists, per file identity (device+inode, or volume+index on Windows), the offset up to
// which records were delivered, so a restart resumes exactly there and a rename keeps its place.
// Size and mtime expose a reused inode: a "new" file that is smaller or older than what was
// last read under that identity starts at 0. It is written (fsync) only when something changed.
type State struct {
	path  string
	mu    sync.Mutex
	dirty bool
	Off   map[string]Entry `json:"offsets"`
}

// LoadState reads <dir>/tail-offsets.json; a missing or torn file starts empty.
func LoadState(dir string) *State {
	s := &State{path: filepath.Join(dir, "tail-offsets.json"), Off: map[string]Entry{}}
	if b, err := os.ReadFile(s.path); err == nil {
		if json.Unmarshal(b, s) != nil || s.Off == nil {
			s.Off = map[string]Entry{}
		}
	}
	return s
}

func (s *State) get(id string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.Off[id]
	return e, ok
}

// set stores e; only a change of offset, size or mtime marks the state dirty.
func (s *State) set(id string, e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.Off[id]
	if !ok || old.Off != e.Off || old.Size != e.Size || old.MTime != e.MTime {
		s.dirty = true
	}
	s.Off[id] = e
}

// prune forgets files not matched for forgetAfter.
func (s *State) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.Off {
		if now.Unix()-e.Seen > int64(forgetAfter.Seconds()) {
			delete(s.Off, id)
			s.dirty = true
		}
	}
}

// Save writes the state atomically (temp file, fsync, rename) if it changed.
func (s *State) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, b); err != nil {
		return err
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

type pending struct {
	lines []string
	bytes int
	start int64 // offset of the record's first line
	last  time.Time
}

// Tailer follows files.
type Tailer struct {
	specs   []compiled
	state   *State
	out     sink.Sink
	pos     map[string]int64 // read position (ahead of the persisted offset while a record is pending)
	pend    map[string]*pending
	started bool
}

// NewTailer compiles the specs.
func NewTailer(specs []TailSpec, st *State, out sink.Sink) (*Tailer, error) {
	t := &Tailer{state: st, out: out, pos: map[string]int64{}, pend: map[string]*pending{}}
	for _, s := range specs {
		if s.Path == "" {
			return nil, errors.New("tail: path is empty")
		}
		c := compiled{TailSpec: s}
		pattern, maxLines, maxWait := s.resolve()
		c.maxLines, c.maxWait = maxLines, maxWait
		if pattern != "" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("tail %s: multiline start pattern: %w", s.Path, err)
			}
			c.re = re
		}
		t.specs = append(t.specs, c)
	}
	return t, nil
}

// RunTail polls the files until ctx ends.
func RunTail(ctx context.Context, specs []TailSpec, stateDir string, out sink.Sink) error {
	t, err := NewTailer(specs, LoadState(stateDir), out)
	if err != nil {
		return err
	}
	tk := time.NewTicker(tailEvery)
	defer tk.Stop()
	for {
		t.Poll(time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
		}
	}
}

// Poll reads what each file gained since the last poll, delivers complete records and persists
// the offsets.
func (t *Tailer) Poll(now time.Time) {
	for _, s := range t.specs {
		paths, _ := filepath.Glob(s.Path)
		limit := maxSpecFiles
		if s.MaxFiles > limit {
			limit = min(s.MaxFiles, 5000)
		}
		if len(paths) > limit {
			paths = paths[:limit]
		}
		for _, p := range paths {
			if err := t.file(s, p, now); err != nil {
				slog.Debug("tail", "path", p, "error", err)
			}
		}
	}
	t.started = true
	t.state.prune(now)
	if err := t.state.Save(); err != nil {
		slog.Warn("cannot persist tail offsets", "error", err)
	}
}

func (t *Tailer) file(s compiled, path string, now time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return err
	}
	id := fileID(f, fi)
	pos, ok := t.pos[id]
	if !ok {
		var e Entry
		if e, ok = t.state.get(id); ok {
			pos = e.Off
			if fi.Size() < e.Size || fi.ModTime().UnixNano() < e.MTime {
				pos = 0 // a different file under a reused inode
			}
		}
	}
	if !ok && !s.FromBeginning && !t.started {
		pos = fi.Size() // an existing file seen for the first time: only new lines
	}
	if fi.Size() < pos { // truncated (copytruncate)
		pos = 0
		delete(t.pend, id)
	}
	buf := make([]byte, min(maxReadBytes, max(fi.Size()-pos, 0)))
	n, err := f.ReadAt(buf, pos)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	buf = buf[:n]
	end := bytes.LastIndexByte(buf, '\n') + 1
	if end == 0 && len(buf) >= maxReadBytes {
		end = len(buf) // one enormous line: cut it
	}
	off := pos
	for _, ln := range bytes.SplitAfter(buf[:end], []byte("\n")) {
		if len(ln) == 0 {
			continue
		}
		t.line(s, path, id, strings.TrimRight(string(ln), "\r\n"), off, now)
		off += int64(len(ln))
	}
	t.pos[id] = pos + int64(end)
	if p := t.pend[id]; p != nil && end == 0 && now.Sub(p.last) >= s.maxWait {
		t.flush(s, path, id)
	}
	e := Entry{Off: t.pos[id], Size: fi.Size(), MTime: fi.ModTime().UnixNano(), Seen: now.Unix()}
	if p := t.pend[id]; p != nil {
		e.Off = p.start
	}
	t.state.set(id, e)
	return nil
}

func (t *Tailer) line(s compiled, path, id, text string, at int64, now time.Time) {
	text = sink.Truncate(text, maxLine)
	if s.re == nil {
		t.emit(s, path, text, now)
		return
	}
	p := t.pend[id]
	if p != nil && s.re.MatchString(text) {
		t.flush(s, path, id)
		p = nil
	}
	if p == nil {
		p = &pending{start: at}
		t.pend[id] = p
	}
	p.lines = append(p.lines, text)
	p.bytes += len(text) + 1
	p.last = now
	if len(p.lines) >= s.maxLines || p.bytes >= maxRecBytes {
		t.flush(s, path, id)
	}
}

func (t *Tailer) flush(s compiled, path, id string) {
	p := t.pend[id]
	if p == nil {
		return
	}
	delete(t.pend, id)
	t.emit(s, path, strings.Join(p.lines, "\n"), p.last)
}

func (t *Tailer) emit(s compiled, path, body string, at time.Time) {
	t.out.Log(Severity(body), body, sink.With(s.Labels, "log.file.path", path), at)
}

// Severity guesses a level from the first line of a record; it defaults to INFO.
func Severity(body string) string {
	head := body
	if i := strings.IndexByte(head, '\n'); i >= 0 {
		head = head[:i]
	}
	if len(head) > 200 {
		head = head[:200]
	}
	h := strings.ToUpper(head)
	switch {
	case strings.Contains(h, "ERROR"), strings.Contains(h, "FATAL"), strings.Contains(h, "PANIC"), strings.Contains(h, "CRIT"):
		return "ERROR"
	case strings.Contains(h, "WARN"):
		return "WARN"
	case strings.Contains(h, "DEBUG"), strings.Contains(h, "TRACE"):
		return "DEBUG"
	}
	return "INFO"
}
