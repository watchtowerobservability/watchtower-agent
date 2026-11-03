package custom

// async-profiler attach (CFT-A15): runs the customer's own asprof binary against matching JVMs and
// posts the result. Opt-in and local-file only: nothing happens without `binary`, the agent bundles
// no native code, and asprof's attach is the JVM's dynamic agent loading, which the operator must
// allow (same user as the JVM, and not disabled by -XX:+DisableAttachMechanism).

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/pprof/profile"
)

// AsyncProfilerConfig is the `async_profiler` module config.
type AsyncProfilerConfig struct {
	Binary   string `json:"binary"`   // absolute path of asprof; required
	Match    string `json:"match"`    // regexp on /proc/<pid>/cmdline; required, must match a java process
	Service  string `json:"service"`  // service name, default the JVM's main class
	Event    string `json:"event"`    // default cpu
	Interval string `json:"interval"` // default 60s, at least 30s
	Seconds  int    `json:"seconds"`  // sampling time per round, default 10
}

// AsyncProfile attaches to every matching JVM each interval until ctx ends. Without a config it waits.
func AsyncProfile(ctx context.Context, raw json.RawMessage, post PostProfile) error {
	var c AsyncProfilerConfig
	if err := json.Unmarshal(raw, &c); len(raw) > 0 && err != nil {
		return fmt.Errorf("async_profiler: %w", err)
	}
	if c.Binary == "" {
		<-ctx.Done()
		return nil
	}
	if !filepath.IsAbs(c.Binary) || c.Match == "" {
		return errors.New("async_profiler: binary must be an absolute path and match is required")
	}
	match, err := regexp.Compile(c.Match)
	if err != nil {
		return fmt.Errorf("async_profiler: match: %w", err)
	}
	if !regexp.MustCompile(`^[a-z_.A-Z0-9]+$`).MatchString(cmp.Or(c.Event, "cpu")) {
		return errors.New("async_profiler: bad event")
	}
	every := time.Minute
	if c.Interval != "" {
		if every, err = time.ParseDuration(c.Interval); err != nil || every < 30*time.Second {
			return errors.New("async_profiler: interval must be at least 30s")
		}
	}
	secs := min(cmp.Or(c.Seconds, 10), int(every.Seconds())-5)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for pid, service := range javaProcs("/proc", match) {
			if err := profileJVM(ctx, c, pid, cmp.Or(c.Service, service), secs, post); err != nil {
				slog.Warn("async_profiler: round failed", "pid", pid, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// javaProcs lists matching java processes as pid -> main class.
func javaProcs(root string, match *regexp.Regexp) map[int]string {
	out := map[int]string{}
	dirs, _ := os.ReadDir(root)
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if filepath.Base(args[0]) != "java" || !match.Match(bytes.ReplaceAll(b, []byte{0}, []byte{' '})) {
			continue
		}
		out[pid] = mainClass(args)
	}
	return out
}

func mainClass(args []string) string {
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-jar" && i+1 < len(args):
			return strings.TrimSuffix(filepath.Base(args[i+1]), ".jar")
		case a == "-cp" || a == "-classpath" || a == "--class-path" || a == "-p" || a == "--module-path":
			i++
		case !strings.HasPrefix(a, "-"):
			return a
		}
	}
	return "jvm"
}

func profileJVM(ctx context.Context, c AsyncProfilerConfig, pid int, service string, secs int, post PostProfile) error {
	dir, err := os.MkdirTemp("", "wt-asprof")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "out.collapsed")
	event := cmp.Or(c.Event, "cpu")
	run, cancel := context.WithTimeout(ctx, time.Duration(secs+30)*time.Second)
	defer cancel()
	// arguments only, no shell; the binary path and event come from the local config file
	cmd := exec.CommandContext(run, c.Binary, "-d", strconv.Itoa(secs), "-e", event, "-o", "collapsed", "-f", out, strconv.Itoa(pid)) //nolint:gosec
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("asprof: %w: %s", err, clipOutput(b))
	}
	f, err := os.Open(out)
	if err != nil {
		return fmt.Errorf("asprof wrote nothing: %w", err)
	}
	defer f.Close()
	gz, err := collapsedToPprof(f, time.Duration(secs)*time.Second, event)
	if err != nil {
		return err
	}
	return post(ctx, service, "cpu", gz)
}

func clipOutput(b []byte) string {
	return string(b[:min(len(b), 300)])
}

// collapsedToPprof turns "a;b;c 12" lines (root first) into a gzip'd pprof.
func collapsedToPprof(r io.Reader, dur time.Duration, event string) ([]byte, error) {
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}},
		PeriodType: &profile.ValueType{Type: event, Unit: "count"}, Period: 1,
		TimeNanos: time.Now().UnixNano(), DurationNanos: dur.Nanoseconds(),
	}
	locs := map[string]*profile.Location{}
	loc := func(name string) *profile.Location {
		if l := locs[name]; l != nil {
			return l
		}
		id := uint64(len(locs) + 1)
		fn := &profile.Function{ID: id, Name: name, SystemName: name}
		l := &profile.Location{ID: id, Line: []profile.Line{{Function: fn}}}
		p.Function, p.Location = append(p.Function, fn), append(p.Location, l)
		locs[name] = l
		return l
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 8<<20)
	for sc.Scan() {
		i := strings.LastIndexByte(sc.Text(), ' ')
		if i <= 0 {
			continue
		}
		n, err := strconv.ParseInt(sc.Text()[i+1:], 10, 64)
		if err != nil {
			continue
		}
		frames := strings.Split(sc.Text()[:i], ";")
		s := &profile.Sample{Value: []int64{n}, Location: make([]*profile.Location, 0, len(frames))}
		for j := len(frames) - 1; j >= 0; j-- { // pprof wants the leaf first
			s.Location = append(s.Location, loc(frames[j]))
		}
		p.Sample = append(p.Sample, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := p.Write(&buf); err != nil { // Write gzips
		return nil, err
	}
	return buf.Bytes(), nil
}
