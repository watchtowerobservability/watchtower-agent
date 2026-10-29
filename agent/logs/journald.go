package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

var journalPriority = [8]string{"ERROR", "ERROR", "ERROR", "ERROR", "WARN", "INFO", "INFO", "DEBUG"}

// ParseJournalLine parses one line of `journalctl -o json`.
func ParseJournalLine(line []byte) (Record, error) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return Record{}, err
	}
	s := func(k string) string { v, _ := e[k].(string); return v }
	body := s("MESSAGE")
	if body == "" {
		// journald writes non-UTF-8 messages as an array of byte values
		if arr, ok := e["MESSAGE"].([]any); ok {
			b := make([]byte, 0, len(arr))
			for _, x := range arr {
				if f, ok := x.(float64); ok {
					b = append(b, byte(f))
				}
			}
			body = string(b)
		}
	}
	if body == "" {
		return Record{}, errors.New("journal entry without MESSAGE")
	}
	sev := "INFO"
	if p, err := strconv.Atoi(s("PRIORITY")); err == nil && p >= 0 && p < len(journalPriority) {
		sev = journalPriority[p]
	}
	at := time.Now()
	if us, err := strconv.ParseInt(s("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		at = time.UnixMicro(us)
	}
	attrs := map[string]string{"log.source": "journald"}
	for k, to := range map[string]string{
		"_SYSTEMD_UNIT": "systemd.unit", "SYSLOG_IDENTIFIER": "syslog.app", "_HOSTNAME": "syslog.hostname",
		"_PID": "process.pid", "_COMM": "process.executable.name",
	} {
		if v := s(k); v != "" {
			attrs[to] = v
		}
	}
	return Record{Severity: sev, Body: body, At: at, Attrs: attrs, Cursor: s("__CURSOR")}, nil
}

const cursorSaveEvery = 5 * time.Second

// RunJournald follows the journal with `journalctl -o json -f`. It keeps the __CURSOR of the last
// record in <stateDir>/journald.cursor (written atomically, at most every 5 s and when the
// process ends) and resumes with --after-cursor, so a restart neither loses the downtime nor
// replays more than a few seconds. The binary path is local config only. Off Linux it waits.
func RunJournald(ctx context.Context, path, stateDir string, out sink.Sink) error {
	if runtime.GOOS != "linux" {
		slog.Warn("journald is only available on Linux")
		<-ctx.Done()
		return nil
	}
	if path == "" {
		path = "journalctl"
	}
	file := filepath.Join(stateDir, "journald.cursor")
	for ctx.Err() == nil {
		followJournal(ctx, path, file, out)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

func followJournal(ctx context.Context, path, cursorFile string, out sink.Sink) {
	args := []string{"-o", "json", "-f", "--no-pager"}
	saved := ""
	if b, err := os.ReadFile(cursorFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
		saved = string(bytes.TrimSpace(b))
		args = append(args, "--after-cursor="+saved)
	} else {
		args = append(args, "-n", "0")
	}
	// Cancelling rctx kills journalctl, so Wait can never hang on a full pipe.
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(rctx, path, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	pipe, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		slog.Warn("journalctl", "error", err)
		return
	}
	cursor, lastSave := saved, time.Now()
	save := func() {
		if cursor == saved {
			return
		}
		if err := writeFileAtomic(cursorFile, []byte(cursor)); err != nil {
			slog.Warn("cannot persist journald cursor", "error", err)
			return
		}
		saved, lastSave = cursor, time.Now()
	}
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		r, err := ParseJournalLine(sc.Bytes())
		if err != nil {
			continue
		}
		r.send(out, nil)
		if r.Cursor != "" {
			cursor = r.Cursor
		}
		if time.Since(lastSave) >= cursorSaveEvery {
			save()
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		// cannot skip one oversized entry without its cursor: continue from the live end
		cursor = ""
		_ = os.Remove(cursorFile)
		saved = ""
	}
	save()
	cancel()
	_ = cmd.Wait()
}
