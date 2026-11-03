package custom

// Process discovery (CFT-A02, Alloy discovery.process): one target per local process, for
// relabel_configs to keep (e.g. on __meta_process_exe) and point at that process's exporter port.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	procRoot      = "/proc" // tests swap it
	containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)
)

func init() { sdHTTPTypes["process"] = SDConfig.processSD }

// processSD needs Port (the scrape URL is 127.0.0.1:Port). Without a keep rule every process
// yields a target on that same URL, so relabel_configs are where the selection happens.
func (c SDConfig) processSD(_ context.Context, _ *http.Client) ([]TargetSpec, error) {
	if c.Port <= 0 {
		return nil, errors.New("process sd: port is required")
	}
	dirs, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, errors.New("process sd needs Linux /proc: " + err.Error())
	}
	var out []TargetSpec
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, d.Name())
		cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil || len(cmd) == 0 { // gone, or a kernel thread
			continue
		}
		l := map[string]string{
			"__process_pid__":            d.Name(),
			"__meta_process_commandline": strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " ")),
		}
		if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
			l["__meta_process_exe"] = exe
		}
		if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
			l["__meta_process_cwd"] = cwd
		}
		if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			for line := range strings.SplitSeq(string(st), "\n") {
				if v, ok := strings.CutPrefix(line, "Uid:"); ok {
					if f := strings.Fields(v); len(f) > 0 {
						l["__meta_process_uid"] = f[0]
					}
				}
			}
		}
		if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
			if id := containerIDRe.Find(cg); id != nil {
				l["__meta_process_container_id"] = string(id)
			}
		}
		out = append(out, TargetSpec{URL: c.scrapeURL("127.0.0.1", c.Port), Labels: l})
	}
	return out, nil
}
