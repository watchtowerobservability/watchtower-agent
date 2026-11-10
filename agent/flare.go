package main

// `wt-agent flare [-out FILE.zip]`: a support bundle made locally, never uploaded. It holds the
// version, the explain output (modules, targets and secret-reference health, every value
// redacted) and, when the status page is on and the agent runs, its status snapshot. No config
// file, token or environment is copied.

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

func flare(ctx context.Context, cfgPath, outPath string) error {
	var ex bytes.Buffer
	local, lerr := LoadLocal(cfgPath)
	if lerr != nil {
		fmt.Fprintf(&ex, "config could not be loaded: %s\n", redactValue(lerr.Error()))
	} else if err := explain(ctx, cfgPath, "", &ex); err != nil {
		fmt.Fprintf(&ex, "explain failed: %s\n", redactValue(err.Error()))
	}
	files := []struct {
		name string
		body []byte
	}{
		{"version.txt", []byte(fmt.Sprintf("wt-agent %s\n%s/%s\ngo %s\ncreated %s\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), time.Now().UTC().Format(time.RFC3339)))},
		{"explain.txt", ex.Bytes()},
	}
	if lerr == nil && local.StatusListen != "" {
		if b := fetchStatus(ctx, local.StatusListen); b != nil {
			files = append(files, struct {
				name string
				body []byte
			}{"status.json", b})
		}
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	for _, e := range files {
		w, err := zw.Create(e.name)
		if err != nil {
			_ = f.Close()
			return err
		}
		if _, err := w.Write(e.body); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// fetchStatus reads the running agent's snapshot; nil when it is not running.
func fetchStatus(ctx context.Context, addr string) []byte {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/status.json", nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b
}
