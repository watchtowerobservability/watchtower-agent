//go:build linux

package autoinst

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Package variables so tests can point them at a temp dir.
var (
	confPath    = "/etc/watchtower/autoinst.conf" // the shim reads this exact path
	preloadPath = "/etc/ld.so.preload"
	probeCmd    = "/bin/true"
)

func shim(c Config) string { return c.agentsDir() + "/libwtpreload.so" }

func apply(c Config) error {
	if len(c.Rules) == 0 {
		return remove(c)
	}
	so := shim(c)
	if _, err := os.Stat(so); err != nil {
		return fmt.Errorf("autoinst: preload shim: %w", err)
	}
	if err := writeIfChanged(confPath, []byte(RenderConf(c))); err != nil {
		return err
	}
	added, err := editLines(preloadPath, so, true)
	if err != nil || !added {
		return err
	}
	// The shim is now in every new process: prove one still starts, else take it out again.
	if err := exec.Command(probeCmd).Run(); err != nil { //nolint:gosec // fixed path
		_, _ = editLines(preloadPath, so, false)
		return fmt.Errorf("autoinst: a process failed to start with the shim, removed it: %w", err)
	}
	return nil
}

func remove(c Config) error {
	_, err := editLines(preloadPath, shim(c), false)
	if rmErr := os.Remove(confPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		err = errors.Join(err, rmErr)
	}
	return err
}

func writeIfChanged(p string, b []byte) error {
	if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, b) { //nolint:gosec // fixed path
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return atomicWrite(p, b)
}

// editLines adds (or removes) line in the file at p, keeping every other line; it reports
// whether it changed the file.
func editLines(p, line string, add bool) (bool, error) {
	cur, err := os.ReadFile(p) //nolint:gosec // fixed path
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	var keep []string
	found := false
	for _, l := range strings.Split(strings.TrimRight(string(cur), "\n"), "\n") {
		if strings.TrimSpace(l) == line {
			found = true
			if !add {
				continue
			}
		}
		if l != "" {
			keep = append(keep, l)
		}
	}
	if found == add {
		return false, nil
	}
	if add {
		keep = append(keep, line)
	}
	if len(keep) == 0 {
		return true, os.Remove(p)
	}
	return true, atomicWrite(p, []byte(strings.Join(keep, "\n")+"\n"))
}

func atomicWrite(p string, b []byte) error {
	tmp := p + ".wt-tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil { //nolint:gosec // world-readable like ld.so.preload
		return err
	}
	return os.Rename(tmp, p)
}
