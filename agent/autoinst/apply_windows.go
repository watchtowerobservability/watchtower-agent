//go:build windows

package autoinst

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// statePath remembers what was applied, so a re-apply without changes does not recycle pools
// and a removal knows which pools to clean.
var statePath = filepath.Join(os.Getenv("ProgramData"), "watchtower", "autoinst-iis.json")

func appcmd() string {
	return filepath.Join(os.Getenv("windir"), "system32", "inetsrv", "appcmd.exe")
}

type iisState struct {
	Hash  string   `json:"hash"`
	Pools []string `json:"pools"`
	Vars  []string `json:"vars"`
}

func loadState() iisState {
	var s iisState
	if b, err := os.ReadFile(statePath); err == nil { //nolint:gosec // fixed path
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func apply(c Config) error {
	if len(c.IISPools) == 0 {
		return remove(c)
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	old := loadState()
	if old.Hash == hash {
		return nil
	}
	if err := remove(c); err != nil {
		return err
	}
	st := iisState{Hash: hash}
	for _, p := range c.IISPools {
		for _, kv := range IISEnv(c, p) {
			if err := run(IISArgs(p.Name, kv[0], kv[1])...); err != nil {
				return fmt.Errorf("autoinst: pool %s: %w", p.Name, err)
			}
			st.Vars = appendNew(st.Vars, kv[0])
		}
		st.Pools = append(st.Pools, p.Name)
		_ = run("recycle", "apppool", "/apppool.name:"+p.Name) // a stopped pool cannot recycle
	}
	out, _ := json.Marshal(st)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(statePath, out, 0o600)
}

func remove(Config) error {
	s := loadState()
	var errs []error
	for _, p := range s.Pools {
		for _, k := range s.Vars {
			_ = run(IISRemoveArgs(p, k)...) // absent already is fine
		}
		_ = run("recycle", "apppool", "/apppool.name:"+p)
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func run(args ...string) error {
	out, err := exec.Command(appcmd(), args...).CombinedOutput() //nolint:gosec // fixed binary, validated args
	if err != nil {
		return fmt.Errorf("appcmd %v: %w: %s", args[:min(2, len(args))], err, out)
	}
	return nil
}

func appendNew(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
