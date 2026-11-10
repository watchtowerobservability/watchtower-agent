//go:build linux

package autoinst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"
)

// restartUnit is replaced in tests. The unit comes from the machine's own config, never the server.
var restartUnit = func(ctx context.Context, unit string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil { //nolint:gosec // unit validated by unitRe
		return fmt.Errorf("systemctl restart %s: %w: %.200s", unit, err, out)
	}
	return nil
}

// Upgrade switches lang to version on this host: the version must already be installed under
// AgentsDir/versions/<version>/<lang>. It re-renders the shim's file (running processes keep their
// old agent until they restart), stores the version so later runs keep it, and, when restart is
// asked and the local config allows it, restarts the systemd units of the rules of svc. On any
// error before the switch nothing changes.
func Upgrade(ctx context.Context, c Config, lang, svc, version string, restart bool) error {
	if !slices.Contains(langs, lang) || !versionRe.MatchString(version) {
		return errors.New("unknown language or malformed version")
	}
	c = WithState(c)
	if !c.Enabled {
		return errors.New("autoinst is not enabled on this host")
	}
	if len(matching(c, lang, svc)) == 0 {
		return fmt.Errorf("no autoinst rule for %s service %q", lang, svc)
	}
	if !Installed(c, lang, version) {
		return fmt.Errorf("version %s of %s is not installed under %s/versions", version, lang, c.agentsDir())
	}
	next := c
	next.Versions = map[string]string{}
	for k, v := range c.Versions {
		next.Versions[k] = v
	}
	next.Versions[lang] = version
	if err := next.Validate(); err != nil {
		return err
	}
	if err := apply(next); err != nil {
		return err
	}
	b, _ := json.Marshal(next.Versions)
	if err := os.MkdirAll(filepath.Dir(c.stateFile()), 0o755); err != nil {
		return err
	}
	if err := atomicWrite(c.stateFile(), b); err != nil {
		return err
	}
	if !restart || !c.AllowRestart {
		return nil
	}
	var errs []error
	done := map[string]bool{}
	for _, r := range matching(c, lang, svc) {
		if r.Unit != "" && !done[r.Unit] {
			done[r.Unit] = true
			errs = append(errs, restartUnit(ctx, r.Unit))
		}
	}
	return errors.Join(errs...)
}
