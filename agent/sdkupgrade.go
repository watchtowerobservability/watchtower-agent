package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/autoinst"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
	"github.com/watchtowerobservability/watchtower-agent/internal/relsig"
)

// sdkTarget is one service the server asks this host to move to another auto-instrumentation
// version (remote SDK upgrade, `GET /v1/sdk-upgrades?kind=host`). Targets are per host: a service
// on N hosts has N targets, each reported by its own agent.
type sdkTarget struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Language string `json:"language"`
	Version  string `json:"version"`
	Restart  bool   `json:"restart"`
}

// SDKRegister tells the server which (language, service) pairs this host runs.
func (f *Fleet) SDKRegister(ctx context.Context, agent string, services [][2]string) error {
	type hs struct {
		Language string `json:"language"`
		Service  string `json:"service"`
	}
	list := make([]hs, 0, len(services))
	for _, s := range services {
		list = append(list, hs{s[0], s[1]})
	}
	b, _ := json.Marshal(map[string]any{"agent": agent, "services": list})
	resp, err := f.do(ctx, http.MethodPost, "/v1/sdk-upgrades/hosts", b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sdk upgrade hosts: status %d", resp.StatusCode)
	}
	return nil
}

// SDKPending lists this host's pending targets.
func (f *Fleet) SDKPending(ctx context.Context, agent string) ([]sdkTarget, error) {
	resp, err := f.do(ctx, http.MethodGet, "/v1/sdk-upgrades?"+url.Values{"kind": {"host"}, "agent": {agent}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sdk upgrades: status %d", resp.StatusCode)
	}
	var out struct {
		Targets []sdkTarget `json:"targets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Targets, nil
}

// SDKReport records the progress of one target: applying, done or failed (with the error).
func (f *Fleet) SDKReport(ctx context.Context, agent, id, status, errMsg string) error {
	body := map[string]any{"kind": "host", "agent": agent, "id": id, "status": status}
	if errMsg != "" {
		body["error"] = errMsg
	}
	b, _ := json.Marshal(body)
	resp, err := f.do(ctx, http.MethodPost, "/v1/sdk-upgrades/report", b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sdk upgrade report: status %d", resp.StatusCode)
	}
	return nil
}

const maxBundleBytes = 256 << 20

// fetchBundle downloads the signed bundle of lang/version from the same package source the agent
// updater uses (the project's registered packages, signed with the release key compiled into this
// binary), verifies signature and SHA-256, and unpacks it under the agents directory. The
// signature is checked before anything is downloaded.
func fetchBundle(ctx context.Context, f *Fleet, hc *http.Client, pub ed25519.PublicKey, cfg autoinst.Config, lang, version string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("no release key compiled in; bundles are refused")
	}
	q := url.Values{"language": {lang}, "version": {version}, "os": {runtime.GOOS}, "arch": {runtime.GOARCH}}
	resp, err := f.do(ctx, http.MethodGet, "/v1/sdk-upgrades/package?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("version %s of %s is not installed and no signed bundle is registered for %s/%s", version, lang, runtime.GOOS, runtime.GOARCH)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bundle lookup: status %d", resp.StatusCode)
	}
	var info struct{ URL, SHA256, Signature string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return err
	}
	sum, err1 := hex.DecodeString(info.SHA256)
	sig, err2 := hex.DecodeString(info.Signature)
	if err1 != nil || err2 != nil || !relsig.Verify(pub, "autoinst-"+lang+"@"+version, runtime.GOOS, runtime.GOARCH, sum, sig) {
		return errors.New("bundle signature does not verify against the release key")
	}
	u, err := url.Parse(info.URL)
	if err != nil || u.Scheme != "https" {
		return errors.New("bundle url must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if hc == nil {
		hc = netguard.Guarded("agent", 5*time.Minute)
	}
	dl, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		return fmt.Errorf("bundle download: status %d", dl.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(dl.Body, maxBundleBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxBundleBytes {
		return errors.New("bundle larger than 256 MiB")
	}
	if got := sha256.Sum256(data); !bytes.Equal(got[:], sum) {
		return errors.New("downloaded bytes do not match the signed hash")
	}
	return autoinst.InstallBundle(cfg, lang, version, data)
}

// upgradeFn applies one target on this host; tests replace it.
var upgradeFn = autoinst.Upgrade

// sdkEnv is what applySDKTargets needs besides the targets.
type sdkEnv struct {
	f     *Fleet
	agent string
	pub   ed25519.PublicKey
	hc    *http.Client // bundle downloads; nil = guarded default
}

// applySDKTargets handles this host's targets (the server only hands out targets of services this
// host registered) and reports each one. A version that is not installed is downloaded and
// verified first; a target fails only when that or the switch itself fails.
func applySDKTargets(ctx context.Context, e sdkEnv, cfg autoinst.Config, ts []sdkTarget) {
	for _, t := range ts {
		if !autoinst.Applies(cfg, t.Language, t.Service) {
			continue
		}
		if err := e.f.SDKReport(ctx, e.agent, t.ID, "applying", ""); err != nil {
			slog.Warn("sdk upgrade report", "error", err)
			continue
		}
		var err error
		if !autoinst.Installed(cfg, t.Language, t.Version) {
			err = fetchBundle(ctx, e.f, e.hc, e.pub, cfg, t.Language, t.Version)
		}
		if err == nil {
			err = upgradeFn(ctx, cfg, t.Language, t.Service, t.Version, t.Restart)
		}
		status, msg := "done", ""
		if err != nil {
			status, msg = "failed", err.Error()
			slog.Warn("sdk upgrade failed", "service", t.Service, "error", err)
		}
		if err := e.f.SDKReport(ctx, e.agent, t.ID, status, msg); err != nil {
			slog.Warn("sdk upgrade report", "error", err)
		}
	}
}

// runSDKUpgrades registers what this host runs and polls for its targets every minute while the
// local config defines the `autoinst` module (the machine's owner opts in there; the server only
// names service and version).
func runSDKUpgrades(ctx context.Context, f *Fleet, agent string, local *LocalConfig) {
	raw, ok := local.Modules["autoinst"]
	if !ok || f == nil {
		return
	}
	var cfg autoinst.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return
	}
	e := sdkEnv{f: f, agent: agent, pub: releasePubKey(), hc: opampHTTP(ctx, local)}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		err := f.SDKRegister(ctx, agent, autoinst.Services(cfg))
		var ts []sdkTarget
		if err == nil {
			ts, err = f.SDKPending(ctx, agent)
		}
		if err != nil {
			if ctx.Err() == nil {
				slog.Debug("sdk upgrades poll", "error", err)
			}
		} else {
			applySDKTargets(ctx, e, cfg, ts)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
