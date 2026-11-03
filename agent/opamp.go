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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-agent/agent/commands"
	"github.com/watchtowerobservability/watchtower-agent/internal/relsig"
)

// ReleaseKey is the hex Ed25519 public key that signs agent packages. It is compiled in
// (-ldflags "-X main.ReleaseKey=...") so a fleet server cannot choose it. Empty: packages are
// refused.
var ReleaseKey = ""

const (
	flareCapability   = "io.watchtower.flare"
	commandCapability = "io.watchtower.command"
	packageName       = "wt-agent"
	maxPackageBytes   = 256 << 20
)

// OpAMPClient runs the agent as an OpAMP client of wt-fleet: it takes remote config, reports
// the effective config, health and package state, answers flare requests and verifies package
// signatures. It is selected with `fleet_mode: opamp` and replaces the edge long poll.
type OpAMPClient struct {
	Endpoint string // https://host/v1/opamp
	Token    string
	AgentID  string // UUID; becomes the OpAMP instance uid
	Info     HostInfo
	StateDir string
	// Apply installs a remote config body; its error is reported to the server as FAILED.
	Apply func(body []byte) error
	// Allow is the agent's own command allowlist; the server can only name entries of it.
	Allow []commands.Command
	// StageOnly downloads and verifies a package but leaves the binary alone.
	StageOnly bool
	// PubKey verifies package signatures; nil refuses every package.
	PubKey ed25519.PublicKey
	// HTTP downloads packages; nil = a guarded client with a 5 minute timeout.
	HTTP *http.Client
	// Health reports the per-module state (CFT-A24); Tap runs a live tap of one module (CFT-A23).
	Health func() map[string]ModuleHealth
	Tap    func(ctx context.Context, module string, seconds int) []byte

	mu        sync.Mutex
	effective []byte
	c         client.OpAMPClient
}

func (o *OpAMPClient) attr(k, v string) *protobufs.KeyValue {
	return &protobufs.KeyValue{Key: k, Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: v}}}
}

// Run connects and serves until ctx ends. Connection loss is retried by the opamp-go client with
// backoff; Run returns only on a setup error or ctx end.
func (o *OpAMPClient) Run(ctx context.Context) error {
	uid, err := uuid.Parse(o.AgentID)
	if err != nil {
		return fmt.Errorf("agent id %q is not a UUID: %w", o.AgentID, err)
	}
	o.c = client.NewHTTP(nil)
	ident := []*protobufs.KeyValue{o.attr("service.name", "wt-agent"), o.attr("service.version", o.Info.Version)}
	non := []*protobufs.KeyValue{o.attr("host.name", o.Info.Hostname), o.attr("os.type", o.Info.OS), o.attr("host.arch", o.Info.Arch)}
	for k, v := range o.Info.Labels {
		non = append(non, o.attr("wt.label."+k, v))
	}
	if names := commandNames(o.Allow); names != "" {
		non = append(non, o.attr("wt.commands", names))
	}
	if err := o.c.SetAgentDescription(&protobufs.AgentDescription{IdentifyingAttributes: ident, NonIdentifyingAttributes: non}); err != nil {
		return err
	}
	if err := o.c.SetHealth(&protobufs.ComponentHealth{Healthy: true, Status: "running", StartTimeUnixNano: uint64(time.Now().UnixNano())}); err != nil {
		return err
	}
	if err := o.c.SetCustomCapabilities(&protobufs.CustomCapabilities{Capabilities: []string{flareCapability, commandCapability, tapCapability}}); err != nil {
		return err
	}
	err = o.c.Start(ctx, types.StartSettings{
		OpAMPServerURL: o.Endpoint,
		Header:         http.Header{"Authorization": {"Bearer " + o.Token}},
		InstanceUid:    types.InstanceUid(uid),
		Capabilities: protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses |
			protobufs.AgentCapabilities_AgentCapabilities_AcceptsRestartCommand,
		Callbacks: types.Callbacks{
			OnConnectFailed: func(_ context.Context, err error) { slog.Warn("opamp connect", "error", err) },
			OnMessage:       func(ctx context.Context, m *types.MessageData) { o.onMessage(ctx, m) },
			GetEffectiveConfig: func(context.Context) (*protobufs.EffectiveConfig, error) {
				o.mu.Lock()
				defer o.mu.Unlock()
				return &protobufs.EffectiveConfig{ConfigMap: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigObject{"config.yaml": {Body: o.effective, ContentType: "text/yaml"}}}}, nil
			},
			SaveRemoteConfigStatus: func(context.Context, *protobufs.RemoteConfigStatus) {},
			OnCommand: func(ctx context.Context, cmd *protobufs.ServerToAgentCommand) error {
				if cmd.GetType() == protobufs.CommandType_CommandType_Restart {
					slog.Info("opamp restart requested; exiting for the service manager to restart us")
					go func() { time.Sleep(time.Second); os.Exit(0) }()
				}
				return nil
			},
		},
	})
	if err != nil {
		return err
	}
	go o.reportHealth(ctx)
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return o.c.Stop(sctx)
}

func (o *OpAMPClient) onMessage(ctx context.Context, m *types.MessageData) {
	if rc := m.RemoteConfig; rc != nil {
		o.applyRemote(ctx, rc)
	}
	if pa := m.PackagesAvailable; pa != nil {
		o.offered(ctx, pa)
	}
	if cm := m.CustomMessage; cm != nil && cm.GetCapability() == commandCapability && cm.GetType() == "run" {
		res, _ := json.Marshal(commands.Exec(ctx, o.Allow, cm.GetData()))
		if _, err := o.c.SendCustomMessage(&protobufs.CustomMessage{Capability: commandCapability, Type: "result", Data: res}); err != nil {
			slog.Warn("command result", "error", err)
		}
	}
	if cm := m.CustomMessage; cm != nil && cm.GetCapability() == tapCapability && cm.GetType() == "start" && o.Tap != nil {
		var req struct {
			Module  string `json:"module"`
			Seconds int    `json:"seconds"`
		}
		if json.Unmarshal(cm.GetData(), &req) == nil && req.Module != "" {
			go func() {
				res := o.Tap(ctx, req.Module, req.Seconds)
				if _, err := o.c.SendCustomMessage(&protobufs.CustomMessage{Capability: tapCapability, Type: "result", Data: res}); err != nil {
					slog.Warn("opamp tap result", "error", err)
				}
			}()
		}
	}
	if cm := m.CustomMessage; cm != nil && cm.GetCapability() == flareCapability && cm.GetType() == "request" {
		if _, err := o.c.SendCustomMessage(&protobufs.CustomMessage{Capability: flareCapability, Type: "bundle", Data: o.flare()}); err != nil {
			slog.Warn("flare", "error", err)
		}
	}
}

// reportHealth sends the per-module health whenever it changes (checked every 15 s).
func (o *OpAMPClient) reportHealth(ctx context.Context) {
	if o.Health == nil {
		return
	}
	start := uint64(time.Now().UnixNano()) //nolint:gosec // wall clock
	last := ""
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		mods := o.Health()
		h := &protobufs.ComponentHealth{Healthy: true, Status: "running", StartTimeUnixNano: start, ComponentHealthMap: map[string]*protobufs.ComponentHealth{}}
		for name, m := range mods {
			msg := m.LastError
			if len(msg) > 512 {
				msg = msg[:512]
			}
			h.ComponentHealthMap[name] = &protobufs.ComponentHealth{Healthy: m.Healthy, Status: fmt.Sprintf("%s;restarts=%d", m.Status, m.Restarts), LastError: string(RedactTap([]byte(msg))),
				StatusTimeUnixNano: uint64(m.Since.UnixNano())} //nolint:gosec // wall clock
			if !m.Healthy {
				h.Healthy, h.Status = false, "degraded"
			}
		}
		if key := fmt.Sprint(mods); key != last {
			if err := o.c.SetHealth(h); err == nil {
				last = key
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (o *OpAMPClient) applyRemote(ctx context.Context, rc *protobufs.AgentRemoteConfig) {
	status := func(s protobufs.RemoteConfigStatuses, msg string) {
		_ = o.c.SetRemoteConfigStatus(&protobufs.RemoteConfigStatus{LastRemoteConfigHash: rc.GetConfigHash(), Status: s, ErrorMessage: msg})
	}
	var body []byte
	for _, f := range rc.GetConfig().GetConfigMap() {
		body = f.GetBody()
		break
	}
	// The hash is an integrity check (TLS authenticates the server), not a signature.
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:], rc.GetConfigHash()) {
		status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, "config hash does not match its body")
		return
	}
	status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLYING, "")
	if err := o.Apply(body); err != nil {
		status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, err.Error())
		return
	}
	o.mu.Lock()
	o.effective = body
	o.mu.Unlock()
	_ = o.c.UpdateEffectiveConfig(ctx)
	status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, "")
}

// verifyPackage checks the release signature the server relayed. Failure is final for that
// version: the server stops offering a version the agent reports as failed.
func (o *OpAMPClient) verifyPackage(p *protobufs.PackageAvailable) error {
	f := p.GetFile()
	if len(o.PubKey) != ed25519.PublicKeySize {
		return errors.New("no release key compiled in; packages are refused")
	}
	if !relsig.Verify(o.PubKey, p.GetVersion(), runtime.GOOS, runtime.GOARCH, f.GetContentHash(), f.GetSignature()) {
		return errors.New("package signature does not verify against the release key")
	}
	return nil
}

func (o *OpAMPClient) offered(ctx context.Context, pa *protobufs.PackagesAvailable) {
	p := pa.GetPackages()[packageName]
	if p == nil {
		return
	}
	report := func(s protobufs.PackageStatusEnum, msg string) {
		_ = o.c.SetPackageStatuses(&protobufs.PackageStatuses{
			ServerProvidedAllPackagesHash: pa.GetAllPackagesHash(),
			Packages: map[string]*protobufs.PackageStatus{packageName: {
				Name: packageName, AgentHasVersion: o.Info.Version, ServerOfferedVersion: p.GetVersion(),
				ServerOfferedHash: p.GetHash(), Status: s, ErrorMessage: msg}},
		})
	}
	if err := o.verifyPackage(p); err != nil {
		slog.Warn("opamp package refused", "version", p.GetVersion(), "error", err)
		report(protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, err.Error())
		return
	}
	staged, err := o.stage(ctx, p)
	if err != nil {
		report(protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, err.Error())
		return
	}
	if o.StageOnly {
		report(protobufs.PackageStatusEnum_PackageStatusEnum_InstallPending, "")
		return
	}
	exe, err := os.Executable()
	if err == nil {
		err = swapBinary(exe, staged, p.GetFile().GetContentHash())
	}
	if err != nil {
		report(protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, err.Error())
		return
	}
	report(protobufs.PackageStatusEnum_PackageStatusEnum_InstallPending, "")
	slog.Info("agent binary replaced; exiting for the service manager to start the new version", "version", p.GetVersion())
	code := 0
	if runtime.GOOS == "windows" {
		code = 1 // the Windows service manager restarts on failure exits only
	}
	go func() { time.Sleep(2 * time.Second); os.Exit(code) }()
}

// stage downloads the verified package into <state_dir>/staged/, checks its SHA-256 against the
// signed hash; swapBinary then re-checks it before replacing the running binary.
func (o *OpAMPClient) stage(ctx context.Context, p *protobufs.PackageAvailable) (string, error) {
	u, err := url.Parse(p.GetFile().GetDownloadUrl())
	if err != nil || u.Scheme != "https" {
		return "", errors.New("package url must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	hc := o.HTTP
	if hc == nil {
		hc = netguard.Guarded("agent", 5*time.Minute)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPackageBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxPackageBytes {
		return "", errors.New("package larger than 256 MiB")
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], p.GetFile().GetContentHash()) {
		return "", errors.New("downloaded bytes do not match the signed hash")
	}
	dir := filepath.Join(o.StateDir, "staged")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "wt-agent-"+filepath.Base(p.GetVersion()))
	return path, os.WriteFile(path, data, 0o750)
}

// flare is the diagnostics bundle: host facts and the running config. The server redacts it
// again; the agent never includes its token.
func (o *OpAMPClient) flare() []byte {
	o.mu.Lock()
	cfg := string(o.effective)
	o.mu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b, _ := json.MarshalIndent(map[string]any{
		"agent_id": o.AgentID, "version": o.Info.Version, "os": o.Info.OS, "arch": o.Info.Arch,
		"hostname": o.Info.Hostname, "goroutines": runtime.NumGoroutine(), "heap_bytes": ms.HeapAlloc,
		"effective_config": cfg, "taken_at": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	return b
}

// remoteFromYAML turns a fleet config body into the RemoteConfig the supervisor merges.
func remoteFromYAML(body []byte) (*RemoteConfig, error) {
	var doc struct {
		Modules map[string]any `yaml:"modules"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	rc := &RemoteConfig{Modules: map[string]json.RawMessage{}}
	for k, v := range doc.Modules {
		j, err := json.Marshal(normalize(v))
		if err != nil {
			return nil, fmt.Errorf("modules.%s: %w", k, err)
		}
		rc.Modules[k] = j
	}
	return rc, nil
}

// releasePubKey decodes ReleaseKey; nil when unset or malformed.
func releasePubKey() ed25519.PublicKey {
	b, err := hex.DecodeString(strings.TrimSpace(ReleaseKey))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return b
}

// commandNames lists the allowlisted command names, comma-separated, so the server only sends a
// command this agent can run (the agent still checks every request against Allow).
func commandNames(allow []commands.Command) string {
	names := make([]string, 0, len(allow))
	for _, c := range allow {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
}
