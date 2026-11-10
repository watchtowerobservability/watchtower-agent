// Command wt-agent is the Watchtower host agent: one binary with collector modules, a fleet
// protocol to wt-edge (registration, remote config by long poll) and an OTLP/HTTP exporter to
// the gateway. See docs/product/infra/agent.md.
package main

import (
	"cmp"
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/csi"
	"github.com/watchtowerobservability/watchtower-agent/agent/relay"
	"github.com/watchtowerobservability/watchtower-agent/internal/wal"
)

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "Watchtower", "agent", "agent.yaml")
	}
	return "/etc/wt-agent/agent.yaml"
}

const usage = `usage: wt-agent [-mode agent|relay|podres-relay|csi] [-config FILE] [run | version | explain [-remote FILE] | flare [-out FILE.zip] | status | service install | service uninstall]`

func main() { os.Exit(realMain(os.Args[1:])) }

func realMain(args []string) int {
	fs := flag.NewFlagSet("wt-agent", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "agent config file")
	mode := fs.String("mode", "agent", "agent (default), relay (store-and-forward OTLP relay, docs/product/ingest/relay.md) or podres-relay (kubelet pod-resources socket sidecar) or csi (node CSI driver that mounts the agent sockets into pods, docs/product/infra/csi.md)")
	listen := fs.String("listen", "", "podres-relay: socket to serve in a pod-private directory")
	target := fs.String("target", "/var/lib/kubelet/pod-resources/kubelet.sock", "podres-relay: the kubelet pod-resources socket")
	csiEndpoint := fs.String("csi-endpoint", "/csi/csi.sock", "csi: the CSI gRPC unix socket")
	csiRegister := fs.String("csi-register", "", "csi: kubelet plugin-registration socket, e.g. /registration/"+csi.DriverName+"-reg.sock")
	csiRoot := fs.String("csi-socket-root", "/var/run/wt-agent", "csi: host directory (and below) pods may mount")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *mode {
	case "csi":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		d := &csi.Driver{NodeID: os.Getenv("NODE_NAME"), Version: Version, SocketRoot: *csiRoot, Mount: csi.SysMounter{}}
		if err := d.Serve(ctx, *csiEndpoint, *csiRegister); err != nil {
			slog.Error("wt-agent csi stopped", "error", err)
			return 1
		}
		return 0
	case "relay":
		path := *cfgPath
		if path == defaultConfigPath() {
			path = "/etc/wt-relay/relay.yaml"
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := relay.Run(ctx, path); err != nil {
			slog.Error("wt-agent relay stopped", "error", err)
			return 1
		}
		return 0
	case "podres-relay":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := runPodResRelay(ctx, *listen, *target); err != nil {
			slog.Error("wt-agent podres-relay stopped", "error", err)
			return 1
		}
		return 0
	case "agent":
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	rest := fs.Args()
	cmd := "run"
	if len(rest) > 0 {
		cmd = rest[0]
	}
	switch cmd {
	case "version":
		if fips140.Enabled() { // a GOFIPS140 build running with the FIPS 140-3 module active
			fmt.Println("wt-agent", Version, "fips140=on")
			return 0
		}
		fmt.Println("wt-agent", Version)
		return 0
	case "explain":
		efs := flag.NewFlagSet("explain", flag.ContinueOnError)
		remote := efs.String("remote", "", "a served remote config (YAML or JSON) to overlay, as the agent would")
		if err := efs.Parse(rest[1:]); err != nil {
			return 2
		}
		if err := explain(context.Background(), *cfgPath, *remote, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "wt-agent explain:", err)
			return 1
		}
		return 0
	case "flare":
		ffs := flag.NewFlagSet("flare", flag.ContinueOnError)
		outPath := ffs.String("out", "wt-agent-flare.zip", "support bundle to write")
		if err := ffs.Parse(rest[1:]); err != nil {
			return 2
		}
		if err := flare(context.Background(), *cfgPath, *outPath); err != nil {
			fmt.Fprintln(os.Stderr, "wt-agent flare:", err)
			return 1
		}
		fmt.Println("wrote", *outPath, "(redacted; review it before sending)")
		return 0
	case "status":
		if err := statusCommand(*cfgPath, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "wt-agent status:", err)
			return 1
		}
		return 0
	case "service":
		if len(rest) != 2 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := serviceCommand(rest[1], *cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "wt-agent:", err)
			return 1
		}
		return 0
	case "run":
		if runAsService(*cfgPath) {
			return 0
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := runAgent(ctx, *cfgPath); err != nil {
			slog.Error("wt-agent stopped", "error", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

// runAgent runs until ctx ends. It returns only on a fatal setup error.
func runAgent(ctx context.Context, cfgPath string) error {
	local, err := LoadLocal(cfgPath)
	if err != nil {
		return err
	}
	token, err := local.Token()
	if err != nil {
		return err
	}
	fleet := NewFleet(local.FleetEndpoint, token)
	egress, err := proxiedClient(ctx, local.Proxy, local.NoProxy, exportTimeout)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	if local.Proxy != "" {
		fleet.HTTP = egress
	}
	info := hostInfo(local.Labels)

	id, err := registerWithRetry(ctx, fleet, local.StateDir, info)
	if err != nil {
		return err
	}
	res := map[string]string{
		"service.name": "wt-agent", "service.version": Version,
		"host.name": info.Hostname, "os.type": info.OS, "agent.id": id.AgentID,
		// the agent's own telemetry; the gateway strips wt.* from clients, so the server side must
		// recognise agent tokens, like wt-uptime sets wt.synthetic after the strip
		"wt.internal": "true",
	}
	if ips, macs := hostAddrs(); ips != "" || macs != "" {
		if ips != "" {
			res["host.ip"] = ips
		}
		if macs != "" {
			res["host.mac"] = macs
		}
	}
	out := NewOTLP(local.Endpoint, token, res)
	if local.Proxy != "" {
		out.HTTP = egress
	}
	if local.BufferDir != "" {
		w, err := wal.Open(local.BufferDir, local.BufferMaxBytes)
		if err != nil {
			return fmt.Errorf("buffer_dir: %w", err)
		}
		switch local.BufferWhenFull {
		case "", "drop_oldest":
		case "drop_newest":
			w.DropNewest = true
		default:
			return fmt.Errorf("buffer_when_full: %q is not drop_oldest or drop_newest", local.BufferWhenFull)
		}
		out.Buffer = w
	}
	fwd, err := StartForwarders(ctx, local.Forward)
	if err != nil {
		return err
	}
	if len(fwd) > 0 {
		out.Tee = fwd.Tee
	}
	out.Enrich = agentEnricher.Apply
	go out.Run(ctx)

	reg := NewRegistry(local)
	sup := &Supervisor{Reg: reg, Out: out}
	warn := func(m string) { slog.Warn(m) }
	if local.StatusListen != "" {
		if err := serveStatus(ctx, local.StatusListen, statusHandler(sup, out, id.AgentID, local)); err != nil {
			return fmt.Errorf("status_listen: %w", err)
		}
	}
	sup.Apply(ctx, Merge(reg, local.Modules, nil, warn))
	slog.Info("wt-agent started", "agent_id", id.AgentID, "modules", sup.Names())

	applied := LoadApplied(local.StateDir)
	if !local.DisableRemoteConfig {
		go runSDKUpgrades(ctx, fleet, id.AgentID, local)
	}
	if local.FleetMode == "opamp" && !local.DisableRemoteConfig {
		oc := &OpAMPClient{
			Endpoint: cmp.Or(local.OpAMPEndpoint, strings.TrimRight(local.FleetEndpoint, "/")+"/v1/opamp"),
			Token:    token, AgentID: id.AgentID, HTTP: opampHTTP(ctx, local), Info: info, StateDir: local.StateDir, PubKey: releasePubKey(), Allow: local.Commands,
			Health: sup.Health, Tap: sup.taps.Run,
			Apply: func(body []byte) error {
				rc, err := remoteFromYAML(body)
				if err != nil {
					return err
				}
				sup.Apply(ctx, Merge(reg, local.Modules, rc, warn))
				slog.Info("opamp config applied", "modules", sup.Names())
				return nil
			},
		}
		if err := oc.Run(ctx); err != nil {
			slog.Error("opamp", "error", err)
		}
		sup.Stop()
		return nil
	}
	if local.DisableRemoteConfig {
		<-ctx.Done()
	}
	for !local.DisableRemoteConfig && ctx.Err() == nil {
		err := fleet.Follow(ctx, id.AgentID, info.Labels, applied, func(version int, rc *RemoteConfig) {
			sup.Apply(ctx, Merge(reg, local.Modules, rc, warn))
			slog.Info("remote config applied", "version", version, "modules", sup.Names())
		}, func(err error) { slog.Warn("remote config", "error", err) })
		if errors.Is(err, ErrNotFound) {
			if id, err = registerWithRetry(ctx, fleet, local.StateDir, info); err != nil {
				break
			}
		}
	}
	sup.Stop()
	return nil
}

func registerWithRetry(ctx context.Context, f *Fleet, stateDir string, info HostInfo) (Identity, error) {
	wait := time.Second
	for {
		id, err := EnsureRegistered(ctx, f, stateDir, info)
		if err == nil {
			return id, nil
		}
		if ctx.Err() != nil {
			return Identity{}, ctx.Err()
		}
		slog.Warn("register failed, retrying", "error", err, "in", wait)
		sleep(ctx, wait)
		wait = min(wait*2, time.Minute)
	}
}

// opampHTTP is the package-download client: proxied when the agent has a proxy, else nil (default).
func opampHTTP(ctx context.Context, local *LocalConfig) *http.Client {
	if local.Proxy == "" {
		return nil
	}
	c, err := proxiedClient(ctx, local.Proxy, local.NoProxy, 5*time.Minute)
	if err != nil {
		return nil // runAgent already failed on the same proxy setting
	}
	return c
}
