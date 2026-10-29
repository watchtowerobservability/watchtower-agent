// Command wt-agent is the Watchtower host agent: one binary with collector modules, a fleet
// protocol to wt-edge (registration, remote config by long poll) and an OTLP/HTTP exporter to
// the gateway. See docs/product/infra/agent.md.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/relay"
	"github.com/watchtowerobservability/watchtower-agent/internal/wal"
)

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "Watchtower", "agent", "agent.yaml")
	}
	return "/etc/wt-agent/agent.yaml"
}

const usage = `usage: wt-agent [-mode agent|relay] [-config FILE] [run | version | service install | service uninstall]`

func main() { os.Exit(realMain(os.Args[1:])) }

func realMain(args []string) int {
	fs := flag.NewFlagSet("wt-agent", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "agent config file")
	mode := fs.String("mode", "agent", "agent (default) or relay: a store-and-forward OTLP relay (docs/product/ingest/relay.md)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *mode {
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
		fmt.Println("wt-agent", Version)
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
	info := hostInfo(local.Labels)

	id, err := registerWithRetry(ctx, fleet, local.StateDir, info)
	if err != nil {
		return err
	}
	res := map[string]string{
		"service.name": "wt-agent", "service.version": Version,
		"host.name": info.Hostname, "os.type": info.OS, "agent.id": id.AgentID,
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
	go out.Run(ctx)

	reg := NewRegistry(local)
	sup := &Supervisor{Reg: reg, Out: out}
	warn := func(m string) { slog.Warn(m) }
	sup.Apply(ctx, Merge(reg, local.Modules, nil, warn))
	slog.Info("wt-agent started", "agent_id", id.AgentID, "modules", sup.Names())

	applied := LoadApplied(local.StateDir)
	if local.FleetMode == "opamp" && !local.DisableRemoteConfig {
		oc := &OpAMPClient{
			Endpoint: cmp.Or(local.OpAMPEndpoint, strings.TrimRight(local.FleetEndpoint, "/")+"/v1/opamp"),
			Token:    token, AgentID: id.AgentID, Info: info, StateDir: local.StateDir, PubKey: releasePubKey(), Allow: local.Commands,
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
