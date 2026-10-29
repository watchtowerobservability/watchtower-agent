//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "wt-agent"

// serviceArgs is the argument list the service manager starts the binary with.
func serviceArgs(cfgPath string) []string { return []string{"-config", cfgPath, "run"} }

// runAsService hands control to the service manager when started by it. It reports whether it did.
func runAsService(cfgPath string) bool {
	ok, err := svc.IsWindowsService()
	if err != nil || !ok {
		return false
	}
	_ = svc.Run(serviceName, &handler{cfg: cfgPath})
	return true
}

type handler struct{ cfg string }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, h.cfg) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

func serviceCommand(action, cfgPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	switch action {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cfg, err := filepath.Abs(cfgPath)
		if err != nil {
			return err
		}
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "Watchtower Agent",
			Description: "Collects host telemetry and sends it to Watchtower over OTLP.",
			StartType:   mgr.StartAutomatic,
			// never LocalSystem: plugins run with this account's rights. The config and token
			// files must be readable by it.
			ServiceStartName: `NT AUTHORITY\LocalService`,
		}, serviceArgs(cfg)...)
		if err != nil {
			return err
		}
		return s.Close()
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.Delete(); err != nil {
			return fmt.Errorf("delete service: %w", err)
		}
		return nil
	}
	return errors.New("service action must be install or uninstall")
}
