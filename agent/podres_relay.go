package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

// runPodResRelay is `wt-agent -mode podres-relay` (INF-010): the kubelet pod-resources socket is
// root-owned, so instead of running the agent as root the chart can add this relay as a sidecar
// that runs as uid 0 with every capability dropped and a read-only root. It only copies bytes
// between a socket in a pod-private emptyDir (mode 0666; nothing outside the pod can reach it) and
// the kubelet socket, which it reaches through a read-only hostPath mount.
func runPodResRelay(ctx context.Context, listen, target string) error {
	if listen == "" || target == "" {
		return errors.New("podres-relay: -listen and -target are required")
	}
	_ = os.Remove(listen) // a stale socket from a previous run of the sidecar
	if err := os.MkdirAll(filepath.Dir(listen), 0o755); err != nil {
		return err
	}
	l, err := net.Listen("unix", listen)
	if err != nil {
		return err
	}
	if err := os.Chmod(listen, 0o666); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("podres-relay: accept", "error", err)
			time.Sleep(time.Second)
			continue
		}
		go relayConn(c, target)
	}
}

func relayConn(c net.Conn, target string) {
	defer c.Close()
	k, err := net.DialTimeout("unix", target, 5*time.Second)
	if err != nil {
		slog.Warn("podres-relay: kubelet socket", "error", err)
		return
	}
	defer k.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(k, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, k); done <- struct{}{} }()
	<-done // either side closing ends the pair
}
