package main

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPodResRelayCopiesBothWays(t *testing.T) {
	dir, err := os.MkdirTemp("", "podres") // short path: unix socket paths are limited to ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	target, listen := filepath.Join(dir, "k.sock"), filepath.Join(dir, "r", "a.sock")
	kl, err := net.Listen("unix", target)
	if err != nil {
		t.Fatal(err)
	}
	defer kl.Close()
	go func() {
		c, err := kl.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("kubelet:" + line))
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runPodResRelay(ctx, listen, target) }()
	var c net.Conn
	for range 100 {
		if c, err = net.Dial("unix", listen); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if st, err := os.Stat(listen); err != nil || st.Mode().Perm() != 0o666 {
		t.Fatalf("relay socket mode: %v %v", st, err)
	}
	_, _ = c.Write([]byte("list\n"))
	got, _ := bufio.NewReader(c).ReadString('\n')
	if got != "kubelet:list\n" {
		t.Fatalf("got %q", got)
	}
}
