package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestSwapBinaryVerifiesHashBeforeReplacing(t *testing.T) {
	dir := t.TempDir()
	exe, staged := filepath.Join(dir, "wt-agent"), filepath.Join(dir, "staged")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	_ = os.WriteFile(staged, []byte("new"), 0o755)
	bad := sha256.Sum256([]byte("other"))
	if err := swapBinary(exe, staged, bad[:]); err == nil {
		t.Fatal("swap accepted bytes that do not match the signed hash")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary replaced despite hash mismatch: %q", b)
	}
	good := sha256.Sum256([]byte("new"))
	if err := swapBinary(exe, staged, good[:]); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("binary not replaced: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "old" {
		t.Fatalf("old binary not kept: %q", b)
	}
}
