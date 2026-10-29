//go:build !linux

package ebpf

import (
	"errors"
	"testing"
)

func TestPreflightUnsupportedOnOtherOS(t *testing.T) {
	if err := Preflight(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Preflight = %v", err)
	}
}
