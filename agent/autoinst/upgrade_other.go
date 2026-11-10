//go:build !linux

package autoinst

import (
	"context"
	"errors"
)

// Upgrade is Linux only: the preload shim and the versioned agent directories exist there.
func Upgrade(context.Context, Config, string, string, string, bool) error {
	return errors.New("host upgrades run on Linux only")
}
