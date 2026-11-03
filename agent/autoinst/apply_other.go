//go:build !linux && !windows

package autoinst

import "errors"

func apply(Config) error { return errors.New("autoinst runs on Linux and Windows only") }

func remove(Config) error { return nil }
