//go:build !windows

package main

import "errors"

func runAsService(string) bool { return false }

func serviceCommand(string, string) error {
	return errors.New("service install|uninstall is Windows only; use the packaged systemd unit or the launchd plist")
}
