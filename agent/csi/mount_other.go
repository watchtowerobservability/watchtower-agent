//go:build !linux

package csi

import "errors"

// SysMounter is Linux-only: CSI nodes are Linux nodes.
type SysMounter struct{}

var errLinux = errors.New("csi: bind mounts need Linux")

func (SysMounter) BindMount(string, string, bool) error { return errLinux }
func (SysMounter) Unmount(string) error                 { return errLinux }
func (SysMounter) IsMounted(string) (bool, error)       { return false, nil }
