//go:build linux

package csi

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

// SysMounter bind-mounts with mount(2); the driver pod runs privileged with
// mountPropagation: Bidirectional on the kubelet pods directory.
type SysMounter struct{}

func (SysMounter) BindMount(src, dst string, readOnly bool) error {
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	if readOnly { // a bind mount takes MS_RDONLY only on a remount
		return syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
	}
	return nil
}

func (SysMounter) Unmount(dst string) error { return syscall.Unmount(dst, 0) }

func (SysMounter) IsMounted(dst string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 4 && fs[4] == dst {
			return true, nil
		}
	}
	return false, sc.Err()
}
