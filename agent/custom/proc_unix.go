//go:build !windows

package custom

import (
	"os/exec"
	"syscall"
)

// killTreeOnCancel puts the plugin in its own process group and, when the context ends, kills
// the whole group, so a hung child of a shell-script plugin does not outlive the check.
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
