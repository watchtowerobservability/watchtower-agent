//go:build windows

package custom

import (
	"os/exec"
	"strconv"
	"syscall"
)

// killTreeOnCancel starts the plugin in a new process group and, when the context ends, kills
// the whole tree with taskkill /T /F.
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.Cancel = func() error {
		pid := strconv.Itoa(cmd.Process.Pid)
		if err := exec.Command("taskkill", "/T", "/F", "/PID", pid).Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
