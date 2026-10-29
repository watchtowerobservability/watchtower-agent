package netconf

import (
	"fmt"
	"strings"
)

// DefaultCommands is run when an ssh_cli device lists none.
var DefaultCommands = []string{"show running-config"}

// RunCLI runs each command in its own SSH session and joins the outputs under a `### cmd`
// header. CLI devices are backup-only: there is no rollback for them.
func (s *Session) RunCLI(commands []string) (string, error) {
	if len(commands) == 0 {
		commands = DefaultCommands
	}
	var b strings.Builder
	for _, c := range commands {
		sess, err := s.ssh.NewSession()
		if err != nil {
			return "", err
		}
		out, err := sess.CombinedOutput(c)
		_ = sess.Close()
		if err != nil {
			return "", fmt.Errorf("netconf: %q: %w", c, err)
		}
		fmt.Fprintf(&b, "### %s\n%s\n", c, strings.TrimRight(string(out), "\r\n"))
	}
	return b.String(), nil
}
