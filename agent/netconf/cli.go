package netconf

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
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

// Output runs one command in its own session and returns at most max bytes of its stdout. A
// non-zero exit status is not an error: smartctl, for one, sets exit bits for disk warnings while
// still printing its full report. Stderr is discarded (it may name hosts or users).
func (s *Session) Output(cmd string, max int) ([]byte, error) {
	sess, err := s.ssh.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var buf capped
	buf.max = max
	sess.Stdout = &buf
	err = sess.Run(cmd)
	var ee *ssh.ExitError
	if err != nil && !errors.As(err, &ee) {
		return nil, fmt.Errorf("netconf: %q could not be run", cmd)
	}
	return buf.Bytes(), nil
}

// capped keeps the first max bytes written to it and drops the rest.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
