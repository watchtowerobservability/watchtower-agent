package netconf

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrCLIRollback is returned for ssh_cli devices, which are backup-only.
var ErrCLIRollback = errors.New("rollback_unsupported_for_cli")

// RollbackOptions tunes Rollback.
type RollbackOptions struct {
	// ConfirmTimeoutS is the confirmed-commit window; the device reverts by itself after it
	// unless the confirming commit arrives. Default 120.
	ConfirmTimeoutS int
	// Check proves the device is reachable after the change (default: a fresh SSH session that
	// reads the running config). A failure leaves the commit unconfirmed.
	Check func(ctx context.Context) error
	// AllowRedacted permits writing a config that contains redaction markers, which would
	// replace real secrets on the device with the literal text.
	AllowRedacted bool
}

// ErrRedacted refuses a rollback whose stored config had secrets removed.
var ErrRedacted = errors.New("netconf: stored config has redacted secrets; rolling back would overwrite them")

// Rollback replaces the candidate with config, commits it with <confirmed/>, runs the
// reachability check and only then sends the confirming <commit/>. If anything fails after the
// confirmed commit, no confirmation is sent and the device auto-reverts at the timeout.
func (c *Collector) Rollback(ctx context.Context, d Device, config string, o RollbackOptions) error {
	if d.Transport != "netconf" {
		return ErrCLIRollback
	}
	if o.ConfirmTimeoutS <= 0 {
		o.ConfirmTimeoutS = 120
	}
	if !o.AllowRedacted && strings.Contains(config, "REDACTED") {
		return ErrRedacted
	}
	c.apply(&d)
	s, err := Dial(ctx, d)
	if err != nil {
		return err
	}
	defer s.Close()
	nc, err := s.OpenNetconf()
	if err != nil {
		return err
	}
	defer nc.Close()
	if !nc.Caps[capCand] || !nc.Caps[capConf] {
		return errors.New("netconf: device lacks candidate and confirmed-commit")
	}
	if _, err := nc.rpc("<edit-config><target><candidate/></target>" +
		"<default-operation>replace</default-operation><config>" + config + "</config></edit-config>"); err != nil {
		_, _ = nc.rpc("<discard-changes/>")
		return fmt.Errorf("netconf: edit-config: %w", err)
	}
	if _, err := nc.rpc("<commit><confirmed/><confirm-timeout>" + strconv.Itoa(o.ConfirmTimeoutS) +
		"</confirm-timeout></commit>"); err != nil {
		_, _ = nc.rpc("<discard-changes/>")
		return fmt.Errorf("netconf: confirmed commit: %w", err)
	}
	check := o.Check
	if check == nil {
		check = func(ctx context.Context) error {
			s2, err := Dial(ctx, d)
			if err != nil {
				return err
			}
			defer s2.Close()
			n2, err := s2.OpenNetconf()
			if err != nil {
				return err
			}
			defer n2.Close()
			_, err = n2.GetConfig("running")
			return err
		}
	}
	if err := check(ctx); err != nil {
		return fmt.Errorf("netconf: unreachable after rollback, device will auto-revert: %w", err)
	}
	if _, err := nc.rpc("<commit/>"); err != nil {
		return fmt.Errorf("netconf: confirming commit: %w", err)
	}
	return nil
}
