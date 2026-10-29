//go:build windows

package netpath

import "syscall"

// ttlControl sets the IP TTL of the probe socket before it connects.
func ttlControl(ttl int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}); err != nil {
			return err
		}
		return serr
	}
}
