// Package trace is the wt-agent module `ebpf_trace` (APM-010, TRC-020): zero-code request spans
// from eBPF captures of the first 512 bytes of socket and TLS reads and writes.
//
// The parsers and the span assembler here are platform neutral and unit tested without a
// kernel; the probe loading lives in the *_linux.go files. Only request and response heads are
// parsed. Headers other than a fixed allowlist are never stored, so `authorization` and
// `cookie` cannot leak, query strings are cut from paths, and SQL is normalized on the host.
package trace

import "errors"

// ErrUnsupported is returned by Run on platforms without eBPF support.
var ErrUnsupported = errors.New("ebpf_trace: unsupported on this platform (Linux only)")
