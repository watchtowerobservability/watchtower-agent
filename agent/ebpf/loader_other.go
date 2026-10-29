//go:build !linux

package ebpf

// Preflight reports that eBPF profiling is not available here.
func Preflight() error { return ErrUnsupported }
