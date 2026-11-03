//go:build linux

package ebpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/link"
)

// lockSymbols are the libc lock calls hooked for lock_contention.
var lockSymbols = []string{"pthread_mutex_lock", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_spin_lock"}

// openLock loads lock_bpfel.o and attaches it: uprobes on every lock symbol of each library in
// libs, and the futex tracepoints with futex set. It fails only when nothing could be attached.
func (s *session) openLock(libs []string, futex bool, minNs uint64) error {
	o, err := loadObjects(s.cfg.ObjectDir, "lock", minNs)
	if err != nil {
		return err
	}
	s.lock = o
	enter, exit := o.coll.Programs["lock_enter"], o.coll.Programs["lock_exit"]
	for _, lib := range libs {
		ex, err := link.OpenExecutable(lib)
		if err != nil {
			slog.Warn("ebpf_profiler: lock library not opened", "lib", lib, "err", err)
			continue
		}
		for _, sym := range lockSymbols {
			in, err := ex.Uprobe(sym, enter, nil)
			if err != nil {
				continue // the library does not export it (libpthread split, musl)
			}
			out, err := ex.Uretprobe(sym, exit, nil)
			if err != nil {
				in.Close()
				continue
			}
			s.lockLinks = append(s.lockLinks, in, out)
		}
	}
	if futex {
		for name, prog := range map[string]string{"sys_enter_futex": "futex_enter", "sys_exit_futex": "futex_exit"} {
			l, err := link.Tracepoint("syscalls", name, o.coll.Programs[prog], nil)
			if err != nil {
				return err
			}
			s.lockLinks = append(s.lockLinks, l)
		}
	}
	if len(s.lockLinks) == 0 {
		return fmt.Errorf("lock_contention: no lock function found in %v and lock_futex is off", libs)
	}
	return nil
}

func (s *session) closeLock() {
	for _, l := range s.lockLinks {
		l.Close()
	}
	s.lockLinks = nil
	s.lock.close()
}
