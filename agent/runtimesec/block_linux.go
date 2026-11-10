//go:build linux

package runtimesec

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"context"
)

const lsmObject = "runtimesec_lsm_bpfel.o"

// lsmEnabled reports whether the running kernel has the bpf LSM active.
func lsmEnabled() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	return err == nil && lsmListHasBPF(string(b))
}

func osStat(path string) (dev, ino uint64, isDir bool, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false, errors.New("no stat_t")
	}
	return uint64(st.Dev), uint64(st.Ino), fi.IsDir(), nil //nolint:unconvert // width differs per arch
}

// mapDeny adapts an *ebpf.Map to denyMap.
type mapDeny struct{ m *ebpf.Map }

func (d mapDeny) Put(k denyKey, v uint32) error { return d.m.Put(k, v) }
func (d mapDeny) Delete(k denyKey) error {
	if err := d.m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}
func (d mapDeny) Keys() ([]denyKey, error) {
	var out []denyKey
	var k denyKey
	var v uint32
	it := d.m.Iterate()
	for it.Next(&k, &v) {
		out = append(out, k)
	}
	return out, it.Err()
}

// startBlock loads the LSM object, fills the deny maps from the policy's block rules and keeps them
// current until ctx ends, reporting each refusal as a signal. It returns errNoBPFLSM before loading
// anything when the kernel lacks the bpf LSM, so a block rule is never silently unenforced.
func startBlock(ctx context.Context, cfg Config, pol Policy, em *Emitter, out Sink, host string) error {
	if !lsmEnabled() {
		out.Log("error", errNoBPFLSM.Error(), map[string]string{
			"agent.module": "runtime_security", "host.name": host, "runtime_security.block": "unavailable"}, time.Now())
		return errNoBPFLSM
	}
	spec, err := loadSpecFile(cfg.ObjectDir, lsmObject)
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("runtime_security: load LSM object: %w", err)
	}
	for _, name := range []string{"wt_bprm_check", "wt_file_open"} {
		prog := coll.Programs[name]
		if prog == nil {
			coll.Close()
			return fmt.Errorf("runtime_security: LSM object has no program %q (rebuild with `make ebpf-gen`)", name)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			coll.Close()
			return fmt.Errorf("runtime_security: attach %s: %w", name, err)
		}
		defer l.Close()
	}
	defer coll.Close()
	rd, err := ringbuf.NewReader(coll.Maps["denied"])
	if err != nil {
		return err
	}
	defer rd.Close()

	entries := map[denyKey]blockEntry{}
	refresh := func() {
		plan, unresolved := BlockPlan(pol, osStat)
		execWant, fileWant := map[denyKey]uint32{}, map[denyKey]uint32{}
		entries = map[denyKey]blockEntry{}
		for _, e := range plan {
			entries[e.Key] = e
			if e.Kind == "exec" {
				execWant[e.Key] |= e.Flags
			} else {
				fileWant[e.Key] |= e.Flags
			}
		}
		_, _, e1 := syncDeny(mapDeny{coll.Maps["deny_exec"]}, execWant)
		_, _, e2 := syncDeny(mapDeny{coll.Maps["deny_file"]}, fileWant)
		attrs := map[string]string{"agent.module": "runtime_security", "host.name": host,
			"runtime_security.block": "enforcing"}
		if err := errors.Join(e1, e2); err != nil {
			attrs["runtime_security.block"] = "error"
			out.Log("error", "runtime_security: updating the deny maps failed: "+err.Error(), attrs, time.Now())
			return
		}
		out.Log("info", fmt.Sprintf("runtime_security enforcing %d block entries (%d paths not found yet)", len(plan), len(unresolved)),
			attrs, time.Now())
	}
	refresh()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				rd.Close()
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	res := newResolver()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}
		d, ok := decodeDenied(rec.RawSample)
		if !ok {
			continue
		}
		e, known := entries[d.Key]
		if !known {
			continue
		}
		svc, _ := res.resolve(d.PID, d.Comm)
		em.Signal(e.Rule, svc, map[string]string{"blocked": "true", "path": e.Path, "comm": d.Comm})
	}
}
