package runtimesec

// Enforcement side of runtime_security: turn `block` rules into the inode keys the BPF LSM
// program (bpf/runtimesec_lsm.bpf.c) denies, and keep its deny maps in step. Everything here is
// platform independent and unit tested; block_linux.go loads the object and owns the real maps.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// denyKey mirrors struct inode_key in the BPF object (16 bytes, no padding).
type denyKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// Deny flags, mirrored by the BPF object.
const (
	flagAny   uint32 = 1 // refuse every open
	flagWrite uint32 = 2 // refuse opens for writing
)

// blockEntry is one denied file and the rule that asked for it.
type blockEntry struct {
	Kind  string // exec or file
	Key   denyKey
	Flags uint32
	Rule  Rule
	Path  string
}

// statFn reads a file's device and inode (os.Stat on Linux; injected by the tests).
type statFn func(path string) (dev, ino uint64, isDir bool, err error)

// kernelDev converts the st_dev a stat call reports (glibc/new_encode_dev layout) to the kernel's
// dev_t (major << 20 | minor), which is what the BPF program reads from the superblock.
func kernelDev(d uint64) uint32 {
	major := uint32((d>>8)&0xfff) | uint32((d>>32)&^0xfff)
	minor := uint32(d&0xff) | uint32((d>>12)&^0xff)
	return major<<20 | minor
}

// hasBlockRules reports whether the policy asks for enforcement.
func (p Policy) hasBlockRules() bool {
	for _, r := range p.Rules {
		if r.Action == "block" {
			return true
		}
	}
	return false
}

// validateBlock checks the extra requirements of a block rule: only exec and file rules can be
// enforced, and they must name absolute file paths (a deny is by inode, so a prefix or a directory
// would silently block nothing).
func validateBlock(r Rule) error {
	if r.Kind != "exec" && r.Kind != "file" {
		return fmt.Errorf("rule %s: only exec and file rules can block", r.ID)
	}
	paths := strList(r.Match["paths"])
	if len(paths) == 0 {
		return fmt.Errorf("rule %s: a block rule needs match.paths (absolute file paths)", r.ID)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || p == "/" {
			return fmt.Errorf("rule %s: block path %q must be an absolute file path", r.ID, p)
		}
	}
	return nil
}

// BlockPlan resolves every block rule's paths to deny entries. A path that cannot be read yet, or is
// a directory, is returned in unresolved (the agent retries on its next refresh) instead of failing
// the rule: a file may be installed later.
func BlockPlan(pol Policy, stat statFn) (entries []blockEntry, unresolved []string) {
	for _, r := range pol.Rules {
		if r.Action != "block" {
			continue
		}
		flags := flagAny
		if r.Kind == "file" && r.Match["op"] == "write" {
			flags = flagWrite
		}
		for _, p := range strList(r.Match["paths"]) {
			dev, ino, dir, err := stat(p)
			if err != nil || dir {
				unresolved = append(unresolved, p)
				continue
			}
			entries = append(entries, blockEntry{Kind: r.Kind, Rule: r, Path: p, Flags: flags,
				Key: denyKey{Ino: ino, Dev: kernelDev(dev)}})
		}
	}
	return entries, unresolved
}

// lsmListHasBPF reports whether /sys/kernel/security/lsm names the bpf LSM.
func lsmListHasBPF(list string) bool {
	for _, n := range strings.Split(strings.TrimSpace(list), ",") {
		if strings.TrimSpace(n) == "bpf" {
			return true
		}
	}
	return false
}

// errNoBPFLSM is why block rules refuse to load on a kernel without the bpf LSM.
var errNoBPFLSM = fmt.Errorf("runtime_security: block rules need the BPF LSM, which this kernel lacks " +
	"(build with CONFIG_BPF_LSM and boot with lsm=...,bpf); remove the block rules or enable it")

// denyMap is the slice of *ebpf.Map the sync needs (a fake in the tests).
type denyMap interface {
	Put(k denyKey, v uint32) error
	Delete(k denyKey) error
	Keys() ([]denyKey, error)
}

// syncDeny makes the map hold exactly want: it writes every wanted key and removes the others.
func syncDeny(m denyMap, want map[denyKey]uint32) (added, removed int, err error) {
	have, err := m.Keys()
	if err != nil {
		return 0, 0, err
	}
	had := make(map[denyKey]bool, len(have))
	for _, k := range have {
		had[k] = true
		if _, keep := want[k]; !keep {
			if err := m.Delete(k); err != nil {
				return added, removed, err
			}
			removed++
		}
	}
	for k, v := range want {
		if err := m.Put(k, v); err != nil {
			return added, removed, err
		}
		if !had[k] {
			added++
		}
	}
	return added, removed, nil
}

// deniedSize mirrors struct denied in the BPF object.
const deniedSize = 48

// denied is one refusal the kernel reported.
type denied struct {
	Key  denyKey
	PID  uint32
	Kind string
	Comm string
}

func decodeDenied(b []byte) (denied, bool) {
	if len(b) < deniedSize {
		return denied{}, false
	}
	kind := "file"
	if binary.LittleEndian.Uint32(b[24:28]) == 0 {
		kind = "exec"
	}
	return denied{
		Key:  denyKey{Ino: binary.LittleEndian.Uint64(b[8:16]), Dev: binary.LittleEndian.Uint32(b[16:20])},
		PID:  binary.LittleEndian.Uint32(b[20:24]),
		Kind: kind,
		Comm: cstr(b[32:48]),
	}, true
}
