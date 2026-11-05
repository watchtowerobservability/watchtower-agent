//go:build linux

package trace

import (
	"bufio"
	"context"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
)

const (
	goWrite = "crypto/tls.(*Conn).Write"
	goRead  = "crypto/tls.(*Conn).Read"
)

// tlsAttacher attaches the uprobes of tls.bpf.c to every OpenSSL library and Go binary it
// finds under /proc, rescanning so processes started later are covered.
type tlsAttacher struct {
	coll  *ebpf.Collection
	mu    sync.Mutex
	links []link.Link
	seen  map[[2]uint64]bool // dev, inode of executables and libraries already handled
}

func newTLSAttacher(cfg Config, events *ebpf.Map) (*tlsAttacher, error) {
	spec, err := agentebpf.LoadSpec(cfg.ObjectDir, "tls")
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"events": events}, // one ring buffer for both
	})
	if err != nil {
		return nil, err
	}
	return &tlsAttacher{coll: coll, seen: map[[2]uint64]bool{}}, nil
}

func (t *tlsAttacher) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.links {
		l.Close()
	}
	t.coll.Close()
}

func (t *tlsAttacher) loop(ctx context.Context) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		t.scan()
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

func (t *tlsAttacher) scan() {
	ents, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range ents {
		t.goBinary(d + "/exe")
		for _, lib := range opensslLibs(d + "/maps") {
			t.openssl(d + "/root" + lib)
		}
	}
}

// first reports whether the file at path has not been handled yet, and marks it.
func (t *tlsAttacher) first(path string) bool {
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		return false
	}
	k := [2]uint64{uint64(st.Dev), st.Ino}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[k] {
		return false
	}
	t.seen[k] = true
	return true
}

func (t *tlsAttacher) add(l link.Link, err error, what string) {
	if err != nil {
		slog.Debug("ebpf_trace: uprobe not attached", "target", what, "err", err)
		return
	}
	t.mu.Lock()
	t.links = append(t.links, l)
	t.mu.Unlock()
}

func opensslLibs(maps string) []string {
	f, err := os.Open(maps)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || !strings.HasPrefix(fl[5], "/") || seen[fl[5]] {
			continue
		}
		if b := filepath.Base(fl[5]); strings.HasPrefix(b, "libssl.so") {
			seen[fl[5]] = true
			out = append(out, fl[5])
		}
	}
	return out
}

func (t *tlsAttacher) openssl(path string) {
	if !t.first(path) {
		return
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return
	}
	p := t.coll.Programs
	l, err := ex.Uprobe("SSL_write", p["ssl_write"], nil)
	t.add(l, err, path+":SSL_write")
	l, err = ex.Uprobe("SSL_read", p["ssl_read"], nil)
	t.add(l, err, path+":SSL_read")
	l, err = ex.Uretprobe("SSL_read", p["ssl_read_ret"], nil)
	t.add(l, err, path+":SSL_read ret")
}

func (t *tlsAttacher) goBinary(path string) {
	f, err := elf.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var wr, rd *elf.Symbol
	syms, _ := f.Symbols() // stripped Go binaries have none and are skipped
	for i := range syms {
		switch syms[i].Name {
		case goWrite:
			wr = &syms[i]
		case goRead:
			rd = &syms[i]
		}
	}
	if wr == nil || rd == nil || !t.first(path) {
		return
	}
	rets, err := retOffsets(f, rd)
	if err != nil {
		slog.Debug("ebpf_trace: go tls read returns not found", "path", path, "err", err)
		return
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return
	}
	p := t.coll.Programs
	l, err := ex.Uprobe(goWrite, p["go_tls_write"], nil)
	t.add(l, err, path+":"+goWrite)
	l, err = ex.Uprobe(goRead, p["go_tls_read"], nil)
	t.add(l, err, path+":"+goRead)
	for _, off := range rets {
		l, err = ex.Uprobe(goRead, p["go_tls_read_ret"], &link.UprobeOptions{Offset: off})
		t.add(l, err, path+":"+goRead+"+"+strconv.FormatUint(off, 10))
	}
}

// retOffsets finds the RET instructions of fn. shortcut: on amd64 this scans for the 0xC3 byte
// without decoding instructions, so a 0xC3 inside an operand is a false hit (an uprobe in the
// middle of an instruction); upgrade to a real disassembler (golang.org/x/arch). arm64 RET is
// fixed width and exact.
func retOffsets(f *elf.File, fn *elf.Symbol) ([]uint64, error) {
	sec := f.Section(".text")
	if sec == nil || fn.Value < sec.Addr || fn.Size == 0 || fn.Size > 1<<20 {
		return nil, fmt.Errorf("symbol outside .text")
	}
	buf := make([]byte, fn.Size)
	if _, err := sec.ReadAt(buf, int64(fn.Value-sec.Addr)); err != nil {
		return nil, err
	}
	var out []uint64
	switch f.Machine {
	case elf.EM_X86_64:
		for i, b := range buf {
			if b == 0xC3 {
				out = append(out, uint64(i))
			}
		}
	case elf.EM_AARCH64:
		for i := 0; i+4 <= len(buf); i += 4 {
			if buf[i] == 0xC0 && buf[i+1] == 0x03 && buf[i+2] == 0x5F && buf[i+3] == 0xD6 {
				out = append(out, uint64(i))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported machine %s", f.Machine)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no RET found")
	}
	return out, nil
}
