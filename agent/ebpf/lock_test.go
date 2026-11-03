package ebpf

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestLockConfigIsOptIn(t *testing.T) {
	c, err := ParseConfig([]byte(`{"enabled":true}`))
	if err != nil || c.LockContention || c.LockFutex || c.LockMinUs != 10 {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	c, err = ParseConfig([]byte(`{"enabled":true,"lock_contention":true,"lock_min_us":50,"lock_futex":true}`))
	if err != nil || !c.LockContention || !c.LockFutex || c.LockMinUs != 50 {
		t.Fatalf("opt-in = %+v, %v", c, err)
	}
	if _, err := ParseConfig([]byte(`{"enabled":true,"lock_futex":true}`)); err == nil {
		t.Fatal("lock_futex without lock_contention must be rejected")
	}
}

func TestLockLibrariesDedupeSymlinks(t *testing.T) {
	// /lib64 links to /usr/lib64 on this fake host; the arm64 paths do not exist.
	resolve := func(p string) (string, error) {
		switch p {
		case "/lib64/libc.so.6", "/usr/lib64/libc.so.6":
			return "/usr/lib64/libc.so.6", nil
		case "/lib64/libpthread.so.0":
			return "/usr/lib64/libpthread.so.0", nil
		}
		return "", errors.New("missing")
	}
	got := Config{}.LockLibraries(resolve)
	if want := []string{"/lib64/libc.so.6", "/lib64/libpthread.so.0"}; !slices.Equal(got, want) {
		t.Fatalf("libs = %v, want %v", got, want)
	}
	named := Config{LockLibs: []string{"/proc/7/root/lib/libc.so.6"}}.LockLibraries(resolve)
	if !slices.Equal(named, []string{"/proc/7/root/lib/libc.so.6"}) {
		t.Fatalf("named libs = %v", named)
	}
}

func TestFoldLockIsWaitNanoseconds(t *testing.T) {
	es := []Entry{{PID: 42, User: []uint64{0x401000}, Value: 3_000_000}}
	ps, err := Fold(Lock, es, fakeResolver{labels}, time.Unix(100, 0), time.Minute, FoldOptions{StripArgs: true, Hz: 19})
	if err != nil || len(ps) != 1 || ps[0].Kind != "lock_contention" {
		t.Fatalf("fold = %v, %v", ps, err)
	}
	d := decode(t, ps[0].Body)
	if len(d.values) != 1 || len(d.values[0]) != 1 || d.values[0][0] != 3_000_000 {
		t.Fatalf("values = %v (one column: nanoseconds waited, not scaled by the CPU rate)", d.values)
	}
	if !slices.Contains(d.strs, "lock_contention") || !slices.Contains(d.strs, "nanoseconds") {
		t.Fatalf("sample type strings = %v", d.strs)
	}
}
