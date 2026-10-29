package wal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func collect(t *testing.T, w *WAL) []string {
	t.Helper()
	var got []string
	if err := w.Replay(func(r []byte) error { got = append(got, string(r)); return nil }); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWALReplayAfterCrash(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"a", "b", "c"} {
		if err := w.Append([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	// kill mid-write: half a record (header promises 9 bytes, 1 present) at the newest segment's end
	segs, _ := w.segments()
	f, err := os.OpenFile(w.name(segs[len(segs)-1]), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{9, 0, 0, 0, 1, 2, 3, 4, 'x'})
	_ = f.Close()

	w2, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, w2)
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("replay = %v, want a b c with the torn tail ignored", got)
	}
	if got := collect(t, w2); len(got) != 0 {
		t.Fatalf("segments not removed after replay: %v", got)
	}
}

func TestWALReplayStopsOnError(t *testing.T) {
	w, _ := Open(t.TempDir(), 0)
	_ = w.Append([]byte("a"))
	if err := w.Replay(func([]byte) error { return errors.New("down") }); err == nil {
		t.Fatal("want the callback error")
	}
	if got := collect(t, w); len(got) != 1 {
		t.Fatalf("unacked record lost: %v", got)
	}
}

func TestWALDropsOldestAtCap(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 2*segmentBytes)
	big := make([]byte, maxRecord) // largest record: two never fit one segment
	for i := 1; i <= 6; i++ {
		big[0] = byte(i)
		if err := w.Append(big); err != nil {
			t.Fatal(err)
		}
	}
	if w.Dropped() == 0 {
		t.Fatal("expected dropped segments")
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	if len(segs) > 2 {
		t.Fatalf("%d segments kept, cap not enforced", len(segs))
	}
	var first byte
	_ = w.Replay(func(r []byte) error {
		if first == 0 {
			first = r[0]
		}
		return nil
	})
	if first < 3 {
		t.Fatalf("oldest record %d survived", first)
	}
}
