package ebpf

import "testing"

func TestStatStartTime(t *testing.T) {
	// A plain line: starttime is the 22nd field (here 4242).
	base := "1234 (dotnet) S 1 1234 1234 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 5 0 4242 123456 100"
	if got := statStartTime(base); got != 4242 {
		t.Fatalf("plain: got %d, want 4242", got)
	}
	// comm with spaces and parentheses must not shift the field offset.
	tricky := "1234 (my app (x) S) S 1 1234 1234 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 5 0 9999 123456 100"
	if got := statStartTime(tricky); got != 9999 {
		t.Fatalf("tricky comm: got %d, want 9999", got)
	}
	// Two different start times for the same pid must produce different values (the whole point).
	reused := "1234 (dotnet) S 1 1234 1234 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 5 0 7777 123456 100"
	if statStartTime(base) == statStartTime(reused) {
		t.Fatal("reused pid at a new start time should differ")
	}
	// Malformed lines yield 0.
	for _, bad := range []string{"", "no parens here", "123 (short) S 1 2 3"} {
		if got := statStartTime(bad); got != 0 {
			t.Fatalf("malformed %q: got %d, want 0", bad, got)
		}
	}
}
