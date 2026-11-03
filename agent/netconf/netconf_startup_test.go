package netconf

import (
	"context"
	"strings"
	"testing"
)

// startupStore is a memStore that also keeps startup uploads, like the API.
type startupStore struct {
	memStore
	startups []string
}

func (s *startupStore) UploadStartup(_ context.Context, _, body string) error {
	s.startups = append(s.startups, body)
	return nil
}

func TestStartupUploadedApartFromRunning(t *testing.T) {
	f := newFake(t, false, "<hostname>r1</hostname>")
	f.mu.Lock()
	f.startup = "<hostname>r0</hostname><password>s3cret</password>"
	f.mu.Unlock()
	st := &startupStore{}
	c := &Collector{Store: st, Creds: testCreds}
	for range 2 {
		if _, err := c.Collect(context.Background(), f.device("netconf")); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.bodies) != 1 || strings.Contains(st.bodies[0], "r0") || strings.Contains(st.bodies[0], "startup") {
		t.Fatalf("running version must hold running only: %q", st.bodies)
	}
	if len(st.startups) != 1 || !strings.Contains(st.startups[0], "r0") || strings.Contains(st.startups[0], "s3cret") {
		t.Fatalf("startup must be sent once, redacted: %q", st.startups)
	}
}

func TestCliStartupConfigLinesUpWithRunning(t *testing.T) {
	f := newFake(t, false, "")
	f.cli["show running-config"] = "hostname r1\n"
	f.cli["show startup-config"] = "hostname r0\nenable secret 5 $1$abc\n"
	st := &startupStore{}
	c := &Collector{Store: st, Creds: testCreds}
	if _, err := c.Collect(context.Background(), f.device("ssh_cli")); err != nil {
		t.Fatal(err)
	}
	if len(st.startups) != 1 {
		t.Fatalf("startups %q", st.startups)
	}
	s := st.startups[0]
	if !strings.HasPrefix(s, "### show running-config\nhostname r0") || strings.Contains(s, "$1$abc") {
		t.Fatalf("startup body %q", s)
	}

	// a device without the command reports no startup, and the backup still works
	g := newFake(t, false, "")
	g.cli["show running-config"] = "hostname r2\n"
	g.cli["show startup-config"] = "% Invalid input detected at '^' marker.\n"
	st2 := &startupStore{}
	c2 := &Collector{Store: st2, Creds: testCreds}
	if _, err := c2.Collect(context.Background(), g.device("ssh_cli")); err != nil || len(st2.bodies) != 1 || len(st2.startups) != 0 {
		t.Fatalf("err=%v bodies=%d startups=%q", err, len(st2.bodies), st2.startups)
	}
}
