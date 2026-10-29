package netconf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var testCreds = map[string]Creds{"c": {Username: "u", Password: "p"}}

// memStore records uploads and keeps one version per distinct hash, like the API.
type memStore struct {
	bodies  []string
	uploads int
	pinned  string
}

func (m *memStore) Devices(context.Context) ([]Device, error) { return nil, nil }
func (m *memStore) Upload(_ context.Context, _, body, _ string) (bool, error) {
	m.uploads++
	if len(m.bodies) > 0 && SHA(m.bodies[len(m.bodies)-1]) == SHA(body) {
		return false, nil
	}
	m.bodies = append(m.bodies, body)
	return true, nil
}
func (m *memStore) PinHostKey(_ context.Context, _, fp string) error { m.pinned = fp; return nil }
func (m *memStore) Version(context.Context, string, int) (string, error) {
	return "", errors.New("unused")
}

func TestCollectStoresOnlyOnChange(t *testing.T) {
	f := newFake(t, false, "<hostname>r1</hostname>")
	st := &memStore{}
	c := &Collector{Store: st, Creds: testCreds}
	ctx := context.Background()
	for i := range 3 {
		if _, err := c.Collect(ctx, f.device("netconf")); err != nil {
			t.Fatalf("collect %d: %v", i, err)
		}
	}
	if st.uploads != 1 || len(st.bodies) != 1 {
		t.Fatalf("unchanged config must be sent once, got uploads=%d versions=%d", st.uploads, len(st.bodies))
	}
	f.set("<hostname>r2</hostname>")
	changed, err := c.Collect(ctx, f.device("netconf"))
	if err != nil || !changed || len(st.bodies) != 2 {
		t.Fatalf("a changed config must add a version: changed=%v err=%v versions=%d", changed, err, len(st.bodies))
	}
}

func TestSecretsRedactedBeforeStore(t *testing.T) {
	f := newFake(t, false, "<user><name>a</name><password>hunter2</password></user>")
	st := &memStore{}
	c := &Collector{Store: st, Creds: testCreds}
	if _, err := c.Collect(context.Background(), f.device("netconf")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.bodies[0], "hunter2") || !strings.Contains(st.bodies[0], "<password>REDACTED") {
		t.Fatalf("secret stored: %q", st.bodies[0])
	}
	cli := "hostname r1\nsnmp-server community public RO\nenable secret 5 $1$abc\nusername a password 7 0822\ninterface eth0\n"
	got := Redact(cli)
	for _, leak := range []string{"public", "$1$abc", "0822"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q leaked in %q", leak, got)
		}
	}
	if !strings.Contains(got, "hostname r1") || !strings.Contains(got, "interface eth0") {
		t.Fatalf("non-secret lines must survive: %q", got)
	}
}

func TestCliDeviceCollectsAndRedacts(t *testing.T) {
	f := newFake(t, false, "")
	f.cli["show running-config"] = "hostname r1\nenable password 7 0822\n"
	st := &memStore{}
	c := &Collector{Store: st, Creds: testCreds}
	if _, err := c.Collect(context.Background(), f.device("ssh_cli")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.bodies[0], "hostname r1") || strings.Contains(st.bodies[0], "0822") {
		t.Fatalf("cli body: %q", st.bodies[0])
	}
}

func TestHostKeyPinnedAndMismatchRefused(t *testing.T) {
	f := newFake(t, false, "<a/>")
	st := &memStore{}
	c := &Collector{Store: st, Creds: testCreds}
	d := f.device("netconf")
	if _, err := c.Collect(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(st.pinned, "SHA256:") {
		t.Fatalf("first use must pin the key, got %q", st.pinned)
	}
	d.HostKey = st.pinned
	if _, _, err := c.Fetch(context.Background(), d); err != nil {
		t.Fatalf("pinned key must connect: %v", err)
	}
	other := newFake(t, false, "<a/>") // a different host key behind the same pin
	d2 := other.device("netconf")
	d2.HostKey = st.pinned
	if _, _, err := c.Fetch(context.Background(), d2); !IsHostKeyChanged(err) {
		t.Fatalf("mismatch must be refused, got %v", err)
	}
}

func TestNetconfFramingChunked(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMsg(&buf, true, []byte("<a>hello</a>")); err != nil {
		t.Fatal(err)
	}
	// a second chunk before the terminator
	multi := "\n#4\n<a>h\n#8\nello</a>\n##\n"
	got, err := readMsg(bufio.NewReader(strings.NewReader(multi)), true)
	if err != nil || string(got) != "<a>hello</a>" {
		t.Fatalf("multi-chunk: %q %v", got, err)
	}
	one, err := readMsg(bufio.NewReader(&buf), true)
	if err != nil || string(one) != "<a>hello</a>" {
		t.Fatalf("single chunk: %q %v", one, err)
	}
	f := newFake(t, true, "<hostname>r1</hostname>")
	c := &Collector{Store: &memStore{}, Creds: testCreds}
	body, _, err := c.Fetch(context.Background(), f.device("netconf"))
	if err != nil || body != "<hostname>r1</hostname>" {
		t.Fatalf("1.1 session: %q %v", body, err)
	}
}

func TestDiffUnifiedOutput(t *testing.T) {
	got := Unified("a\nb\nc\n", "a\nB\nc\nd\n", 1, 2)
	for _, want := range []string{"--- v1\n+++ v2\n", "@@ -1,3 +1,4 @@", "-b\n+B\n", "+d\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if Unified("x\n", "x\n", 1, 2) != "" {
		t.Fatal("equal configs must diff empty")
	}
}

func TestRollbackUsesConfirmedCommit(t *testing.T) {
	f := newFake(t, false, "<hostname>new</hostname>")
	c := &Collector{Store: &memStore{}, Creds: testCreds}
	err := c.Rollback(context.Background(), f.device("netconf"), "<hostname>old</hostname>",
		RollbackOptions{ConfirmTimeoutS: 1, Check: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // past the confirm window: a confirmed commit must stay
	if got := f.config(); got != "<hostname>old</hostname>" {
		t.Fatalf("rollback must stay after confirmation, running=%q", got)
	}
}

func TestRollbackAutoRevertsWhenNotConfirmed(t *testing.T) {
	f := newFake(t, false, "<hostname>new</hostname>")
	c := &Collector{Store: &memStore{}, Creds: testCreds}
	err := c.Rollback(context.Background(), f.device("netconf"), "<hostname>old</hostname>",
		RollbackOptions{ConfirmTimeoutS: 1, Check: func(context.Context) error { return errors.New("unreachable") }})
	if err == nil {
		t.Fatal("failed reachability check must fail the rollback")
	}
	if got := f.config(); got != "<hostname>old</hostname>" {
		t.Fatalf("change is live inside the confirm window, running=%q", got)
	}
	time.Sleep(1500 * time.Millisecond)
	if got := f.config(); got != "<hostname>new</hostname>" {
		t.Fatalf("unconfirmed commit must auto-revert, running=%q", got)
	}
}

func TestCliDeviceRollbackRefused(t *testing.T) {
	c := &Collector{Store: &memStore{}}
	err := c.Rollback(context.Background(), Device{Transport: "ssh_cli"}, "x", RollbackOptions{})
	if !errors.Is(err, ErrCLIRollback) {
		t.Fatalf("got %v", err)
	}
}

func TestRollbackRefusesRedactedConfig(t *testing.T) {
	c := &Collector{Store: &memStore{}}
	err := c.Rollback(context.Background(), Device{Transport: "netconf"}, "<password>REDACTED</password>", RollbackOptions{})
	if !errors.Is(err, ErrRedacted) {
		t.Fatalf("got %v", err)
	}
}
