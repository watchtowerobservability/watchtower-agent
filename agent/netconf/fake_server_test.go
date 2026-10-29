package netconf

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeDevice is an SSH server speaking NETCONF 1.0 or 1.1 framing with candidate and
// confirmed-commit, plus an exec channel for CLI devices.
type fakeDevice struct {
	t       *testing.T
	ln      net.Listener
	chunked bool

	mu        sync.Mutex
	running   string
	candidate string
	prev      string
	pending   bool // a confirmed commit awaits its confirmation
	timer     *time.Timer
	cli       map[string]string
}

func newFake(t *testing.T, chunked bool, running string) *fakeDevice {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "u" && string(pw) == "p" {
				return nil, nil
			}
			return nil, errAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDevice{t: t, ln: ln, chunked: chunked, running: running, cli: map[string]string{}}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, cfg)
		}
	}()
	return f
}

type authErr struct{}

func (authErr) Error() string { return "bad credentials" }

var errAuth = authErr{}

func (f *fakeDevice) port() int {
	return f.ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeDevice) device(transport string) Device {
	return Device{ID: "d1", Host: "127.0.0.1", Port: f.port(), Transport: transport, CredRef: "c"}
}

func (f *fakeDevice) config() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeDevice) set(cfg string) {
	f.mu.Lock()
	f.running = cfg
	f.mu.Unlock()
}

func (f *fakeDevice) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go f.session(ch, creqs)
	}
}

func (f *fakeDevice) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "subsystem":
			_ = r.Reply(true, nil)
			go f.netconf(ch)
		case "exec":
			var p struct{ Cmd string }
			_ = ssh.Unmarshal(r.Payload, &p)
			_ = r.Reply(true, nil)
			f.mu.Lock()
			out, ok := f.cli[p.Cmd]
			f.mu.Unlock()
			if !ok {
				_, _ = ch.Stderr().Write([]byte("unknown command"))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{1}))
			} else {
				_, _ = ch.Write([]byte(out))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
			}
			_ = ch.Close()
		default:
			_ = r.Reply(false, nil)
		}
	}
}

var (
	msgIDRe  = regexp.MustCompile(`message-id="([^"]*)"`)
	timeoutR = regexp.MustCompile(`<confirm-timeout>(\d+)</confirm-timeout>`)
)

func (f *fakeDevice) netconf(ch ssh.Channel) {
	defer ch.Close()
	caps := "<capability>" + cap10 + "</capability><capability>" + capCand + "</capability><capability>" + capConf + "</capability>"
	if f.chunked {
		caps += "<capability>" + cap11 + "</capability>"
	}
	if err := writeMsg(ch, false, []byte(`<hello xmlns="`+baseNS+`"><capabilities>`+caps+`</capabilities><session-id>1</session-id></hello>`)); err != nil {
		return
	}
	r := bufio.NewReader(ch)
	if _, err := readMsg(r, false); err != nil {
		return
	}
	for {
		raw, err := readMsg(r, f.chunked)
		if err != nil {
			return
		}
		msg := string(raw)
		id := ""
		if m := msgIDRe.FindStringSubmatch(msg); m != nil {
			id = m[1]
		}
		reply := f.handle(msg)
		out := `<rpc-reply xmlns="` + baseNS + `" message-id="` + id + `">` + reply + `</rpc-reply>`
		if err := writeMsg(ch, f.chunked, []byte(out)); err != nil {
			return
		}
		if strings.Contains(msg, "<close-session/>") {
			return
		}
	}
}

func (f *fakeDevice) handle(msg string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(msg, "<get-config>"):
		return "<data>" + f.running + "</data>"
	case strings.Contains(msg, "<edit-config>"):
		a := strings.Index(msg, "<config>") + len("<config>")
		f.candidate = msg[a:strings.Index(msg, "</config>")]
		return "<ok/>"
	case strings.Contains(msg, "<commit>") && strings.Contains(msg, "<confirmed/>"):
		secs := 120
		if m := timeoutR.FindStringSubmatch(msg); m != nil {
			secs, _ = strconv.Atoi(m[1])
		}
		f.prev, f.running, f.pending = f.running, f.candidate, true
		f.timer = time.AfterFunc(time.Duration(secs)*time.Second, func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.pending {
				f.running, f.pending = f.prev, false
			}
		})
		return "<ok/>"
	case strings.Contains(msg, "<commit/>"):
		f.pending = false
		return "<ok/>"
	default: // close-session, discard-changes
		return "<ok/>"
	}
}
