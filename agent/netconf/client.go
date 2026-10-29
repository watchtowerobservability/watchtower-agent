// Package netconf backs up network device configuration (P6-NC1, INF-017): NETCONF get-config
// over SSH (RFC 6241/6242, 1.0 end-of-message and 1.1 chunked framing) or `show running-config`
// over an SSH shell, stored only when the SHA-256 changes, with secrets redacted first. Rollback
// uses a confirmed-commit so a device that becomes unreachable reverts by itself.
package netconf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHTimeout bounds the TCP connect and SSH handshake.
const SSHTimeout = 30 * time.Second

const (
	baseNS  = "urn:ietf:params:xml:ns:netconf:base:1.0"
	cap10   = "urn:ietf:params:netconf:base:1.0"
	cap11   = "urn:ietf:params:netconf:base:1.1"
	capCand = "urn:ietf:params:netconf:capability:candidate:1.0"
	capConf = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
	capStrt = "urn:ietf:params:netconf:capability:startup:1.0"
	eom     = "]]>]]>"
)

// ErrHostKeyChanged is returned, without authenticating, when the device presents a key other
// than the pinned one.
var ErrHostKeyChanged = errors.New("netconf: host key does not match the pinned key")

// Device is one polled device. Credentials come from the agent's local config.
type Device struct {
	ID         string   `json:"id"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Transport  string   `json:"transport"` // netconf or ssh_cli
	Commands   []string `json:"commands"`
	HostKey    string   `json:"host_key"` // pinned SHA256 fingerprint, empty before first use
	IntervalS  int      `json:"interval_s"`
	CredRef    string   `json:"credentials_ref"`
	Rollback   *int     `json:"rollback_version"`
	LastSHA    string   `json:"-"`
	Username   string   `json:"-"`
	Password   string   `json:"-"`
	PrivateKey string   `json:"-"`
}

// Creds is a local credential, selected by Device.CredRef.
type Creds struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// Session is an SSH connection to a device and the fingerprint it presented.
type Session struct {
	ssh         *ssh.Client
	Fingerprint string
}

// Close ends the SSH connection.
func (s *Session) Close() error { return s.ssh.Close() }

// Dial connects with trust on first use: with no pinned key the presented one is accepted (the
// caller stores Session.Fingerprint); with one, any other key fails with ErrHostKeyChanged.
func Dial(ctx context.Context, d Device) (*Session, error) {
	auth := []ssh.AuthMethod{}
	if d.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(d.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("netconf: private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if d.Password != "" {
		auth = append(auth, ssh.Password(d.Password))
	}
	var seen string
	cfg := &ssh.ClientConfig{
		User: d.Username,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			if d.HostKey != "" && d.HostKey != seen {
				return ErrHostKeyChanged
			}
			return nil
		},
		Timeout: SSHTimeout,
	}
	port := d.Port
	if port == 0 {
		port = 830
	}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, SSHTimeout)
	defer cancel()
	var nd net.Dialer
	conn, err := nd.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(SSHTimeout))
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		if seen != "" && d.HostKey != "" && d.HostKey != seen {
			return nil, ErrHostKeyChanged
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Session{ssh: ssh.NewClient(sc, chans, reqs), Fingerprint: seen}, nil
}

// Conn is an established NETCONF session.
type Conn struct {
	sess    *ssh.Session
	in      io.WriteCloser
	out     *bufio.Reader
	chunked bool
	msgID   int
	// Caps are the capabilities the server announced in its hello.
	Caps map[string]bool
}

// OpenNetconf starts the netconf subsystem and exchanges hellos. Both sides advertise 1.0; when
// the server also offers 1.1 the session switches to chunked framing after the hello.
func (s *Session) OpenNetconf() (*Conn, error) {
	sess, err := s.ssh.NewSession()
	if err != nil {
		return nil, err
	}
	in, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.RequestSubsystem("netconf"); err != nil {
		return nil, err
	}
	c := &Conn{sess: sess, in: in, out: bufio.NewReader(out), Caps: map[string]bool{}}
	hello := `<hello xmlns="` + baseNS + `"><capabilities><capability>` + cap10 +
		`</capability><capability>` + cap11 + `</capability></capabilities></hello>`
	if err := writeMsg(in, false, []byte(hello)); err != nil {
		return nil, err
	}
	raw, err := readMsg(c.out, false)
	if err != nil {
		return nil, err
	}
	var h struct {
		Caps []string `xml:"capabilities>capability"`
	}
	if err := xml.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("netconf: server hello: %w", err)
	}
	for _, cp := range h.Caps {
		c.Caps[strings.TrimSpace(cp)] = true
	}
	c.chunked = c.Caps[cap11]
	return c, nil
}

// Close sends close-session (best effort) and ends the channel.
func (c *Conn) Close() {
	_, _ = c.rpc("<close-session/>")
	_ = c.in.Close()
	_ = c.sess.Close()
}

// rpcError is a device-reported <rpc-error>.
type rpcError struct{ Tag, Message string }

func (e *rpcError) Error() string { return "netconf rpc-error: " + e.Tag + " " + e.Message }

// rpc sends one operation and returns the reply body (children of <rpc-reply>).
func (c *Conn) rpc(op string) (string, error) {
	c.msgID++
	msg := `<rpc xmlns="` + baseNS + `" message-id="` + strconv.Itoa(c.msgID) + `">` + op + `</rpc>`
	if err := writeMsg(c.in, c.chunked, []byte(msg)); err != nil {
		return "", err
	}
	raw, err := readMsg(c.out, c.chunked)
	if err != nil {
		return "", err
	}
	var rep struct {
		Inner string `xml:",innerxml"`
		Err   *struct {
			Tag string `xml:"error-tag"`
			Msg string `xml:"error-message"`
		} `xml:"rpc-error"`
	}
	if err := xml.Unmarshal(raw, &rep); err != nil {
		return "", fmt.Errorf("netconf: reply: %w", err)
	}
	if rep.Err != nil {
		return "", &rpcError{Tag: rep.Err.Tag, Message: rep.Err.Msg}
	}
	return rep.Inner, nil
}

// GetConfig returns the inner XML of <data> for the datastore (running or startup).
func (c *Conn) GetConfig(store string) (string, error) {
	inner, err := c.rpc("<get-config><source><" + store + "/></source></get-config>")
	if err != nil {
		return "", err
	}
	start := strings.Index(inner, "<data")
	end := strings.LastIndex(inner, "</data>")
	if start < 0 || end < start {
		return "", errors.New("netconf: get-config reply has no <data>")
	}
	gt := strings.Index(inner[start:], ">")
	return strings.TrimSpace(inner[start+gt+1 : end]), nil
}

// SHA returns the hex SHA-256 of s.
func SHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// writeMsg frames and writes one message.
func writeMsg(w io.Writer, chunked bool, b []byte) error {
	var buf bytes.Buffer
	if chunked {
		fmt.Fprintf(&buf, "\n#%d\n", len(b))
		buf.Write(b)
		buf.WriteString("\n##\n")
	} else {
		buf.Write(b)
		buf.WriteString(eom)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// maxMsg bounds one reply (a large running config).
const maxMsg = 32 << 20

// readMsg reads one framed message.
func readMsg(r *bufio.Reader, chunked bool) ([]byte, error) {
	var msg bytes.Buffer
	if !chunked {
		for !bytes.HasSuffix(msg.Bytes(), []byte(eom)) {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			msg.WriteByte(b)
			if msg.Len() > maxMsg {
				return nil, errors.New("netconf: message too large")
			}
		}
		return bytes.TrimSuffix(msg.Bytes(), []byte(eom)), nil
	}
	for {
		line, err := r.ReadString('\n') // "\n" before "#<n>", or the "\n" after it
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(line) == "" { // the leading LF of a chunk header
			if line, err = r.ReadString('\n'); err != nil {
				return nil, err
			}
		}
		line = strings.TrimSpace(line)
		if line == "##" {
			return msg.Bytes(), nil
		}
		n, err := strconv.Atoi(strings.TrimPrefix(line, "#"))
		if err != nil || !strings.HasPrefix(line, "#") || n <= 0 || msg.Len()+n > maxMsg {
			return nil, fmt.Errorf("netconf: bad chunk header %q", line)
		}
		if _, err := io.CopyN(&msg, r, int64(n)); err != nil {
			return nil, err
		}
	}
}
