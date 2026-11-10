package integrations

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// TLSCertConfig is the tlscert module config: host:port targets to handshake with and PEM files
// to read. Both live only in the agent's own file.
type TLSCertConfig struct {
	Base
	Targets []string `json:"targets"`
	Files   []string `json:"files"`
}

func (c *TLSCertConfig) check() error {
	if len(c.Targets)+len(c.Files) == 0 {
		return errors.New("targets or files is required")
	}
	return nil
}

// TLSCert reports `tls.cert.expiry_seconds` (negative once expired) and `tls.cert.hostname_match`
// for each target's leaf certificate and each certificate in each file.
func TLSCert(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TLSCertConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "tlscert", c.Base, 5*time.Minute, out, func(ctx context.Context, now time.Time) error {
		var firstErr error
		for _, t := range c.Targets {
			cert, err := leafOf(ctx, t)
			if err != nil {
				firstErr = errors.Join(firstErr, errors.New("tlscert "+t+": "+err.Error()))
				continue
			}
			host, _, _ := net.SplitHostPort(t)
			emitCert(out, t, cert, host, now)
		}
		for _, f := range c.Files {
			b, err := os.ReadFile(f)
			if err != nil {
				firstErr = errors.Join(firstErr, errors.New("tlscert: cannot read "+f))
				continue
			}
			for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
				if cert, err := x509.ParseCertificate(blk.Bytes); blk.Type == "CERTIFICATE" && err == nil {
					emitCert(out, f, cert, "", now)
				}
			}
		}
		return firstErr
	})
}

// leafOf handshakes without verification (an expired or untrusted certificate must still be
// measured, not hidden) and returns the leaf the server presents.
func leafOf(ctx context.Context, target string) (*x509.Certificate, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, errors.New("target must be host:port")
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}} //nolint:gosec // measuring, not trusting
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, errors.New("handshake failed")
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs[0], nil
}

func emitCert(out sink.Sink, source string, c *x509.Certificate, host string, now time.Time) {
	a := map[string]string{"target": source, "subject": c.Subject.CommonName, "issuer": c.Issuer.CommonName}
	out.Gauge("tls.cert.expiry_seconds", "s", c.NotAfter.Sub(now).Seconds(), a, now)
	if host != "" {
		m := 0.0
		if c.VerifyHostname(host) == nil {
			m = 1
		}
		out.Gauge("tls.cert.hostname_match", "1", m, a, now)
	}
}
