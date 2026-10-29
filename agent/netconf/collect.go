package netconf

import (
	"context"
	"errors"
	"regexp"
)

// Store is the server side of the module: the device list, config uploads and host-key pins.
type Store interface {
	Devices(ctx context.Context) ([]Device, error)
	// Upload sends a redacted config; the server keeps it only when the hash differs from the
	// latest version.
	Upload(ctx context.Context, id, body, source string) (changed bool, err error)
	PinHostKey(ctx context.Context, id, fingerprint string) error
	// Version fetches a stored (redacted) config body, the source of a rollback.
	Version(ctx context.Context, id string, version int) (string, error)
}

var (
	xmlSecret = regexp.MustCompile(`(?i)(<[\w:.-]*(?:password|secret|community|key-string)[\w.-]*(?:\s[^>]*)?>)[^<]+`)
	cliSecret = regexp.MustCompile(`(?im)^([^\r\n]*?\b(?:password|secret|community|key-string)\b)[ \t]+[^\r\n]*$`)
)

// Redact hides secret values (password, secret, community, key-string) in XML elements and CLI
// lines. It runs before anything is hashed, stored or diffed.
func Redact(cfg string) string {
	cfg = xmlSecret.ReplaceAllString(cfg, "${1}REDACTED")
	return cliSecret.ReplaceAllString(cfg, "${1} REDACTED")
}

// Collector polls devices and uploads a config only when its hash differs from the last one
// this process sent.
type Collector struct {
	Store Store
	Creds map[string]Creds
	last  map[string]string
}

// Fetch connects (trust on first use), reads the running config (and startup when offered) or
// the CLI output, and returns it redacted. pinned is the fingerprint to store for a new pin.
func (c *Collector) Fetch(ctx context.Context, d Device) (body, pinned string, err error) {
	c.apply(&d)
	s, err := Dial(ctx, d)
	if err != nil {
		return "", "", err
	}
	defer s.Close()
	if d.HostKey == "" {
		pinned = s.Fingerprint
	}
	if d.Transport == "ssh_cli" {
		out, err := s.RunCLI(d.Commands)
		return Redact(out), pinned, err
	}
	nc, err := s.OpenNetconf()
	if err != nil {
		return "", pinned, err
	}
	defer nc.Close()
	body, err = nc.GetConfig("running")
	if err != nil {
		return "", pinned, err
	}
	if nc.Caps[capStrt] {
		if st, err := nc.GetConfig("startup"); err == nil {
			body += "\n<!-- startup -->\n" + st
		}
	}
	return Redact(body), pinned, nil
}

func (c *Collector) apply(d *Device) {
	cr := c.Creds[d.CredRef]
	d.Username, d.Password, d.PrivateKey = cr.Username, cr.Password, cr.PrivateKey
}

// Collect fetches one device and uploads the config if it changed. It returns whether the
// server stored a new version. A key mismatch is returned as ErrHostKeyChanged and nothing is
// sent; the caller raises the event.
func (c *Collector) Collect(ctx context.Context, d Device) (bool, error) {
	body, pinned, err := c.Fetch(ctx, d)
	if err != nil {
		return false, err
	}
	if pinned != "" {
		if err := c.Store.PinHostKey(ctx, d.ID, pinned); err != nil {
			return false, err
		}
	}
	if c.last == nil {
		c.last = map[string]string{}
	}
	sha := SHA(body)
	if c.last[d.ID] == sha {
		return false, nil
	}
	changed, err := c.Store.Upload(ctx, d.ID, body, "poll")
	if err != nil {
		return false, err
	}
	c.last[d.ID] = sha
	return changed, nil
}

// IsHostKeyChanged reports a pinned-key mismatch.
func IsHostKeyChanged(err error) bool { return errors.Is(err, ErrHostKeyChanged) }
