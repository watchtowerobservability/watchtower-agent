package netconf

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
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

// StartupStore is implemented by a Store that keeps the startup config apart from the running
// versions (INF-017), so running-vs-startup can be compared.
type StartupStore interface {
	UploadStartup(ctx context.Context, id, body string) error
}

// Collector polls devices and uploads a config only when its hash differs from the last one
// this process sent.
type Collector struct {
	Store       Store
	Creds       map[string]Creds
	last        map[string]string
	lastStartup map[string]string
}

// Fetch connects (trust on first use), reads the running config or the CLI output, and returns
// it redacted. pinned is the fingerprint to store for a new pin.
func (c *Collector) Fetch(ctx context.Context, d Device) (body, pinned string, err error) {
	body, _, pinned, err = c.fetch(ctx, d)
	return body, pinned, err
}

// startupCLI reads the startup config of a CLI device that backs up `show running-config`.
// Its header is renamed so the two bodies line up in a compare; a device without the command
// (an error text instead of a config) yields "".
func startupCLI(s *Session, cmds []string) string {
	if len(cmds) > 0 && !slices.Equal(cmds, DefaultCommands) {
		return ""
	}
	out, err := s.RunCLI([]string{"show startup-config"})
	if err != nil {
		return ""
	}
	_, cfg, _ := strings.Cut(out, "\n")
	cfg = strings.TrimSpace(cfg)
	if cfg == "" || strings.HasPrefix(cfg, "%") || strings.Contains(cfg, "Invalid input") || strings.Contains(cfg, "not present") {
		return ""
	}
	return strings.Replace(out, "### show startup-config\n", "### show running-config\n", 1)
}

// fetch also returns the startup config (NETCONF startup datastore when the device offers the
// capability, `show startup-config` for CLI devices), redacted, or "" when there is none.
func (c *Collector) fetch(ctx context.Context, d Device) (body, startup, pinned string, err error) {
	c.apply(&d)
	s, err := Dial(ctx, d)
	if err != nil {
		return "", "", "", err
	}
	defer s.Close()
	if d.HostKey == "" {
		pinned = s.Fingerprint
	}
	if d.Transport == "ssh_cli" {
		out, err := s.RunCLI(d.Commands)
		if err != nil {
			return "", "", pinned, err
		}
		return Redact(out), Redact(startupCLI(s, d.Commands)), pinned, nil
	}
	nc, err := s.OpenNetconf()
	if err != nil {
		return "", "", pinned, err
	}
	defer nc.Close()
	body, err = nc.GetConfig("running")
	if err != nil {
		return "", "", pinned, err
	}
	if nc.Caps[capStrt] {
		if st, err := nc.GetConfig("startup"); err == nil {
			startup = Redact(st)
		}
	}
	return Redact(body), startup, pinned, nil
}

func (c *Collector) apply(d *Device) {
	cr := c.Creds[d.CredRef]
	d.Username, d.Password, d.PrivateKey = cr.Username, cr.Password, cr.PrivateKey
}

// Collect fetches one device and uploads the config if it changed. It returns whether the
// server stored a new version. A key mismatch is returned as ErrHostKeyChanged and nothing is
// sent; the caller raises the event.
func (c *Collector) Collect(ctx context.Context, d Device) (bool, error) {
	body, startup, pinned, err := c.fetch(ctx, d)
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
	c.uploadStartup(ctx, d.ID, startup)
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

// uploadStartup sends a changed startup config to a store that keeps it. It is best effort: a
// failure is retried on the next poll and never blocks the running-config backup.
func (c *Collector) uploadStartup(ctx context.Context, id, startup string) {
	ss, ok := c.Store.(StartupStore)
	if !ok || startup == "" {
		return
	}
	if c.lastStartup == nil {
		c.lastStartup = map[string]string{}
	}
	sha := SHA(startup)
	if c.lastStartup[id] == sha {
		return
	}
	if ss.UploadStartup(ctx, id, startup) == nil {
		c.lastStartup[id] = sha
	}
}

// IsHostKeyChanged reports a pinned-key mismatch.
func IsHostKeyChanged(err error) bool { return errors.Is(err, ErrHostKeyChanged) }
