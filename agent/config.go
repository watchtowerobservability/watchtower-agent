package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-agent/agent/commands"
)

// LocalConfig is the agent's own file (YAML). It holds everything that decides what the server
// may and may not do to this host: the plugin directory and the scrape allow list live here and
// cannot be set by remote config.
type LocalConfig struct {
	// Endpoint is the gateway base URL for OTLP/HTTP (https://host:4318).
	Endpoint string `yaml:"endpoint"`
	// FleetEndpoint is the wt-edge base URL (default: Endpoint).
	FleetEndpoint string `yaml:"fleet_endpoint"`
	// TokenFile holds the `wti_` token; WT_AGENT_TOKEN overrides it.
	TokenFile string `yaml:"token_file"`
	StateDir  string `yaml:"state_dir"`
	// Labels select remote configs. Strings only.
	Labels map[string]string `yaml:"labels"`
	// PluginDir is where the Nagios plugins named in the local modules live. Use a directory that
	// holds only checks you vet; never a stock plugin dir with wrapper plugins (negate, urlize,
	// check_by_ssh). Empty disables the nagios module.
	PluginDir string `yaml:"plugin_dir"`
	// ScrapeAllow lists host:port values remote config may scrape.
	ScrapeAllow []string `yaml:"scrape_allow"`
	// BufferDir enables the on-disk export buffer (batches that could not be sent are kept there
	// and replayed after a restart); BufferMaxBytes caps it (default 512 MiB, oldest dropped).
	BufferDir      string `yaml:"buffer_dir"`
	BufferMaxBytes int64  `yaml:"buffer_max_bytes"`
	// BufferWhenFull is what a full disk buffer does: "drop_oldest" (default) discards the oldest
	// segment, "drop_newest" refuses new batches so the oldest data is delivered first.
	BufferWhenFull string `yaml:"buffer_when_full"`
	// InsecureHTTP allows plain http to a non-loopback endpoint (never for production).
	InsecureHTTP bool `yaml:"insecure_http"`
	// DisableRemoteConfig makes the agent ignore the server's config.
	DisableRemoteConfig bool `yaml:"disable_remote_config"`
	// FleetMode is "" (edge long poll) or "opamp" (wt-fleet over OpAMP, P6-FL1).
	FleetMode string `yaml:"fleet_mode"`
	// OpAMPEndpoint is the wt-fleet OpAMP URL (default: FleetEndpoint + /v1/opamp).
	OpAMPEndpoint string `yaml:"opamp_endpoint"`
	// Commands is the allowlist of commands the server may trigger by name (remediation actions,
	// P5-R1). Empty means none; the server never sends script text.
	Commands []commands.Command `yaml:"commands"`
	// Forward sends a copy of every export to third-party backends (forward.go). Local only.
	Forward []ForwardTarget `yaml:"forward"`
	// Modules is the local module config, by module name.
	Modules map[string]json.RawMessage `yaml:"-"`
	// RawModules lets YAML carry arbitrary module configs.
	RawModules map[string]any `yaml:"modules"`
}

// LoadLocal reads and validates the config file. A non-empty WT_AGENT_CONFIG_YAML replaces the
// file (containers that get their config through the environment).
func LoadLocal(path string) (*LocalConfig, error) {
	var b []byte
	if env := os.Getenv("WT_AGENT_CONFIG_YAML"); strings.TrimSpace(env) != "" {
		b, path = []byte(env), "WT_AGENT_CONFIG_YAML"
	} else {
		var err error
		if b, err = os.ReadFile(path); err != nil {
			return nil, err
		}
	}
	var c LocalConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Modules = map[string]json.RawMessage{}
	for k, v := range c.RawModules {
		j, err := json.Marshal(normalize(v))
		if err != nil {
			return nil, fmt.Errorf("modules.%s: %w", k, err)
		}
		c.Modules[k] = j
	}
	if c.FleetEndpoint == "" {
		c.FleetEndpoint = c.Endpoint
	}
	if c.StateDir == "" {
		c.StateDir = defaultStateDir()
	}
	return &c, c.validate()
}

// normalize turns yaml.v3's map[string]any / []any tree into something json can marshal.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalize(x)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = normalize(x)
		}
		return m
	case []any:
		for i, x := range t {
			t[i] = normalize(x)
		}
		return t
	}
	return v
}

func (c *LocalConfig) validate() error {
	for _, u := range []string{c.Endpoint, c.FleetEndpoint} {
		if err := checkEndpoint(u, c.InsecureHTTP); err != nil {
			return err
		}
	}
	if c.FleetMode != "" && c.FleetMode != "opamp" {
		return errors.New(`fleet_mode must be "" or "opamp"`)
	}
	if c.OpAMPEndpoint != "" {
		if err := checkEndpoint(c.OpAMPEndpoint, c.InsecureHTTP); err != nil {
			return err
		}
	}
	if len(c.Labels) > 50 {
		return errors.New("at most 50 labels")
	}
	return commands.ValidateAllowlist(c.Commands)
}

// checkEndpoint requires https, except to a loopback host or with insecure_http, because the
// token and the remote config travel over this connection.
func checkEndpoint(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("endpoint %q is not a URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if insecure || h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return fmt.Errorf("endpoint %q must be https (set insecure_http only for tests)", raw)
}

// Token returns the credential from WT_AGENT_TOKEN or token_file.
func (c *LocalConfig) Token() (string, error) {
	if t := strings.TrimSpace(os.Getenv("WT_AGENT_TOKEN")); t != "" {
		return t, nil
	}
	if c.TokenFile == "" {
		return "", errors.New("no token: set WT_AGENT_TOKEN or token_file")
	}
	b, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if !strings.HasPrefix(t, "wti_") {
		return "", errors.New("token_file does not hold a wti_ token")
	}
	return t, nil
}

// RemoteConfig is the content of a served config body.
type RemoteConfig struct {
	Modules map[string]json.RawMessage `json:"modules"`
}

// Served is the GET /v1/agents/{id}/config response. Selector and Body are the exact JSON texts
// the server signed. Version 0 with an empty ConfigID means "no config applies any more".
type Served struct {
	Version int `json:"version"`
	// Gen is the project's config generation when the server answered. It only grows, so the
	// agent refuses a response with a lower one than it has seen (a replay).
	Gen      int64  `json:"gen"`
	ConfigID string `json:"config_id"`
	Selector string `json:"selector"`
	SHA256   string `json:"sha256"`
	MAC      string `json:"mac"`
	Body     string `json:"body"`
}

// AgentIDKey is the selector key that matches the agent's own server-assigned id.
const AgentIDKey = "wt.agent.id"

// macKey mirrors wt_auth::config_mac: HMAC-SHA256 keyed with
// sha256("wt-agent-config-v1" || sha256(token)).
func macKey(token string) []byte {
	stored := sha256.Sum256([]byte(token))
	k := sha256.Sum256(append([]byte("wt-agent-config-v1"), stored[:]...))
	return k[:]
}

// macOf mirrors the edge's mac_message.
func macOf(token, agentID string, s *Served) string {
	m := hmac.New(sha256.New, macKey(token))
	fmt.Fprintf(m, "%s\n%s\n%d\n%d\n%s\n%s", agentID, s.ConfigID, s.Version, s.Gen, s.Selector, s.Body)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify checks a served config before anything in it is used: the body hash, the HMAC over
// agent, config id, version, selector and body, and that the selector matches this agent's
// labels. It is a tamper check, not protection against the server itself: what a config can do
// is bounded by the agent's local policy (see Overlayer). It returns the parsed config.
func (s *Served) Verify(token, agentID string, labels map[string]string) (*RemoteConfig, error) {
	sum := sha256.Sum256([]byte(s.Body))
	if !hmac.Equal([]byte(hex.EncodeToString(sum[:])), []byte(s.SHA256)) {
		return nil, errors.New("remote config: sha256 mismatch")
	}
	if !hmac.Equal([]byte(macOf(token, agentID, s)), []byte(s.MAC)) {
		return nil, errors.New("remote config: bad signature")
	}
	var sel map[string]string
	if err := json.Unmarshal([]byte(s.Selector), &sel); err != nil {
		return nil, fmt.Errorf("remote config selector: %w", err)
	}
	// wt.agent.id addresses one agent by the id the server assigned it (the signed agent id), not
	// by a local label: the agent's own file cannot claim it, and the server fills it in the same way.
	eff := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		eff[k] = v
	}
	eff[AgentIDKey] = agentID
	if !Match(sel, eff) {
		return nil, errors.New("remote config: selector does not match this agent")
	}
	dec := json.NewDecoder(strings.NewReader(s.Body))
	dec.DisallowUnknownFields()
	var raw struct {
		Interval any                        `json:"interval"`
		Modules  map[string]json.RawMessage `json:"modules"`
	}
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("remote config: %w", err)
	}
	return &RemoteConfig{Modules: raw.Modules}, nil
}

// Applied remembers, in <state_dir>/applied.json, the highest generation seen and the highest
// version applied per config id, so an older signed response that is replayed (by a proxy or a
// restored backup) is refused, also across restarts.
type Applied struct {
	path string
	mu   sync.Mutex
	// Gen is the highest config generation seen; V the highest version applied per config id.
	Gen int64          `json:"gen"`
	V   map[string]int `json:"v"`
}

// LoadApplied reads the file. A missing file starts empty; a torn or invalid one is logged and
// also starts empty (the next successful write replaces it), since the state cannot be trusted.
func LoadApplied(stateDir string) *Applied {
	a := &Applied{path: filepath.Join(stateDir, "applied.json"), V: map[string]int{}}
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return a
	}
	if err == nil {
		err = json.Unmarshal(b, a)
	}
	if err != nil {
		slog.Warn("applied.json unreadable: replay protection restarts from this run", "error", err)
		a.Gen, a.V = 0, map[string]int{}
	}
	if a.V == nil {
		a.V = map[string]int{}
	}
	return a
}

// Check refuses a response from an older generation, or an older version of a config already
// applied.
func (a *Applied) Check(s *Served) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Gen < a.Gen {
		return fmt.Errorf("remote config: generation %d is older than the %d already seen", s.Gen, a.Gen)
	}
	if s.ConfigID != "" && s.Version < a.V[s.ConfigID] {
		return fmt.Errorf("remote config %s: version %d is older than the applied %d", s.ConfigID, s.Version, a.V[s.ConfigID])
	}
	return nil
}

// Record stores an applied response. A failed write is logged; the in-memory state still holds.
func (a *Applied) Record(s *Served) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Gen = max(a.Gen, s.Gen)
	if s.ConfigID != "" {
		a.V[s.ConfigID] = max(a.V[s.ConfigID], s.Version)
	}
	b, err := json.Marshal(a)
	if err == nil {
		err = writeFileAtomic(a.path, b, 0o600)
	}
	if err != nil {
		slog.Warn("cannot persist applied.json", "error", err)
	}
}

// writeFileAtomic writes via a temp file in the same directory, fsyncs it and renames it over
// path, so a crash leaves the old file or the new one, never a torn one.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Candidate is a config with its selector, for Select.
type Candidate struct {
	Name      string
	Selector  map[string]string
	CreatedAt int64
	Version   int
}

// Match reports whether every selector pair equals the label. {} matches all.
func Match(selector, labels map[string]string) bool {
	for k, v := range selector {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// Select mirrors the server's rule (wt_store_pg::pick_config): the most specific match (most
// matchers), ties broken by the newest, then the higher version. The server decides; this copy
// exists so the rule is pinned by a test on both sides.
func Select(labels map[string]string, cands []Candidate) (Candidate, bool) {
	var best Candidate
	found := false
	for _, c := range cands {
		if !Match(c.Selector, labels) {
			continue
		}
		better := !found ||
			len(c.Selector) > len(best.Selector) ||
			len(c.Selector) == len(best.Selector) && (c.CreatedAt > best.CreatedAt ||
				c.CreatedAt == best.CreatedAt && c.Version > best.Version)
		if better {
			best, found = c, true
		}
	}
	return best, found
}
