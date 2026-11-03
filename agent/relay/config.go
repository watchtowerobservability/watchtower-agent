package relay

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the relay's YAML file (`wt-agent --mode relay -config relay.yaml`).
type Config struct {
	ListenHTTP string `yaml:"listen_http"` // default :4318
	ListenGRPC string `yaml:"listen_grpc"` // default :4317
	// Upstream is the gateway OTLP/HTTP base URL (https://ingest.example.com:4318).
	Upstream string `yaml:"upstream"`
	// KeyFile holds the project's ingestion key (wti_...); WT_RELAY_KEY overrides it.
	KeyFile string `yaml:"key_file"`
	// AcceptTokenFile, when set, makes the relay require `Authorization: Bearer <token>` from
	// local senders (WT_RELAY_ACCEPT_TOKEN overrides the file).
	AcceptTokenFile string `yaml:"accept_token_file"`
	// API and TokenFile register heartbeats (every 30 s) with the control plane; the relay token
	// (wtr_...) comes from `POST /v1/projects/{p}/relays`. WT_RELAY_TOKEN overrides the file.
	API       string `yaml:"api"`
	TokenFile string `yaml:"token_file"`
	Queue     struct {
		Dir      string `yaml:"dir"`
		MaxBytes int64  `yaml:"max_bytes"` // default 1 GiB
	} `yaml:"queue"`
	Processors ProcessorConfig `yaml:"processors"`
	// MetricProcessors run on metrics (metrics_proc.go).
	MetricProcessors []MetricStage `yaml:"metric_processors"`
	// SpanLogs writes a log record per forwarded span (span_logs.go).
	SpanLogs SpanLogs `yaml:"span_logs"`
	// Self is this relay's URL as its peers reach it. Peers lists the other relays of the
	// peer group, and PeersFile (JSON array or one URL per line, written by fleet config) is
	// re-read every 30 s. PeerSecretFile holds the group secret (WT_RELAY_PEER_SECRET).
	Self           string   `yaml:"self"`
	Peers          []string `yaml:"peers"`
	PeersFile      string   `yaml:"peers_file"`
	PeerSecretFile string   `yaml:"peer_secret_file"`
	// InsecureHTTP allows plain http to non-loopback upstreams and peers (never for production).
	InsecureHTTP bool `yaml:"insecure_http"`
}

// LoadConfig reads and validates a relay config; unknown keys are errors.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c.defaults()
	return c, c.Validate()
}

func (c *Config) defaults() {
	if c.ListenHTTP == "" {
		c.ListenHTTP = ":4318"
	}
	if c.ListenGRPC == "" {
		c.ListenGRPC = ":4317"
	}
	if c.Queue.MaxBytes <= 0 {
		c.Queue.MaxBytes = DefaultQueueBytes
	}
	c.Upstream = strings.TrimRight(c.Upstream, "/")
	c.API = strings.TrimRight(c.API, "/")
}

// Validate checks everything that can be checked without the network.
func (c Config) Validate() error {
	if err := c.checkURL("upstream", c.Upstream, true); err != nil {
		return err
	}
	if c.API != "" {
		if err := c.checkURL("api", c.API, true); err != nil {
			return err
		}
	}
	if c.Queue.Dir == "" {
		return errors.New("queue.dir is required")
	}
	if _, err := Compile(c.Processors); err != nil {
		return fmt.Errorf("processors: %w", err)
	}
	if len(c.Peers) > 0 || c.PeersFile != "" {
		if c.Self == "" {
			return errors.New("self is required with peers")
		}
		if c.PeerSecretFile == "" && os.Getenv("WT_RELAY_PEER_SECRET") == "" {
			return errors.New("peer_secret_file (or WT_RELAY_PEER_SECRET) is required with peers")
		}
		for _, p := range append([]string{c.Self}, c.Peers...) {
			if err := c.checkURL("peer", p, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Config) checkURL(what, raw string, required bool) error {
	if raw == "" {
		if required {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%s must be an http(s) URL", what)
	}
	if u.Scheme == "http" && !c.InsecureHTTP && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return fmt.Errorf("%s uses plain http; set insecure_http only for tests", what)
	}
	return nil
}

// secret reads a one-line secret from env (preferred) or file; "" when neither is set.
func secret(env, file string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v, nil
	}
	if file == "" {
		return "", nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
