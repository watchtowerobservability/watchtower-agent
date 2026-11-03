// Package meraki polls the Cisco Meraki Dashboard API v1 (INF-015): device statuses, uplink
// loss and latency, and client counts per network. The API key lives only in the agent's own
// file (normally a ${env:...} or ${file:...} reference, resolved before Start); it is sent only
// to the configured origin and never logged. Requests go through the netguard client; pagination
// links and redirects that leave the Meraki domain are refused.
package meraki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

const (
	defaultBase = "https://api.meraki.com/api/v1"
	maxBody     = 16 << 20
	maxPages    = 50
)

// Config is the meraki module's local config. Remote config may only toggle it.
type Config struct {
	Enabled       *bool    `json:"enabled"`
	Interval      string   `json:"interval"` // default 5m, at least 1m (the API allows 10 req/s per org)
	BaseURL       string   `json:"base_url"` // default https://api.meraki.com/api/v1 (regional clouds differ)
	APIKey        string   `json:"api_key"`  // a ${env:...} or ${file:...} reference
	Organizations []string `json:"organizations"`
	// ClientCounts reads clients/overview once per network; off saves one call per network.
	ClientCounts *bool `json:"client_counts"`
}

// Client is one Dashboard API session.
type Client struct {
	base   *url.URL
	key    string
	domain string // redirects may only stay inside this registrable domain
	hc     *http.Client
}

// New validates the config and builds the client.
func New(c Config) (*Client, error) {
	if c.APIKey == "" {
		return nil, errors.New("meraki: api_key is required")
	}
	raw := c.BaseURL
	if raw == "" {
		raw = defaultBase
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("meraki: bad base_url")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("meraki: base_url must be https (http only for loopback)")
		}
	}
	cl := &Client{base: u, key: c.APIKey, domain: regDomain(u.Hostname())}
	cl.hc = netguard.NewClient(netguard.FromEnv("agent"))
	cl.hc.Timeout = 30 * time.Second
	cl.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !cl.sameDomain(req.URL) {
			return errors.New("meraki: redirect leaves the api domain")
		}
		req.Header.Set("Authorization", "Bearer "+cl.key) // net/http drops it across hosts
		return nil
	}
	return cl, nil
}

// regDomain keeps the last two labels (api.meraki.com -> meraki.com); an IP stays as it is.
func regDomain(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (c *Client) sameDomain(u *url.URL) bool {
	h := u.Hostname()
	return u.Scheme == c.base.Scheme && (h == c.domain || strings.HasSuffix(h, "."+c.domain))
}

// get reads one page; next is the rel="next" link, already checked to stay on the api domain.
func (c *Client) get(ctx context.Context, target string, dst any) (next string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", errors.New("meraki: bad request")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", errors.New("meraki: request failed") // the url error names the host and path
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("meraki: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(dst); err != nil {
		return "", errors.New("meraki: bad response")
	}
	return c.nextLink(resp.Header.Get("Link")), nil
}

func (c *Client) nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		link, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(strings.ReplaceAll(params, `"`, ""), "rel=next") {
			continue
		}
		raw := strings.Trim(strings.TrimSpace(link), "<>")
		u, err := c.base.Parse(raw)
		if err != nil || !c.sameDomain(u) {
			return ""
		}
		return u.String()
	}
	return ""
}

// list walks a paginated collection, decoding each page into a slice of T.
func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	target := c.base.String() + path
	for range maxPages {
		var page []T
		next, err := c.get(ctx, target, &page)
		if err != nil {
			return out, err
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		target = next
	}
	return out, nil
}

// Org is one Meraki organization.
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type deviceStatus struct {
	Name        string `json:"name"`
	Serial      string `json:"serial"`
	NetworkID   string `json:"networkId"`
	Status      string `json:"status"` // online, alerting, offline, dormant
	ProductType string `json:"productType"`
	Model       string `json:"model"`
}

type uplinkLL struct {
	NetworkID  string `json:"networkId"`
	Serial     string `json:"serial"`
	Uplink     string `json:"uplink"`
	IP         string `json:"ip"`
	TimeSeries []struct {
		LossPercent *float64 `json:"lossPercent"`
		LatencyMs   *float64 `json:"latencyMs"`
	} `json:"timeSeries"`
}

var statuses = []string{"online", "alerting", "offline", "dormant"}

// PollOrg reads one organization and emits meraki.* metrics.
func (c *Client) PollOrg(ctx context.Context, o Org, clients bool, out sink.Sink, at time.Time) error {
	base := map[string]string{"meraki.org.id": o.ID, "meraki.org.name": o.Name}
	nets, err := list[network](ctx, c, "/organizations/"+url.PathEscape(o.ID)+"/networks?perPage=1000")
	netName := map[string]string{}
	for _, n := range nets {
		netName[n.ID] = n.Name
	}
	devs, derr := list[deviceStatus](ctx, c, "/organizations/"+url.PathEscape(o.ID)+"/devices/statuses?perPage=1000")
	names := map[string]string{}
	for _, d := range devs {
		names[d.Serial] = d.Name
		a := sink.With(base, "device.id", d.Serial, "device.name", nameOr(d.Name, d.Serial), "device.model.identifier", d.Model,
			"meraki.product_type", d.ProductType, "meraki.network.id", d.NetworkID, "meraki.network.name", netName[d.NetworkID])
		up := 0.0
		if d.Status == "online" || d.Status == "alerting" {
			up = 1
		}
		out.Gauge("meraki.device.up", "1", up, a, at)
		for _, s := range statuses {
			v := 0.0
			if d.Status == s {
				v = 1
			}
			out.Gauge("meraki.device.status", "1", v, sink.With(a, "meraki.device.status", s), at)
		}
	}
	lls, lerr := list[uplinkLL](ctx, c, "/organizations/"+url.PathEscape(o.ID)+"/devices/uplinksLossAndLatency?timespan=300")
	for _, l := range lls {
		a := sink.With(base, "device.id", l.Serial, "device.name", nameOr(names[l.Serial], l.Serial), "meraki.uplink", l.Uplink,
			"meraki.uplink.probe_ip", l.IP, "meraki.network.id", l.NetworkID, "meraki.network.name", netName[l.NetworkID])
		var loss, lat *float64
		for _, p := range l.TimeSeries { // oldest first: keep the latest point that has a value
			if p.LossPercent != nil {
				loss = p.LossPercent
			}
			if p.LatencyMs != nil {
				lat = p.LatencyMs
			}
		}
		if loss != nil {
			out.Gauge("meraki.uplink.loss", "%", *loss, a, at)
		}
		if lat != nil {
			out.Gauge("meraki.uplink.latency", "ms", *lat, a, at)
		}
	}
	var cerr error
	if clients {
		for _, n := range nets {
			var ov struct {
				Counts struct {
					Total *float64 `json:"total"`
				} `json:"counts"`
			}
			if _, e := c.get(ctx, c.base.String()+"/networks/"+url.PathEscape(n.ID)+"/clients/overview?timespan=3600", &ov); e != nil {
				if cerr == nil {
					cerr = e
				}
				continue
			}
			if ov.Counts.Total != nil {
				out.Gauge("meraki.network.clients", "{client}", *ov.Counts.Total,
					sink.With(base, "meraki.network.id", n.ID, "meraki.network.name", n.Name, "meraki.window", "1h"), at)
			}
		}
	}
	for _, e := range []error{derr, lerr, cerr} {
		if err == nil {
			err = e
		}
	}
	return err
}

func nameOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Orgs returns the configured organizations, or every one the key can read.
func (c *Client) Orgs(ctx context.Context, ids []string) ([]Org, error) {
	all, err := list[Org](ctx, c, "/organizations")
	if err != nil || len(ids) == 0 {
		return all, err
	}
	var out []Org
	for _, o := range all {
		for _, id := range ids {
			if o.ID == id {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// Run polls every interval until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("meraki config: %w", err)
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	cl, err := New(c)
	if err != nil {
		return err
	}
	clients := c.ClientCounts == nil || *c.ClientCounts
	host.Every(ctx, host.Duration(c.Interval, 5*time.Minute, time.Minute), func(ctx context.Context) {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		at := time.Now()
		orgs, err := cl.Orgs(pctx, c.Organizations)
		if err != nil {
			host.Warn("meraki organizations", host.Redact(err, cl.key))
			return
		}
		for _, o := range orgs {
			host.Warn("meraki org "+o.ID, host.Redact(cl.PollOrg(pctx, o, clients, out, at), cl.key))
		}
	})
	return nil
}
