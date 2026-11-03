package cloud

// Shared scheduler for the cloud metric pulls (GCP Cloud Monitoring, Azure Monitor, Cloudflare;
// AWS CloudWatch stays in RunAWS and is started from here too). Every run asks for the window
// since the last successful run plus a 5-minute overlap, so a late datapoint is not lost;
// the overlap is deduplicated by (series, timestamp) before it reaches the sink, which makes
// delivery at-least-once without double counting. A 429 backs off (Retry-After, else the agent's
// exponential backoff). Credentials come from the agent's own file and never reach a label,
// a log line or an error.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	pullOverlap     = 5 * time.Minute
	minPullInterval = 60 * time.Second
	maxPullBody     = 16 << 20
)

// PullSpec is one entry of the module's "pulls" list.
type PullSpec struct {
	Provider  string          `json:"provider"` // aws, gcp, azure, cloudflare
	IntervalS int             `json:"interval_s"`
	Config    json.RawMessage `json:"config"`
	// PublicOnly marks a tenant's row: every call goes through tenantClient. An agent's own config
	// may reach private endpoints, a tenant's may not.
	PublicOnly bool `json:"public_only,omitempty"`
}

// EndpointKeys are the config keys that say where a credential is sent.
var EndpointKeys = []string{"endpoint", "login_endpoint"}

// MergeCredential adds an opened credential to a tenant row's config. An endpoint counts only from
// inside the credential, where the API seals it: it can only change along with the credential, so
// editing a row cannot send a stored credential to another host.
func MergeCredential(cfg, sec map[string]any) {
	for _, k := range EndpointKeys {
		delete(cfg, k)
	}
	for k, v := range sec {
		cfg[k] = v
	}
}

// strictTenantClient refuses private addresses after DNS and on redirects, and honours the airgap.
func strictTenantClient() *http.Client {
	p := netguard.FromEnv("agent")
	p.AllowPrivate = false
	c := netguard.NewClient(p)
	c.Timeout = 30 * time.Second
	return c
}

// tenantClient is a variable so tests can reach their local servers.
var tenantClient = strictTenantClient

func (a *azurePull) setClient(c *http.Client)      { a.cl = c }
func (g *gcpPull) setClient(c *http.Client)        { g.cl = c }
func (c *cloudflarePull) setClient(h *http.Client) { c.cl = h }
func (v *vercelPull) setClient(c *http.Client)     { v.cl = c }

type pullConfig struct {
	Pulls []PullSpec `json:"pulls"`
}

type puller interface {
	// pull emits the datapoints in [from, to) through e.
	pull(ctx context.Context, from, to time.Time, e *emitter) error
}

// rateLimitErr is a provider 429.
type rateLimitErr struct{ after time.Duration }

func (e *rateLimitErr) Error() string { return "rate limited by provider" }

// emitter deduplicates datapoints by (series, ts) and counts the distinct series it saw.
type emitter struct {
	out      sink.Sink
	provider string
	mu       sync.Mutex
	seen     map[string]time.Time
	series   map[string]struct{}
}

func newEmitter(out sink.Sink, provider string) *emitter {
	return &emitter{out: out, provider: provider, seen: map[string]time.Time{}, series: map[string]struct{}{}}
}

func seriesID(name string, attrs map[string]string) string {
	ks := make([]string, 0, len(attrs))
	for k := range attrs {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	b.WriteString(name)
	for _, k := range ks {
		b.WriteString("\x00" + k + "=" + attrs[k])
	}
	return b.String()
}

// gauge emits one point unless this (series, ts) was already emitted. res holds the resource
// attributes (cloud.account.id, cloud.region, cloud.resource_id); cloud.provider is added.
func (e *emitter) gauge(name, unit string, v float64, at time.Time, res, attrs map[string]string) {
	a := sink.With(attrs)
	for k, val := range res {
		if val != "" {
			a[sink.ResourcePrefix+k] = val
		}
	}
	a[sink.ResourcePrefix+"cloud.provider"] = e.provider
	id := seriesID(name, a)
	key := id + "\x00" + strconv.FormatInt(at.UnixNano(), 10)
	e.mu.Lock()
	_, dup := e.seen[key]
	if !dup {
		e.seen[key] = at
		e.series[id] = struct{}{}
	}
	e.mu.Unlock()
	if !dup {
		e.out.Gauge(name, unit, v, a, at)
	}
}

// finish drops dedupe entries older than the overlap window and reports the pulled series.
func (e *emitter) finish(to time.Time) {
	e.mu.Lock()
	for k, at := range e.seen {
		if to.Sub(at) > 2*pullOverlap {
			delete(e.seen, k)
		}
	}
	n := len(e.series)
	clear(e.series)
	e.mu.Unlock()
	e.out.Gauge("cloud.pull.pulled_series", "{series}", float64(n),
		map[string]string{sink.ResourcePrefix + "cloud.provider": e.provider}, to)
}

// pullState is the scheduler state of one pull.
type pullState struct {
	last     time.Time
	attempts int
	interval time.Duration
}

// step runs one pull at now and returns how long to wait before the next one.
func (s *pullState) step(ctx context.Context, p puller, e *emitter, now time.Time) time.Duration {
	from := s.last.Add(-pullOverlap)
	if s.last.IsZero() {
		from = now.Add(-pullOverlap - s.interval)
	}
	err := p.pull(ctx, from, now, e)
	var rl *rateLimitErr
	switch {
	case errors.As(err, &rl):
		d := max(rl.after, sink.Backoff(s.attempts, rand.Float64())) //nolint:gosec // jitter
		s.attempts++
		return d
	case err != nil:
		e.out.Log("WARN", "cloud pull failed: "+err.Error(), map[string]string{"cloud.provider": e.provider}, now)
		s.attempts++
		return max(s.interval, sink.Backoff(s.attempts-1, rand.Float64())) //nolint:gosec // jitter
	}
	s.attempts, s.last = 0, now
	e.finish(now)
	return s.interval
}

func (s *pullState) loop(ctx context.Context, p puller, e *emitter) {
	for {
		wait := s.step(ctx, p, e, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func newPuller(spec PullSpec) (puller, error) {
	var p puller
	var err error
	switch spec.Provider {
	case "gcp":
		p, err = newGCP(spec.Config)
	case "azure":
		p, err = newAzure(spec.Config)
	case "cloudflare":
		p, err = newCloudflare(spec.Config)
	case "vercel":
		p, err = newVercel(spec.Config)
	default:
		return nil, fmt.Errorf("unknown cloud pull provider %q", spec.Provider)
	}
	if err != nil {
		return nil, err
	}
	if s, ok := p.(interface{ setClient(*http.Client) }); ok && spec.PublicOnly {
		s.setClient(tenantClient())
	}
	return p, nil
}

// RunPulls starts every configured pull and blocks until ctx ends. A bad entry is reported and
// skipped so one typo does not stop the others.
func RunPulls(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return RunPullsIn(ctx, raw, "", out)
}

// RunPullsIn is RunPulls for a BYOC agent: when out keeps no positions itself, App Insights
// positions are kept in stateDir (empty: in memory only).
func RunPullsIn(ctx context.Context, raw json.RawMessage, stateDir string, out sink.Sink) error {
	var c pullConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	ship := spanShipper(out) // before Hoist wraps it
	store, _ := out.(cursorStore)
	local := store == nil && stateDir != ""
	if local {
		store = newFileCursors(stateDir, out)
	}
	out = sink.Hoist(out)
	var wg sync.WaitGroup
	for _, spec := range c.Pulls {
		if spec.Provider == "azure_appinsights" {
			p, err := newAppInsights(spec.Config)
			if err == nil && ship == nil {
				err = errors.New("this sink takes no spans")
			}
			if err != nil {
				out.Log("ERROR", "cloud pull not started: "+err.Error(), map[string]string{"cloud.provider": "azure"}, time.Now())
				continue
			}
			if spec.PublicOnly {
				p.cl = tenantClient()
			}
			p.store = store
			if local {
				p.c.PullID = localPullID
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.run(ctx, max(time.Duration(spec.IntervalS)*time.Second, minPullInterval), ship, out)
			}()
			continue
		}
		if spec.Provider == "databases" {
			wg.Add(1)
			go func() { defer wg.Done(); _ = RunDBDiscovery(ctx, spec.Config, out) }()
			continue
		}
		if spec.Provider == "aws" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var hc *http.Client
				if spec.PublicOnly {
					hc = tenantClient()
				}
				_ = runAWS(ctx, spec.Config, out, hc)
			}()
			continue
		}
		p, err := newPuller(spec)
		if err != nil {
			out.Log("ERROR", "cloud pull not started: "+err.Error(), map[string]string{"cloud.provider": spec.Provider}, time.Now())
			continue
		}
		st := &pullState{interval: max(time.Duration(spec.IntervalS)*time.Second, minPullInterval)}
		wg.Add(1)
		go func() { defer wg.Done(); st.loop(ctx, p, newEmitter(out, spec.Provider)) }()
	}
	wg.Wait()
	<-ctx.Done()
	return nil
}

// doJSON sends one request and decodes a JSON answer into out. Errors carry the status only.
func doJSON(ctx context.Context, c *http.Client, method, u string, hdr map[string]string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return errors.New("bad request url")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("request failed") // the url error text could hold a query string
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxPullBody))
	if err != nil {
		return errors.New("read failed")
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		n, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return &rateLimitErr{after: time.Duration(n) * time.Second}
	case resp.StatusCode >= 300:
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.New("malformed response")
	}
	return nil
}

// tokenCache holds an OAuth access token until shortly before it expires.
type tokenCache struct {
	mu  sync.Mutex
	tok string
	exp time.Time
}

func (t *tokenCache) get(now time.Time, fetch func() (string, time.Duration, error)) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tok != "" && now.Before(t.exp) {
		return t.tok, nil
	}
	tok, ttl, err := fetch()
	if err != nil {
		return "", err
	}
	t.tok, t.exp = tok, now.Add(ttl-time.Minute)
	return tok, nil
}

// tokenForm posts an OAuth form and returns the access token and its lifetime.
func tokenForm(ctx context.Context, c *http.Client, u string, form url.Values) (string, time.Duration, error) {
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	err := doJSON(ctx, c, http.MethodPost, u, map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		strings.NewReader(form.Encode()), &r)
	if err != nil {
		return "", 0, fmt.Errorf("token: %w", err)
	}
	if r.AccessToken == "" {
		return "", 0, errors.New("token: empty")
	}
	return r.AccessToken, time.Duration(max(r.ExpiresIn, 120)) * time.Second, nil
}

func httpClient() *http.Client { return netguard.Guarded("agent", 30*time.Second) }
