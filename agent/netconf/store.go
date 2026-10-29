package netconf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Config is the module's config. Devices live in the API (`/netconf-devices`); credentials
// exist only in the agent's file, selected by each device's credentials_ref. Remote config may
// only set Enabled and Interval.
type Config struct {
	Enabled     *bool            `json:"enabled"`
	Interval    string           `json:"interval"` // how often due devices are looked for, default 60s
	APIURL      string           `json:"api_url"`
	APIToken    string           `json:"api_token"`
	ProjectID   string           `json:"project_id"`
	Credentials map[string]Creds `json:"credentials"`
}

// HTTPStore is the Store backed by the Watchtower API.
type HTTPStore struct {
	Base, Project, Token string
	Client               *http.Client
}

func (h *HTTPStore) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := strings.TrimRight(h.Base, "/") + "/v1/projects/" + url.PathEscape(h.Project) + "/netconf-devices" + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := h.Client
	if c == nil {
		c = netguard.Guarded("agent", 30*time.Second)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("netconf api %s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// Devices pages through the project's devices.
func (h *HTTPStore) Devices(ctx context.Context) ([]Device, error) {
	var all []Device
	cursor := ""
	for {
		var page struct {
			Data       []Device `json:"data"`
			NextCursor *string  `json:"next_cursor"`
		}
		if err := h.do(ctx, http.MethodGet, "?limit=200&cursor="+url.QueryEscape(cursor), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = *page.NextCursor
	}
}

// Upload sends a config; the server stores it only when its hash differs.
func (h *HTTPStore) Upload(ctx context.Context, id, body, source string) (bool, error) {
	var res struct {
		Changed bool `json:"changed"`
	}
	err := h.do(ctx, http.MethodPost, "/"+id+"/configs", map[string]string{"body": body, "source": source}, &res)
	return res.Changed, err
}

// PinHostKey stores the fingerprint seen on first use (the server ignores it once one is pinned).
func (h *HTTPStore) PinHostKey(ctx context.Context, id, fp string) error {
	return h.do(ctx, http.MethodPatch, "/"+id, map[string]string{"host_key": fp}, nil)
}

// Version fetches a stored config body.
func (h *HTTPStore) Version(ctx context.Context, id string, v int) (string, error) {
	var res struct {
		Body string `json:"body"`
	}
	err := h.do(ctx, http.MethodGet, fmt.Sprintf("/%s/configs/%d", id, v), nil, &res)
	return res.Body, err
}

// Run is the agent module. Each tick it lists devices and, for every one that is due, executes a
// pending rollback request or collects its config.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("netconf config: %w", err)
		}
	}
	if c.Enabled != nil && !*c.Enabled || c.APIURL == "" || c.ProjectID == "" {
		<-ctx.Done()
		return nil
	}
	st := &HTTPStore{Base: c.APIURL, Project: c.ProjectID, Token: c.APIToken}
	col := &Collector{Store: st, Creds: c.Credentials}
	every := host.Duration(c.Interval, 60*time.Second, 10*time.Second)
	lastRun := map[string]time.Time{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		tick(ctx, col, st, lastRun, out)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func tick(ctx context.Context, col *Collector, st Store, lastRun map[string]time.Time, out sink.Sink) {
	devs, err := st.Devices(ctx)
	if err != nil {
		slog.Warn("netconf: listing devices", "err", err)
		return
	}
	for _, d := range devs {
		attrs := map[string]string{"network.device.host": d.Host}
		now := time.Now()
		key, wait := d.ID, time.Duration(max(d.IntervalS, 300))*time.Second
		if d.Rollback != nil {
			key, wait = d.ID+"/rollback", 5*time.Minute // a failing request is retried, not hammered
		}
		if now.Sub(lastRun[key]) < wait {
			continue
		}
		lastRun[key] = now
		if d.Rollback != nil {
			if err := doRollback(ctx, col, st, d); err != nil {
				out.Log("ERROR", "network config rollback failed: "+err.Error(), attrs, now)
			}
			continue
		}
		changed, err := col.Collect(ctx, d)
		switch {
		case IsHostKeyChanged(err):
			out.Log("ERROR", "ssh host key changed, not connecting: "+d.Host, attrs, now)
		case err != nil:
			out.Log("WARN", "network config collect failed: "+err.Error(), attrs, now)
		case changed:
			out.Log("INFO", "network config changed", attrs, now)
			out.Gauge("network.config.changed", "1", 1, attrs, now)
		}
	}
}

// doRollback restores the requested version, then uploads the result as a `manual` version so
// the server clears the request.
func doRollback(ctx context.Context, col *Collector, st Store, d Device) error {
	body, err := st.Version(ctx, d.ID, *d.Rollback)
	if err != nil {
		return err
	}
	// the startup section is a second datastore dump, not part of running
	body, _, _ = strings.Cut(body, "\n<!-- startup -->\n")
	if err := col.Rollback(ctx, d, body, RollbackOptions{}); err != nil {
		return err
	}
	now, _, err := col.Fetch(ctx, d)
	if err != nil {
		return err
	}
	_, err = st.Upload(ctx, d.ID, now, "manual")
	return err
}
