package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// StatusPageConfig is the config of the vendor status integrations (githubstatus.com, Twilio,
// Stripe). URL is optional: each has a default public endpoint.
type StatusPageConfig struct {
	Base
	URL string `json:"url"`
}

func (c *StatusPageConfig) check() error {
	if c.URL == "" {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("url must be http or https")
	}
	return nil
}

type statusPage struct {
	url    string
	stripe bool // status.stripe.com/current instead of an Atlassian Statuspage summary
}

var statusPages = map[string]statusPage{
	"github_status": {url: "https://www.githubstatus.com/api/v2/summary.json"},
	"twilio":        {url: "https://status.twilio.com/api/v2/summary.json"},
	"stripe_status": {url: "https://status.stripe.com/current", stripe: true},
}

func runStatusPage(ctx context.Context, name string, sp statusPage, raw json.RawMessage, out sink.Sink) error {
	c := &StatusPageConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.URL == "" {
		c.URL = sp.url
	}
	return Loop(ctx, name, c.Base, 2*time.Minute, out, func(ctx context.Context, now time.Time) error {
		b, err := getBody(ctx, HTTPConfig{URL: c.URL}, c.URL)
		if err != nil {
			return err
		}
		return emitStatusPage(name, sp.stripe, b, out, now)
	})
}

var (
	indicatorLevel = map[string]float64{"none": 0, "minor": 1, "major": 2, "critical": 3}
	componentLevel = map[string]float64{"operational": 0, "degraded_performance": 1, "partial_outage": 2, "major_outage": 3, "under_maintenance": 4}
	stripeLevel    = map[string]float64{"up": 0, "degraded": 1, "down": 3}
)

// emitStatusPage turns a status document into `<name>.indicator`, `<name>.component.status` and
// `<name>.incidents.active` (Stripe: the indicator only).
func emitStatusPage(name string, stripe bool, body []byte, out sink.Sink, now time.Time) error {
	if stripe {
		var d struct {
			Largest string `json:"largestatus"`
		}
		err := json.Unmarshal(body, &d)
		lvl, ok := stripeLevel[strings.ToLower(d.Largest)]
		if err != nil || !ok {
			return fmt.Errorf("%s: unexpected status document", name)
		}
		out.Gauge(name+".indicator", "1", lvl, nil, now)
		return nil
	}
	var d struct {
		Status     struct{ Indicator string } `json:"status"`
		Components []struct{ Name, Status string }
		Incidents  []struct{ Status string }
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return fmt.Errorf("%s: not a status summary", name)
	}
	lvl, ok := indicatorLevel[d.Status.Indicator]
	if !ok {
		return fmt.Errorf("%s: unknown indicator %q", name, d.Status.Indicator)
	}
	out.Gauge(name+".indicator", "1", lvl, nil, now)
	for i, c := range d.Components {
		if i >= 200 {
			break
		}
		if v, ok := componentLevel[c.Status]; ok {
			out.Gauge(name+".component.status", "1", v, map[string]string{"component": c.Name}, now)
		}
	}
	active := 0
	for _, in := range d.Incidents {
		if in.Status != "resolved" && in.Status != "postmortem" {
			active++
		}
	}
	out.Gauge(name+".incidents.active", "{incidents}", float64(active), nil, now)
	return nil
}
