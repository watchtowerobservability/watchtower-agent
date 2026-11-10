package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// OktaConfig is the okta module config: the org URL and an API token (SSWS) with log read access.
type OktaConfig struct {
	Base
	URL   string `json:"url"`
	Token string `json:"token"`
}

func (c *OktaConfig) check() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || c.Token == "" {
		return errors.New("url (https org URL) and token are required (in the agent's own config file)")
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return nil
}

// Okta polls the System Log and counts events by type and outcome as `okta.system_log.events`
// (cumulative since the agent started).
// shortcut: one page of up to 1000 events per round, so a burst beyond that between polls is under-counted; shorten the interval.
func Okta(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &OktaConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	since := time.Now().UTC()
	counts := map[[2]string]float64{}
	return Loop(ctx, "okta", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		evs, err := oktaEvents(ctx, c, since)
		if err != nil {
			return err
		}
		for _, e := range evs {
			counts[[2]string{e.EventType, e.Outcome.Result}]++
			if e.Published.After(since) {
				since = e.Published.Add(time.Millisecond)
			}
		}
		for k, v := range counts {
			out.Sum("okta.system_log.events", "{events}", v, map[string]string{"event_type": k[0], "outcome": k[1]}, now)
		}
		return nil
	})
}

type oktaEvent struct {
	EventType string    `json:"eventType"`
	Published time.Time `json:"published"`
	Outcome   struct {
		Result string `json:"result"`
	} `json:"outcome"`
}

func oktaEvents(ctx context.Context, c *OktaConfig, since time.Time) ([]oktaEvent, error) {
	q := url.Values{"since": {since.Format(time.RFC3339Nano)}, "limit": {"1000"}, "sortOrder": {"ASCENDING"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/api/v1/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200)) // the URL may carry a token
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta: HTTP %d", resp.StatusCode)
	}
	var evs []oktaEvent
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&evs); err != nil {
		return nil, errors.New("okta: unexpected response")
	}
	return evs, nil
}
