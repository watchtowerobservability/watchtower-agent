package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// HostInfo is what the agent tells the server about itself. The project and environment are not
// part of it: the server takes them from the credential.
type HostInfo struct {
	Hostname string            `json:"hostname"`
	Version  string            `json:"version"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Labels   map[string]string `json:"labels"`
}

// Version is set at build time (-ldflags "-X main.Version=...").
var Version = "dev"

func hostInfo(labels map[string]string) HostInfo {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	if labels == nil {
		labels = map[string]string{}
	}
	return HostInfo{Hostname: h, Version: Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Labels: labels}
}

// Fleet talks to wt-edge.
type Fleet struct {
	Base  string
	Token string
	// HTTP needs a timeout above the server's 30 s long poll.
	HTTP *http.Client
}

// NewFleet builds a client with a 45 s timeout and no redirects (a redirect would carry the
// bearer token to another host).
func NewFleet(base, token string) *Fleet {
	return &Fleet{Base: base, Token: token, HTTP: netguard.GuardedNoRedirect("agent", 45*time.Second)}
}

// ErrNotFound is a 404: the server does not know this agent id (for this credential's project).
var ErrNotFound = errors.New("agent not found")

func (f *Fleet) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, f.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("Content-Type", "application/json")
	return f.HTTP.Do(req)
}

// Register announces the agent. id is the stored id ("" on first start).
func (f *Fleet) Register(ctx context.Context, id string, info HostInfo) (string, error) {
	body := struct {
		AgentID string `json:"agent_id,omitempty"`
		HostInfo
	}{id, info}
	b, _ := json.Marshal(body)
	resp, err := f.do(ctx, http.MethodPost, "/v1/agents/register", b)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusNotFound && id != "" {
		return "", ErrNotFound // the server forgot this id; EnsureRegistered registers afresh
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return "", fmt.Errorf("fleet registration failed at %s (status %d, no such route or the key lacks agent:fleet): set fleet_endpoint to your wt-edge URL", f.Base, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("register: status %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AgentID == "" {
		return "", errors.New("register: bad response")
	}
	return out.AgentID, nil
}

// Poll long-polls for a config different from version have. It returns nil when nothing changed
// (304) or no config applies (204).
func (f *Fleet) Poll(ctx context.Context, id string, have int) (*Served, error) {
	q := url.Values{"version": {strconv.Itoa(have)}}
	resp, err := f.do(ctx, http.MethodGet, "/v1/agents/"+url.PathEscape(id)+"/config?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified, http.StatusNoContent:
		return nil, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("config: status %d", resp.StatusCode)
	}
	var s Served
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Follow polls until ctx ends and calls apply with each verified config. A config that fails
// verification is dropped (the running one stays) and reported through onErr. Errors back off up
// to a minute. It returns ErrNotFound when the server forgot the agent, nil when ctx ends.
func (f *Fleet) Follow(ctx context.Context, id string, labels map[string]string, ap *Applied, apply func(version int, rc *RemoteConfig), onErr func(error)) error {
	have, wait := 0, time.Second
	for ctx.Err() == nil {
		s, err := f.Poll(ctx, id, have)
		if err == nil && s != nil {
			var rc *RemoteConfig
			if rc, err = s.Verify(f.Token, id, labels); err == nil {
				if err = ap.Check(s); err == nil {
					apply(s.Version, rc)
					ap.Record(s)
					have = s.Version
				}
			}
		}
		if errors.Is(err, ErrNotFound) {
			return err // the caller registers again
		}
		if err != nil {
			if ctx.Err() == nil {
				onErr(err)
				sleep(ctx, wait)
				wait = min(wait*2, time.Minute)
			}
			continue
		}
		wait = time.Second
		if s == nil {
			sleep(ctx, time.Second) // the server already waited; this only guards a hot loop
		}
	}
	return nil
}

// swapBinary replaces the executable at exe with the staged file after re-checking the staged
// bytes against want (the SHA-256 the release key signed), so a swap can never apply bytes whose
// hash was not verified. The old binary stays as exe+".old" (works on Windows, where a running
// exe can be renamed but not overwritten). shortcut: no automatic rollback if the new binary
// fails to start, an operator restores .old; add a start-health probe when the fleet can pin it.
func swapBinary(exe, staged string, want []byte) error {
	data, err := os.ReadFile(staged)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], want) {
		return errors.New("staged binary does not match the signed hash; not replacing")
	}
	next := exe + ".new"
	if err := os.WriteFile(next, data, 0o755); err != nil { // #nosec G306 -- an executable
		return err
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		_ = os.Remove(next)
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		_ = os.Rename(old, exe) // put the working binary back
		_ = os.Remove(next)
		return err
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
