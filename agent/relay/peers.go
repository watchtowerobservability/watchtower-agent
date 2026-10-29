package relay

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/internal/cluster"
)

// PeerHeader marks a batch already routed by another relay of the group: the receiver
// processes it locally and never re-shards (no forwarding loops).
const PeerHeader = "X-Wt-Relay-Peer"

// Peers shards spans by trace id over the relays of one peer group with the same rendezvous
// hashing the platform uses for shuffle sharding (cluster.Subset), so all spans of a trace land
// on one relay. Nodes are relay base URLs; the local relay's own URL (Self) is always a node.
type Peers struct {
	Self   string
	Secret string // shared by the group; sent in PeerHeader
	File   string // optional: JSON array or one URL per line, re-read by Refresh (fleet config writes it)
	HTTP   *http.Client

	mu    sync.RWMutex
	nodes []string
}

// NewPeers builds a group from a static list.
func NewPeers(self, secret string, peers []string) *Peers {
	p := &Peers{Self: self, Secret: secret}
	p.Set(peers)
	return p
}

// Set replaces the peer list (Self is added, duplicates and blanks removed).
func (p *Peers) Set(peers []string) {
	set := map[string]bool{}
	if p.Self != "" {
		set[p.Self] = true
	}
	for _, n := range peers {
		if n = strings.TrimRight(strings.TrimSpace(n), "/"); n != "" {
			set[n] = true
		}
	}
	nodes := make([]string, 0, len(set))
	for n := range set {
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	p.mu.Lock()
	p.nodes = nodes
	p.mu.Unlock()
}

// Refresh re-reads File when set. A bad file keeps the previous list.
func (p *Peers) Refresh() error {
	if p.File == "" {
		return nil
	}
	b, err := os.ReadFile(p.File)
	if err != nil {
		return err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		list = strings.Fields(string(b))
	}
	p.Set(list)
	return nil
}

// Active reports whether there is anyone to share traces with.
func (p *Peers) Active() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.nodes) > 1
}

// Owner is the relay responsible for the trace id; Self when the id is unusable or alone.
func (p *Peers) Owner(trace []byte) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.nodes) < 2 || usableTrace(trace) == nil {
		return p.Self
	}
	var id [16]byte
	copy(id[:], trace)
	return cluster.Subset(id, p.nodes, 1)[0]
}

// Authentic reports whether header carries the group secret.
func (p *Peers) Authentic(header string) bool {
	return p.Secret != "" && subtle.ConstantTimeCompare([]byte(header), []byte(p.Secret)) == 1
}

// SplitTraces groups the spans of req by owner. Resources and scopes are copied per group.
func SplitTraces(req *coltrace.ExportTraceServiceRequest, owner func(trace []byte) string) map[string]*coltrace.ExportTraceServiceRequest {
	out := map[string]*coltrace.ExportTraceServiceRequest{}
	for _, rs := range req.GetResourceSpans() {
		perOwner := map[string]*tracepb.ResourceSpans{}
		for _, ss := range rs.GetScopeSpans() {
			scopes := map[string]*tracepb.ScopeSpans{}
			for _, sp := range ss.GetSpans() {
				o := owner(sp.TraceId)
				sc := scopes[o]
				if sc == nil {
					sc = &tracepb.ScopeSpans{Scope: ss.Scope, SchemaUrl: ss.SchemaUrl}
					scopes[o] = sc
					r := perOwner[o]
					if r == nil {
						r = &tracepb.ResourceSpans{Resource: rs.Resource, SchemaUrl: rs.SchemaUrl}
						perOwner[o] = r
					}
					r.ScopeSpans = append(r.ScopeSpans, sc)
				}
				sc.Spans = append(sc.Spans, sp)
			}
		}
		for o, r := range perOwner {
			g := out[o]
			if g == nil {
				g = &coltrace.ExportTraceServiceRequest{}
				out[o] = g
			}
			g.ResourceSpans = append(g.ResourceSpans, r)
		}
	}
	return out
}

// Send posts a trace batch to peer. The peer queues it for the gateway; an error means the
// caller keeps the batch itself.
func (p *Peers) Send(ctx context.Context, peer string, req *coltrace.ExportTraceServiceRequest) error {
	b, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, peer+"/v1/traces", bytes.NewReader(b))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/x-protobuf")
	hr.Header.Set(PeerHeader, p.Secret)
	resp, err := p.HTTP.Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("peer %s: status %d", peer, resp.StatusCode)
	}
	return nil
}
