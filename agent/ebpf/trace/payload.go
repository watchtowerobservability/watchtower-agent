package trace

// Payload capture for observed HTTP/1 server spans (APM-016), gated on the same capture rules
// the SDKs fetch from the edge, delivered in the module config as `payload_rules` (local or
// remote config). Only the bytes the probe already holds (the 512 B head of each direction) are
// used, capped at the rule's body_bytes, text-like content types only, and masked by the
// gateway's default detectors (internal/redact) before they leave the host.
// shortcut: rules come from the module config, not a per-service poll of /v1/capture-rules; add
// the poll when operators want edits to reach agents without a config push.

import (
	"bytes"
	"encoding/json"
	"regexp"

	"github.com/watchtowerobservability/watchtower-agent/internal/redact"
)

// PayloadRule selects server traffic by service and path glob (`*` matches any run). It has the
// stored rule's shape so rules can be copied as they are; headers and GraphQL are SDK-side only.
type PayloadRule struct {
	Service         string   `json:"service"`
	Route           string   `json:"route"`
	BodyBytes       int      `json:"body_bytes"`
	RequestHeaders  []string `json:"request_headers"`
	ResponseHeaders []string `json:"response_headers"`
	GraphQLQuery    bool     `json:"graphql_query"`
}

// Payload applies the rules; a nil Payload records nothing.
type Payload struct {
	rules []PayloadRule
	red   *redact.Redactor
}

var textBody = regexp.MustCompile(`(?i)content-type:\s*[^\r\n]*(?:json|text/|xml|x-www-form-urlencoded|graphql)`)

// NewPayload returns nil when no rule asks for body bytes.
func NewPayload(rules []PayloadRule) *Payload {
	var keep []PayloadRule
	for _, r := range rules {
		if r.BodyBytes > 0 {
			keep = append(keep, r)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return &Payload{rules: keep, red: redact.New(redact.Standard, nil, nil)}
}

func (p *Payload) rule(svc, path string) (PayloadRule, bool) {
	for _, r := range p.rules {
		if (r.Service == "" || redact.Glob(r.Service, svc)) && (r.Route == "" || redact.Glob(r.Route, path)) {
			return r, true
		}
	}
	return PayloadRule{}, false
}

// excerpt masks then caps; JSON that survived the head intact is masked by key too.
func (p *Payload) excerpt(raw []byte, n int) string {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok || len(body) == 0 || !textBody.Match(head) {
		return ""
	}
	if json.Valid(body) {
		body = p.red.JSON(body)
	}
	s := p.red.Text(string(body))
	if len(s) > n {
		s = s[:n]
	}
	return string(bytes.ToValidUTF8([]byte(s), nil))
}

// apply sets http.request.body / http.response.body on a server span the rules select.
func (p *Payload) apply(sp *Span, svc string) {
	if p == nil || sp.Client || (sp.reqHead == nil && sp.resHead == nil) {
		return
	}
	path, _ := sp.Attrs["url.path"].(string)
	r, ok := p.rule(svc, path)
	if !ok {
		return
	}
	if s := p.excerpt(sp.reqHead, r.BodyBytes); s != "" {
		sp.Attrs["http.request.body"] = s
	}
	if s := p.excerpt(sp.resHead, r.BodyBytes); s != "" {
		sp.Attrs["http.response.body"] = s
	}
}
