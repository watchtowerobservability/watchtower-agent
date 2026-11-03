package main

// Log and object sinks and outbound auth for `forward:` targets (CFT-A10, A17). splunkhec, datadog,
// googlecloud and syslog take log batches (other signals have no equivalent there and are skipped);
// s3 stores any signal's OTLP protobuf as one object per batch; loadbalancing sends OTLP to one of
// several endpoints, keeping every span of a trace on the same one.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// ForwardOAuth2 is the client credentials grant.
type ForwardOAuth2 struct {
	TokenURL     string   `yaml:"token_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
}

// ForwardSigV4 signs requests with the AWS default credential chain.
type ForwardSigV4 struct {
	Region  string `yaml:"region"`
	Service string `yaml:"service"`
	// RoleARN, when set, is assumed through STS on top of the default chain (ExternalID optional).
	RoleARN    string `yaml:"role_arn"`
	ExternalID string `yaml:"external_id"`
}

type logLine struct {
	ts       time.Time
	service  string
	severity string
	body     string
	attrs    map[string]string
}

func attrValue(a *common.AnyValue) string {
	switch v := a.GetValue().(type) {
	case nil:
		return ""
	case *common.AnyValue_StringValue:
		return v.StringValue
	default:
		b, _ := json.Marshal(a.GetValue())
		return string(b)
	}
}

func logLines(body []byte) ([]logLine, error) {
	var req collectorlogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	var out []logLine
	for _, rl := range req.GetResourceLogs() {
		service := ""
		for _, a := range rl.GetResource().GetAttributes() {
			if a.GetKey() == "service.name" {
				service = attrValue(a.GetValue())
			}
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, r := range sl.GetLogRecords() {
				attrs := map[string]string{}
				for _, a := range r.GetAttributes() {
					attrs[a.GetKey()] = attrValue(a.GetValue())
				}
				out = append(out, logLine{time.Unix(0, int64(r.GetTimeUnixNano())), service, r.GetSeverityText(), attrValue(r.GetBody()), attrs}) //nolint:gosec // wall clock
			}
		}
	}
	return out, nil
}

// initSink prepares the kinds forward.go does not handle itself.
func (f *forwarder) initSink(ctx context.Context) error {
	t := f.t
	hc, err := forwardClient(ctx, t)
	if err != nil {
		return err
	}
	f.hc = hc
	if err := f.applyHeaders(ctx); err != nil {
		return err
	}
	if err := f.initAuth(); err != nil {
		return err
	}
	switch t.Kind {
	case "splunkhec", "datadog":
		tok, err := resolveRef(ctx, t.Token)
		if err != nil {
			return err
		}
		if tok == "" {
			return fmt.Errorf("forward: %s needs token", t.Kind)
		}
		if t.Kind == "splunkhec" {
			if t.Endpoint == "" {
				return errors.New("forward: splunkhec needs endpoint")
			}
			f.hdr.Set("Authorization", "Splunk "+tok)
		} else {
			f.hdr.Set("DD-API-KEY", tok)
		}
	case "googlecloud":
		if t.Project == "" {
			return errors.New("forward: googlecloud needs project")
		}
		f.google = true
	case "syslog":
		if _, _, err := net.SplitHostPort(t.Endpoint); err != nil {
			return errors.New("forward: syslog endpoint must be host:port")
		}
	case "s3":
		if t.Bucket == "" || t.SigV4 == nil {
			return errors.New("forward: s3 needs bucket and sigv4")
		}
	case "loadbalancing":
		if len(t.Endpoints) == 0 {
			return errors.New("forward: loadbalancing needs endpoints")
		}
	default:
		return fmt.Errorf("forward: unknown kind %q", t.Kind)
	}
	return nil
}

func (f *forwarder) applyHeaders(ctx context.Context) error {
	for k, v := range f.t.Headers {
		rv, err := resolveRef(ctx, v)
		if err != nil {
			return err
		}
		f.hdr.Set(k, rv)
	}
	return nil
}

func (f *forwarder) initAuth() error {
	if o := f.t.OAuth2; o != nil && (o.TokenURL == "" || o.ClientID == "") {
		return errors.New("forward: oauth2 needs token_url and client_id")
	}
	if s := f.t.SigV4; s != nil && (s.Region == "" || s.Service == "") {
		return errors.New("forward: sigv4 needs region and service")
	}
	return nil
}

type cachedToken struct {
	mu  sync.Mutex
	tok string
	exp time.Time
}

func (f *forwarder) token(ctx context.Context, fetch func(context.Context) (string, time.Duration, error)) (string, error) {
	f.bearer.mu.Lock()
	defer f.bearer.mu.Unlock()
	if f.bearer.tok != "" && time.Now().Before(f.bearer.exp) {
		return f.bearer.tok, nil
	}
	tok, ttl, err := fetch(ctx)
	if err != nil {
		return "", err
	}
	f.bearer.tok, f.bearer.exp = tok, time.Now().Add(ttl-30*time.Second)
	return tok, nil
}

func tokenResponse(resp *http.Response) (string, time.Duration, error) {
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		return "", 0, fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	if out.ExpiresIn <= 60 {
		out.ExpiresIn = 300
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (f *forwarder) oauth2Token(ctx context.Context) (string, time.Duration, error) {
	o := f.t.OAuth2
	secret, err := resolveRef(ctx, o.ClientSecret)
	if err != nil {
		return "", 0, err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {o.ClientID}, "client_secret": {secret}}
	if len(o.Scopes) > 0 {
		form.Set("scope", strings.Join(o.Scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("bad token_url")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", 0, errors.New("token endpoint unreachable")
	}
	return tokenResponse(resp)
}

// googleClient is unguarded on purpose: the metadata server is link-local, which netguard refuses.
var googleClient = &http.Client{Timeout: 5 * time.Second}

func googleToken(ctx context.Context) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", http.NoBody)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := googleClient.Do(req)
	if err != nil {
		return "", 0, errors.New("gce metadata token unavailable")
	}
	return tokenResponse(resp)
}

// authorize adds the configured outbound auth to one request.
func (f *forwarder) authorize(ctx context.Context, req *http.Request, body []byte) error {
	switch {
	case f.t.OAuth2 != nil:
		tok, err := f.token(ctx, f.oauth2Token)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case f.google:
		tok, err := f.token(ctx, googleToken)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case f.t.SigV4 != nil:
		creds, err := f.aws.get(ctx, f.t.SigV4)
		if err != nil {
			return errors.New("aws credentials unavailable")
		}
		sum := sha256.Sum256(body)
		payload := hex.EncodeToString(sum[:])
		req.Header.Set("X-Amz-Content-Sha256", payload)
		if v4.NewSigner().SignHTTP(ctx, creds, req, payload, f.t.SigV4.Service, f.t.SigV4.Region, time.Now()) != nil {
			return errors.New("sigv4 signing failed")
		}
	}
	return nil
}

func (f *forwarder) do(ctx context.Context, method, u, contentType string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad endpoint")
	}
	req.Header = f.hdr.Clone()
	req.Header.Set("Content-Type", contentType)
	if err := f.authorize(ctx, req, body); err != nil {
		return err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return errors.New("unreachable") // url.Error would embed the endpoint
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (f *forwarder) sendSink(ctx context.Context, it fwdItem) error {
	switch f.t.Kind {
	case "s3":
		return f.sendS3(ctx, it)
	case "loadbalancing":
		return f.sendBalanced(ctx, it)
	}
	if it.signal != "logs" {
		return nil
	}
	lines, err := logLines(it.body)
	if err != nil || len(lines) == 0 {
		return err
	}
	base := strings.TrimSuffix(f.t.Endpoint, "/")
	switch f.t.Kind {
	case "splunkhec":
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, l := range lines {
			_ = enc.Encode(map[string]any{"time": float64(l.ts.UnixMilli()) / 1000, "source": l.service, "event": l.body, "fields": l.attrs})
		}
		return f.do(ctx, http.MethodPost, base+"/services/collector/event", "application/json", b.Bytes())
	case "datadog":
		if base == "" {
			base = "https://http-intake.logs.datadoghq.com"
		}
		rows := make([]map[string]any, len(lines))
		for i, l := range lines {
			rows[i] = map[string]any{"message": l.body, "service": l.service, "status": strings.ToLower(l.severity), "ddsource": "watchtower", "attributes": l.attrs}
		}
		b, _ := json.Marshal(rows)
		return f.do(ctx, http.MethodPost, base+"/api/v2/logs", "application/json", b)
	case "googlecloud":
		if base == "" {
			base = "https://logging.googleapis.com"
		}
		rows := make([]map[string]any, len(lines))
		for i, l := range lines {
			rows[i] = map[string]any{"textPayload": l.body, "severity": cloudSeverity(l.severity), "timestamp": l.ts.UTC().Format(time.RFC3339Nano), "labels": l.attrs}
		}
		b, _ := json.Marshal(map[string]any{"logName": "projects/" + f.t.Project + "/logs/watchtower", "resource": map[string]string{"type": "global"}, "entries": rows})
		return f.do(ctx, http.MethodPost, base+"/v2/entries:write", "application/json", b)
	}
	return f.sendSyslog(ctx, lines)
}

func cloudSeverity(s string) string {
	switch u := strings.ToUpper(s); {
	case strings.HasPrefix(u, "WARN"):
		return "WARNING"
	case strings.HasPrefix(u, "ERR"), strings.HasPrefix(u, "FATAL"):
		return "ERROR"
	case strings.HasPrefix(u, "DEBUG"), strings.HasPrefix(u, "TRACE"):
		return "DEBUG"
	case u == "":
		return "DEFAULT"
	}
	return "INFO"
}

func syslogPriority(s string) int {
	const local0 = 16 * 8
	switch cloudSeverity(s) {
	case "ERROR":
		return local0 + 3
	case "WARNING":
		return local0 + 4
	case "DEBUG":
		return local0 + 7
	}
	return local0 + 6
}

// formatSyslog is one RFC 5424 message with RFC 6587 octet counting.
func formatSyslog(l logLine) string {
	app := strings.ReplaceAll(l.service, " ", "_")
	if app == "" {
		app = "-"
	}
	m := fmt.Sprintf("<%d>1 %s - %s - - - %s", syslogPriority(l.severity), l.ts.UTC().Format(time.RFC3339Nano), app, l.body)
	return fmt.Sprintf("%d %s", len(m), m)
}

func (f *forwarder) sendSyslog(ctx context.Context, lines []logLine) error {
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", f.t.Endpoint)
	if err != nil {
		return errors.New("unreachable")
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var w io.Writer = conn
	if f.t.TLS {
		host, _, _ := net.SplitHostPort(f.t.Endpoint)
		w = tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(formatSyslog(l))
	}
	_, err = io.WriteString(w, b.String())
	return err
}

func (f *forwarder) sendS3(ctx context.Context, it fwdItem) error {
	base := strings.TrimSuffix(f.t.Endpoint, "/")
	if base == "" {
		base = "https://" + f.t.Bucket + ".s3." + f.t.SigV4.Region + ".amazonaws.com"
	}
	var id [8]byte
	_, _ = rand.Read(id[:])
	now := time.Now().UTC()
	key := fmt.Sprintf("%s/dt=%s/%d-%s.otlp.pb", it.signal, now.Format("2006-01-02/15"), now.UnixNano(), hex.EncodeToString(id[:]))
	return f.do(ctx, http.MethodPut, base+"/"+key, "application/x-protobuf", it.body)
}

func (f *forwarder) sendBalanced(ctx context.Context, it fwdItem) error {
	pick := func(k []byte) string {
		h := fnv.New32a()
		_, _ = h.Write(k)
		return strings.TrimSuffix(f.t.Endpoints[int(h.Sum32())%len(f.t.Endpoints)], "/") + "/v1/" + it.signal //nolint:gosec // a modulus of a small list
	}
	const ct = "application/x-protobuf"
	if it.signal != "traces" {
		f.next++ // shortcut: metrics and logs go round-robin, not by series or stream; add keys if a backend needs them
		return f.do(ctx, http.MethodPost, pick([]byte{byte(f.next)}), ct, it.body)
	}
	parts, err := splitByTrace(it.body, len(f.t.Endpoints))
	if err != nil {
		return err
	}
	var first error
	for i, p := range parts {
		if err := f.do(ctx, http.MethodPost, strings.TrimSuffix(f.t.Endpoints[i], "/")+"/v1/traces", ct, p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// splitByTrace regroups a batch per endpoint so one trace's spans always share an endpoint.
func splitByTrace(body []byte, n int) (map[int][]byte, error) {
	var req collectortrace.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	out := make(map[int]*collectortrace.ExportTraceServiceRequest, n)
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			groups := map[int][]*tracepb.Span{}
			for _, sp := range ss.GetSpans() {
				h := fnv.New32a()
				_, _ = h.Write(sp.GetTraceId())
				i := int(h.Sum32()) % n //nolint:gosec // a modulus of a small list
				groups[i] = append(groups[i], sp)
			}
			for i, spans := range groups {
				if out[i] == nil {
					out[i] = &collectortrace.ExportTraceServiceRequest{}
				}
				out[i].ResourceSpans = append(out[i].ResourceSpans, &tracepb.ResourceSpans{Resource: rs.GetResource(), SchemaUrl: rs.GetSchemaUrl(),
					ScopeSpans: []*tracepb.ScopeSpans{{Scope: ss.GetScope(), Spans: spans, SchemaUrl: ss.GetSchemaUrl()}}})
			}
		}
	}
	bodies := make(map[int][]byte, len(out))
	for i, r := range out {
		b, err := proto.Marshal(r)
		if err != nil {
			return nil, err
		}
		bodies[i] = b
	}
	return bodies, nil
}
