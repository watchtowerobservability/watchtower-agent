package relay

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var (
	siteRe   = regexp.MustCompile(`^[a-z0-9.-]+$`)
	prefixRe = regexp.MustCompile(`^[A-Za-z0-9._/=-]*$`)
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// newSender validates c and builds its sender. client and secret may be empty (config check only).
func newSender(c DestConfig, client *http.Client, secret string) (sender, error) {
	h := httpDest{c: client, secret: secret}
	switch c.Type {
	case "s3":
		if c.Bucket == "" || !bucketRe.MatchString(c.Bucket) || c.Region == "" {
			return nil, errors.New("s3 needs bucket and region")
		}
		ak := or(c.AccessKey, os.Getenv("AWS_ACCESS_KEY_ID"))
		if client != nil && (ak == "" || secret == "") {
			return nil, errors.New("s3 needs static credentials: access_key and secret_file/secret_env, or env AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
		tok, err := secretOr(c.SessionTokenEnv, c.SessionTokenFile, "AWS_SESSION_TOKEN")
		if err != nil {
			return nil, err
		}
		c.AccessKey = ak
		if !prefixRe.MatchString(c.Prefix) || strings.Contains(c.Prefix, "..") {
			return nil, errors.New("s3 prefix may only hold letters, digits and ._/=-")
		}
		return &s3Dest{httpDest: h, cfg: c, token: tok, now: time.Now}, nil
	case "splunk_hec":
		if c.URL == "" || (c.SecretFile == "" && c.SecretEnv == "") {
			return nil, errors.New("splunk_hec needs url and secret_file or secret_env (the HEC token)")
		}
		return &splunkDest{httpDest: h, cfg: c}, nil
	case "elasticsearch":
		if c.URL == "" {
			return nil, errors.New("elasticsearch needs url")
		}
		return &esDest{httpDest: h, cfg: c, now: time.Now}, nil
	case "datadog":
		if c.Site != "" && !siteRe.MatchString(c.Site) {
			return nil, errors.New("datadog site must be a host name such as datadoghq.eu")
		}
		if c.SecretFile == "" && c.SecretEnv == "" {
			return nil, errors.New("datadog needs secret_file or secret_env (the API key)")
		}
		return &datadogDest{httpDest: h, cfg: c}, nil
	}
	return nil, fmt.Errorf("unknown type %q (s3, splunk_hec, elasticsearch or datadog)", c.Type)
}

type httpDest struct {
	c      *http.Client
	secret string
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// do sends req and classifies the outcome: 2xx nil; 429, 5xx, 408, 401 and 403 retried (a rotated
// credential must not lose data); other statuses are a permError. The body is returned (capped).
func (h httpDest) do(req *http.Request) ([]byte, error) {
	resp, err := h.c.Do(req)
	if err != nil {
		return nil, &retryError{err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch c := resp.StatusCode; {
	case c < 300:
		return body, nil
	case c == 429 || c >= 500 || c == 408 || c == 401 || c == 403:
		return nil, &retryError{after: parseRetryAfter(resp.Header.Get("Retry-After")), err: fmt.Errorf("%s: status %d", req.URL.Host, c)}
	default:
		return nil, &permError{fmt.Errorf("%s: status %d: %.200s", req.URL.Host, c, body)}
	}
}

func (h httpDest) post(ctx context.Context, url, ctype string, body []byte, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(gz(body)))
	if err != nil {
		return nil, &permError{err}
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Content-Encoding", "gzip")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return h.do(req)
}

func ndjson(parts ...any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, p := range parts {
		_ = enc.Encode(p)
	}
	return b.Bytes()
}

// --- Splunk HEC ---------------------------------------------------------------------------

type splunkDest struct {
	httpDest
	cfg DestConfig
}

func (s *splunkDest) send(ctx context.Context, evs []Event) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range evs {
		m := map[string]any{"time": float64(e.Time.UnixMilli()) / 1000, "event": e, "host": e.Attrs["host.name"]}
		for k, v := range map[string]string{"index": s.cfg.Index, "source": s.cfg.Source, "sourcetype": s.cfg.Sourcetype} {
			if v != "" {
				m[k] = v
			}
		}
		_ = enc.Encode(m)
	}
	_, err := s.post(ctx, strings.TrimRight(s.cfg.URL, "/")+"/services/collector/event", "application/json", b.Bytes(),
		map[string]string{"Authorization": "Splunk " + s.secret})
	return err
}

// --- Elasticsearch / OpenSearch -----------------------------------------------------------

type esDest struct {
	httpDest
	cfg DestConfig
	now func() time.Time
}

var strftime = strings.NewReplacer("%Y", "2006", "%m", "01", "%d", "02")

func (s *esDest) send(ctx context.Context, evs []Event) error {
	pat := s.cfg.Index
	if pat == "" {
		pat = "watchtower-%Y.%m.%d"
	}
	var parts []any
	for _, e := range evs {
		b, _ := json.Marshal(e)
		sum := sha256.Sum256(b)
		// A fixed _id makes a repeated delivery overwrite instead of duplicate.
		parts = append(parts, map[string]any{"index": map[string]string{"_index": e.Time.UTC().Format(strftime.Replace(pat)), "_id": hex.EncodeToString(sum[:16])}}, e)
	}
	hdr := map[string]string{}
	switch {
	case s.cfg.Username != "":
		hdr["Authorization"] = "Basic " + basic(s.cfg.Username, s.secret)
	case s.secret != "":
		hdr["Authorization"] = "ApiKey " + s.secret
	}
	body, err := s.post(ctx, strings.TrimRight(s.cfg.URL, "/")+"/_bulk", "application/x-ndjson", ndjson(parts...), hdr)
	if err != nil {
		return err
	}
	var r struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if !bytes.Contains(body, []byte(`"errors":true`)) || json.Unmarshal(body, &r) != nil {
		return nil
	}
	retry, bad := 0, 0
	for _, it := range r.Items {
		for _, v := range it {
			switch {
			case v.Status < 300:
			case v.Status == 429 || v.Status >= 500:
				retry++
			default:
				bad++
			}
		}
	}
	if retry > 0 { // the ids make resending the accepted documents harmless
		return &retryError{err: fmt.Errorf("elasticsearch bulk: %d items failed with 429 or 5xx", retry)}
	}
	if bad > 0 {
		return &permError{fmt.Errorf("elasticsearch bulk: %d items rejected", bad)}
	}
	return nil
}

func basic(u, p string) string { return base64.StdEncoding.EncodeToString([]byte(u + ":" + p)) }

// --- Datadog ------------------------------------------------------------------------------

type datadogDest struct {
	httpDest
	cfg DestConfig
}

func tags(a map[string]string) []string {
	out := make([]string, 0, len(a))
	for k, v := range a {
		out = append(out, k+":"+v)
	}
	sort.Strings(out)
	return out
}

func (d *datadogDest) send(ctx context.Context, evs []Event) error {
	site := d.cfg.Site
	if site == "" {
		site = "datadoghq.com"
	}
	var logs, series []any
	var spans []Event
	for _, e := range evs {
		switch e.Kind {
		case "log":
			status := strings.ToLower(e.Severity)
			if status == "" {
				status = "info"
			}
			logs = append(logs, map[string]any{"ddsource": "watchtower", "ddtags": strings.Join(tags(e.Attrs), ","), "hostname": or(d.cfg.Hostname, e.Attrs["host.name"]),
				"service": e.Service, "message": e.Message, "status": status, "timestamp": e.Time.UnixMilli(), "trace_id": e.TraceID, "span_id": e.SpanID})
		case "metric":
			typ := 3 // gauge
			if e.MetricType == "count" {
				typ = 1
			}
			series = append(series, map[string]any{"metric": e.Name, "type": typ, "points": []map[string]any{{"timestamp": e.Time.Unix(), "value": *e.Value}},
				"tags": tags(e.Attrs), "resources": []map[string]string{{"name": or(d.cfg.Hostname, e.Attrs["host.name"]), "type": "host"}}})
		case "span":
			spans = append(spans, e)
		}
	}
	hdr := map[string]string{"DD-API-KEY": d.secret}
	if len(logs) > 0 {
		b, _ := json.Marshal(logs)
		if _, err := d.post(ctx, or(d.cfg.URL, "https://http-intake.logs."+site+"/api/v2/logs"), "application/json", b, hdr); err != nil {
			return err
		}
	}
	if len(series) > 0 {
		b, _ := json.Marshal(map[string]any{"series": series})
		if _, err := d.post(ctx, or(d.cfg.MetricsURL, "https://api."+site+"/api/v2/series"), "application/json", b, hdr); err != nil {
			return err
		}
	}
	if len(spans) > 0 {
		url := or(d.cfg.TracesURL, "https://trace.agent."+site+"/api/v0.2/traces")
		if _, err := d.post(ctx, url, "application/x-protobuf", ddAgentPayload(spans, d.cfg.Hostname), hdr); err != nil {
			return err
		}
	}
	return nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// --- S3 -----------------------------------------------------------------------------------

type s3Dest struct {
	httpDest
	cfg   DestConfig
	token string // STS session token, signed as X-Amz-Security-Token
	now   func() time.Time
}

// send writes one gzip NDJSON object per (kind, hour). The key holds a hash of the content, so a
// retry overwrites the same object.
func (s *s3Dest) send(ctx context.Context, evs []Event) error {
	groups := map[string][]Event{}
	for _, e := range evs {
		k := e.Kind + "s/dt=" + e.Time.UTC().Format("2006-01-02") + "/hour=" + e.Time.UTC().Format("15")
		groups[k] = append(groups[k], e)
	}
	for k, g := range groups {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, e := range g {
			_ = enc.Encode(e)
		}
		sum := sha256.Sum256(b.Bytes())
		key := strings.Trim(s.cfg.Prefix, "/")
		if key != "" {
			key += "/"
		}
		key += k + "/" + hex.EncodeToString(sum[:12]) + ".ndjson.gz"
		if err := s.put(ctx, key, gz(b.Bytes())); err != nil {
			return err
		}
	}
	return nil
}

func (s *s3Dest) put(ctx context.Context, key string, body []byte) error {
	target := "https://" + s.cfg.Bucket + ".s3." + s.cfg.Region + ".amazonaws.com/" + key
	if s.cfg.URL != "" {
		target = strings.TrimRight(s.cfg.URL, "/") + "/" + s.cfg.Bucket + "/" + key
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return &permError{err}
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	creds := aws.Credentials{AccessKeyID: s.cfg.AccessKey, SecretAccessKey: s.secret, SessionToken: s.token, Source: "relay"}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, payload, "s3", s.cfg.Region, s.now()); err != nil {
		return &permError{errors.New("sigv4 signing failed")}
	}
	_, err = s.do(req)
	return err
}

// secretOr is secret() with a fallback environment variable.
func secretOr(env, file, fallback string) (string, error) {
	v, err := secret(env, file)
	if v == "" && err == nil {
		v = strings.TrimSpace(os.Getenv(fallback))
	}
	return v, err
}
