package hw

// Storage array collectors (INF-013, gap G-23): NetApp ONTAP REST (/api/storage/...) and Pure
// Storage FlashArray REST 2.x. Capacity, health and state of aggregates, volumes, disks and
// hardware become hw.* metrics. The credential is bound to the array's base URL: requests only
// ever go to that origin, redirects are never followed and pagination links that leave the
// origin are refused, so a compromised array cannot forward the password elsewhere.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

const (
	maxArrayPages   = 20
	maxArrayRecords = 1000
	pureAPIVersion  = "2.4"
)

// Array is one storage array. Vendor is "ontap", "pure", "powerstore" (Dell PowerStore REST)
// or "hpe" (HPE 3PAR/Primera/Alletra 9000 WSAPI), both in array_more.go, and "unity" (Dell Unity
// Unisphere), "nimble" (HPE Nimble/Alletra 5000/6000) or "ibm" (IBM FlashSystem/Storwize Spectrum
// Virtualize), in array_rest3.go.
type Array struct {
	Name               string `json:"name"`
	Vendor             string `json:"vendor"`
	BaseURL            string `json:"base_url"`
	Username           string `json:"username"`       // all but pure
	PasswordFile       string `json:"password_file"`  // all but pure
	APITokenFile       string `json:"api_token_file"` // pure
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Scope              Scope  `json:"scope"`
}

type arrayClient struct {
	a      Array
	origin *url.URL
	hc     *http.Client
	secret string
	hdr    map[string]string
}

func readSecret(path, what string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("hw array: %s is required", what)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hw array: %s cannot be read", what)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func newArrayClient(a Array) (*arrayClient, error) {
	u, err := url.Parse(a.BaseURL)
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return nil, errors.New("hw array: base_url must be an https URL")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: a.InsecureSkipVerify} //nolint:gosec // local opt-in for self-signed arrays
	if a.CAFile != "" {
		pem, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, errors.New("hw array: ca_file cannot be read")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("hw array: ca_file has no certificates")
		}
		tc.RootCAs = pool
	}
	hc := netguard.NewClientWith(netguard.FromEnv("agent"), netguard.Options{}, func(tr *http.Transport) {
		tr.TLSClientConfig = tc
	})
	hc.Timeout = 15 * time.Second
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &arrayClient{a: a, origin: &url.URL{Scheme: u.Scheme, Host: u.Host}, hc: hc, hdr: map[string]string{}}
	switch a.Vendor {
	case "ontap":
		if a.Username == "" {
			return nil, errors.New("hw array: ontap needs username")
		}
		c.secret, err = readSecret(a.PasswordFile, "password_file")
	case "pure":
		c.secret, err = readSecret(a.APITokenFile, "api_token_file")
	case "powerstore", "hpe", "unity", "nimble", "ibm":
		if a.Username == "" {
			return nil, fmt.Errorf("hw array: %s needs username", a.Vendor)
		}
		c.secret, err = readSecret(a.PasswordFile, "password_file")
	default:
		return nil, fmt.Errorf("hw array: unknown vendor %q (ontap, pure, powerstore, hpe, unity, nimble or ibm)", a.Vendor)
	}
	return c, err
}

// apiPath reports whether p is under one of the vendors' REST roots.
func apiPath(p string) bool {
	for _, root := range []string{"/api/", "/v1/", "/rest/"} {
		if strings.HasPrefix(p, root) && !strings.Contains(p, "/../") {
			return true
		}
	}
	return false
}

// at builds a URL on the array's own origin; a path that is absolute elsewhere is refused.
func (c *arrayClient) at(path string) (string, error) {
	ref, err := url.Parse(path)
	if err != nil || ref.Host != "" || ref.Scheme != "" || !apiPath(ref.Path) {
		return "", errors.New("hw array: link leaves the array")
	}
	return c.origin.ResolveReference(ref).String(), nil
}

func (c *arrayClient) do(ctx context.Context, method, path string, v any) (http.Header, error) {
	return c.doBody(ctx, method, path, nil, v)
}

// doBody sends an optional JSON body; every request stays on the pinned origin.
func (c *arrayClient) doBody(ctx context.Context, method, path string, body, v any) (http.Header, error) {
	u, err := c.at(path)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("hw array: bad request body")
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, errors.New("hw array: bad request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range c.hdr {
		req.Header.Set(k, val)
	}
	if c.a.Vendor == "ontap" || c.a.Vendor == "powerstore" || c.a.Vendor == "unity" {
		req.SetBasicAuth(c.a.Username, c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, errors.New("hw array: request failed") // the url error could name the host
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 { // WSAPI answers 201 to a session login
		return nil, fmt.Errorf("hw array %s: HTTP %d", path, resp.StatusCode)
	}
	if v == nil || resp.StatusCode == http.StatusNoContent {
		return resp.Header, nil
	}
	return resp.Header, json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

// PollArray reads one array and emits hw.array.up plus everything it could read.
func PollArray(ctx context.Context, a Array, out sink.Sink, at time.Time) error {
	out = withScope(out, a.Scope)
	base := map[string]string{"hw.array": a.Name, "hw.vendor": a.Vendor}
	c, err := newArrayClient(a)
	if err != nil {
		return err
	}
	switch a.Vendor {
	case "ontap":
		err = c.ontap(ctx, out, base, at)
	case "pure":
		err = c.pure(ctx, out, base, at)
	case "powerstore":
		err = c.powerstore(ctx, out, base, at)
	case "hpe":
		err = c.hpe(ctx, out, base, at)
	case "unity":
		err = c.unity(ctx, out, base, at)
	case "nimble":
		err = c.nimble(ctx, out, base, at)
	case "ibm":
		err = c.ibm(ctx, out, base, at)
	}
	up := 1.0
	if err != nil {
		up = 0
	}
	out.Gauge("hw.array.up", "1", up, base, at)
	return err
}

type ontapSpace struct {
	Size      *float64 `json:"size"`
	Used      *float64 `json:"used"`
	Available *float64 `json:"available"`
}

// ontapRecords walks a collection through its relative `_links.next.href`.
func (c *arrayClient) ontapRecords(ctx context.Context, path string, each func(json.RawMessage)) error {
	next := path
	for range maxArrayPages {
		var page struct {
			Records []json.RawMessage `json:"records"`
			Links   struct {
				Next *struct {
					Href string `json:"href"`
				} `json:"next"`
			} `json:"_links"`
		}
		if _, err := c.do(ctx, http.MethodGet, next, &page); err != nil {
			return err
		}
		for _, r := range page.Records {
			each(r)
		}
		if page.Links.Next == nil || page.Links.Next.Href == "" {
			return nil
		}
		next = page.Links.Next.Href
	}
	return nil
}

func ontapState(s string) string {
	switch s {
	case "online", "present", "spare", "shared":
		return "ok"
	case "", "unknown":
		return ""
	case "restricted", "reconstructing", "pending", "copy", "maintenance":
		return "degraded"
	}
	return "failed" // offline, broken, failed, mixed
}

func (c *arrayClient) ontap(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	q := fmt.Sprintf("&max_records=%d", maxArrayRecords)
	err := c.ontapRecords(ctx, "/api/storage/aggregates?fields=name,state,space"+q, func(b json.RawMessage) {
		var r struct {
			Name  string `json:"name"`
			State string `json:"state"`
			Space struct {
				Block ontapSpace `json:"block_storage"`
			} `json:"space"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.Name, "hw.name", r.Name, "hw.storage.kind", "aggregate")
		if s := ontapState(r.State); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Space.Block.Size, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Space.Block.Used, "logical_disk", a, at)
	})
	verr := c.ontapRecords(ctx, "/api/storage/volumes?fields=name,state,space,svm.name"+q, func(b json.RawMessage) {
		var r struct {
			Name  string     `json:"name"`
			State string     `json:"state"`
			Space ontapSpace `json:"space"`
			SVM   struct {
				Name string `json:"name"`
			} `json:"svm"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.SVM.Name+"/"+r.Name, "hw.name", r.Name, "hw.storage.kind", "volume", "hw.svm", r.SVM.Name)
		if s := ontapState(r.State); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Space.Size, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Space.Used, "logical_disk", a, at)
	})
	derr := c.ontapRecords(ctx, "/api/storage/disks?fields=name,state,model,serial_number"+q, func(b json.RawMessage) {
		var r struct {
			Name   string `json:"name"`
			State  string `json:"state"`
			Model  string `json:"model"`
			Serial string `json:"serial_number"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		if s := ontapState(r.State); s != "" {
			emitState(out, sink.With(base, "hw.id", r.Name, "hw.name", nameOf(r.Model, r.Name), "hw.serial_number", r.Serial), "physical_disk", s, at)
		}
	})
	return cmpErr(cmpErr(err, verr), derr)
}

// pureLogin trades the API token for a session token (x-auth-token), as REST 2.x requires.
func (c *arrayClient) pureLogin(ctx context.Context) error {
	c.hdr = map[string]string{"api-token": c.secret}
	h, err := c.do(ctx, http.MethodPost, "/api/"+pureAPIVersion+"/login", nil)
	c.hdr = map[string]string{}
	if err != nil {
		return err
	}
	tok := h.Get("x-auth-token")
	if tok == "" {
		return errors.New("hw array: pure login returned no session token")
	}
	c.hdr["x-auth-token"] = tok
	return nil
}

// pureItems walks a REST 2.x collection through its continuation token.
func (c *arrayClient) pureItems(ctx context.Context, path string, each func(json.RawMessage)) error {
	token := ""
	for range maxArrayPages {
		p := fmt.Sprintf("/api/%s/%s?limit=%d", pureAPIVersion, path, maxArrayRecords)
		if token != "" {
			p += "&continuation_token=" + url.QueryEscape(token)
		}
		var page struct {
			Items             []json.RawMessage `json:"items"`
			ContinuationToken string            `json:"continuation_token"`
		}
		if _, err := c.do(ctx, http.MethodGet, p, &page); err != nil {
			return err
		}
		for _, it := range page.Items {
			each(it)
		}
		if token = page.ContinuationToken; token == "" {
			return nil
		}
	}
	return nil
}

func pureState(s string) string {
	switch s {
	case "ok", "healthy":
		return "ok"
	case "not_installed", "unused", "":
		return ""
	case "degraded", "identifying":
		return "degraded"
	}
	return "failed" // critical, unhealthy, unknown
}

func (c *arrayClient) pure(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	if err := c.pureLogin(ctx); err != nil {
		return err
	}
	err := c.pureItems(ctx, "arrays/space", func(b json.RawMessage) {
		var r struct {
			Name     string   `json:"name"`
			Capacity *float64 `json:"capacity"`
			Space    struct {
				TotalPhysical *float64 `json:"total_physical"`
				DataReduction *float64 `json:"data_reduction"`
			} `json:"space"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.Name, "hw.name", r.Name, "hw.storage.kind", "array")
		emitNum(out, "hw.logical_disk.limit", "By", r.Capacity, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Space.TotalPhysical, "logical_disk", a, at)
		emitNum(out, "hw.array.data_reduction", "1", r.Space.DataReduction, "logical_disk", a, at)
	})
	verr := c.pureItems(ctx, "volumes", func(b json.RawMessage) {
		var r struct {
			Name        string   `json:"name"`
			Provisioned *float64 `json:"provisioned"`
			Space       struct {
				Virtual *float64 `json:"virtual"`
			} `json:"space"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.Name, "hw.name", r.Name, "hw.storage.kind", "volume")
		emitNum(out, "hw.logical_disk.limit", "By", r.Provisioned, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Space.Virtual, "logical_disk", a, at)
	})
	herr := c.pureItems(ctx, "hardware", func(b json.RawMessage) {
		var r struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Type   string `json:"type"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		typ := "enclosure"
		switch r.Type {
		case "drive_bay":
			typ = "physical_disk"
		case "power_supply":
			typ = "power_supply"
		case "cooling":
			typ = "fan"
		case "temp_sensor":
			typ = "temperature"
		case "controller":
			typ = "disk_controller"
		}
		if s := pureState(r.Status); s != "" {
			emitState(out, sink.With(base, "hw.id", r.Name, "hw.name", r.Name), typ, s, at)
		}
	})
	return cmpErr(cmpErr(err, verr), herr)
}
