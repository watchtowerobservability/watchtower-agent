package cloud

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func testKeyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestGcpJwtSignedRS256(t *testing.T) {
	k, _ := testKeyPEM(t)
	now := time.Unix(1700000000, 0)
	jwt, err := gcpJWT(k, "sa@p.iam", "https://tok", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatal(jwt)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(hdr), `"RS256"`) {
		t.Fatal(string(hdr))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal("signature does not verify:", err)
	}
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(claims), `"iss":"sa@p.iam"`) || !strings.Contains(string(claims), `"aud":"https://tok"`) {
		t.Fatal(string(claims))
	}
}

func TestGcpTimeSeriesMapsToOtel(t *testing.T) {
	_, pemKey := testKeyPEM(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"access_token":"tok1","expires_in":3600}`)
		case strings.HasPrefix(r.URL.Path, "/v3/projects/proj1/timeSeries"):
			if r.Header.Get("Authorization") != "Bearer tok1" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"timeSeries":[{"metric":{"type":"compute.googleapis.com/instance/cpu/utilization","labels":{"instance_name":"vm1"}},
				"resource":{"type":"gce_instance","labels":{"instance_id":"123","zone":"us-central1-a"}},
				"points":[{"interval":{"endTime":"2026-10-30T10:00:00Z"},"value":{"doubleValue":0.25}}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"project":"proj1","metrics":["compute.googleapis.com/instance/cpu/utilization"],
		"endpoint":%q,"service_account":{"client_email":"sa@p.iam","private_key":%q,"token_uri":%q}}`,
		srv.URL, pemKey, srv.URL+"/token")
	p, err := newGCP(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "gcp")); err != nil {
		t.Fatal(err)
	}
	s := rec.Snapshot()
	if len(s) != 1 || s[0].Name != "cloud.gcp.compute.instance.cpu.utilization" || s[0].Value != 0.25 ||
		s[0].Attrs["resource.cloud.provider"] != "gcp" || s[0].Attrs["resource.cloud.resource_id"] != "123" ||
		s[0].Attrs["resource.cloud.account.id"] != "proj1" {
		t.Fatalf("%+v", s)
	}
}

func TestAzureOAuthClientCredentialsThenMetrics(t *testing.T) {
	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			tokenCalls.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != "shh" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"access_token":"az1","expires_in":3600}`)
		case strings.Contains(r.URL.Path, "/providers/microsoft.insights/metrics"):
			if r.Header.Get("Authorization") != "Bearer az1" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"value":[{"name":{"value":"Percentage CPU"},"unit":"Percent","timeseries":[{"data":[{"timeStamp":"2026-10-30T10:00:00Z","average":12.5}]}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"tenant_id":"t1","client_id":"c1","client_secret":"shh","metrics":["Percentage CPU"],
		"resources":["/subscriptions/sub1/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/vm1"],
		"login_endpoint":%q,"endpoint":%q}`, srv.URL, srv.URL)
	p, err := newAzure(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	for range 2 {
		if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "azure")); err != nil {
			t.Fatal(err)
		}
	}
	s := rec.Snapshot()
	if len(s) != 2 || s[0].Name != "cloud.azure.microsoft.compute.virtualmachines.percentage_cpu" || s[0].Value != 12.5 ||
		s[0].Attrs["resource.cloud.account.id"] != "sub1" || s[0].Attrs["resource.cloud.resource_id"] != "vm1" {
		t.Fatalf("%+v", s)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token fetched %d times, want cached", tokenCalls.Load())
	}
}

func TestCloudflareGraphqlMapsZoneAnalytics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-token" {
			w.WriteHeader(403)
			return
		}
		fmt.Fprint(w, `{"data":{"viewer":{"zones":[{"httpRequests1mGroups":[{"dimensions":{"datetimeMinute":"2026-10-30T10:00:00Z"},"sum":{"requests":120,"bytes":4096}}]}]}}}`)
	}))
	defer srv.Close()
	p, err := newCloudflare(json.RawMessage(fmt.Sprintf(`{"api_token":"cf-token","zone_ids":["z1"],"account_id":"acc1","endpoint":%q}`, srv.URL)))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "cloudflare")); err != nil {
		t.Fatal(err)
	}
	n := rec.Names()
	if !n["cloud.cloudflare.zone.requests"] || !n["cloud.cloudflare.zone.bytes"] {
		t.Fatalf("%v", n)
	}
	for _, s := range rec.Snapshot() {
		if s.Name == "cloud.cloudflare.zone.requests" && (s.Value != 120 || s.Attrs["resource.cloud.resource_id"] != "z1") {
			t.Fatalf("%+v", s)
		}
	}
}

// fakePuller replays the same datapoint every run (an overlapping window) or fails.
type fakePuller struct {
	err   error
	calls int
}

func (f *fakePuller) pull(_ context.Context, _, to time.Time, e *emitter) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	e.gauge("cloud.x.m", "", 1, to.Truncate(time.Hour), map[string]string{"cloud.resource_id": "r"}, nil)
	return nil
}

func TestPullOverlapDeduped(t *testing.T) {
	rec := &sink.Recorder{}
	e := newEmitter(rec, "x")
	st := &pullState{interval: time.Minute}
	p := &fakePuller{}
	now := time.Date(2026, 10, 30, 10, 1, 0, 0, time.UTC)
	st.step(context.Background(), p, e, now)
	st.step(context.Background(), p, e, now.Add(time.Minute))
	points := 0
	for _, s := range rec.Snapshot() {
		if s.Name == "cloud.x.m" {
			points++
		}
	}
	if points != 1 || p.calls != 2 {
		t.Fatalf("points=%d calls=%d", points, p.calls)
	}
}

func TestPullBacksOffOn429(t *testing.T) {
	rec := &sink.Recorder{}
	st := &pullState{interval: time.Minute}
	p := &fakePuller{err: &rateLimitErr{after: 90 * time.Second}}
	if w := st.step(context.Background(), p, newEmitter(rec, "x"), time.Now()); w < 90*time.Second {
		t.Fatalf("waited %v, Retry-After is 90s", w)
	}
	p.err = &rateLimitErr{}
	w1 := st.step(context.Background(), p, newEmitter(rec, "x"), time.Now())
	w2 := st.step(context.Background(), p, newEmitter(rec, "x"), time.Now())
	if st.attempts != 3 || !st.last.IsZero() || w2 <= 0 || w1 <= 0 {
		t.Fatalf("attempts=%d last=%v", st.attempts, st.last)
	}
}

func TestPullErrorNeverHasSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	var out struct{}
	err := doJSON(context.Background(), http.DefaultClient, "GET", srv.URL+"/x?key=SECRET", nil, nil, &out)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}
