package integrations

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func manifestByName(t *testing.T, name string) *Manifest {
	t.Helper()
	for _, m := range loadAll(t) {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("no manifest %s", name)
	return nil
}

func metricSet(m *Manifest) func(string) bool {
	set := map[string]bool{}
	for _, d := range m.Metrics {
		set[d.Name] = true
	}
	return func(n string) bool { return set[n] }
}

// Each Prometheus-endpoint pack scrapes the path it names and forwards exactly the series its
// manifest documents (the fixture is built from the manifest, plus one series that must be dropped).
func TestExporterPacksForwardWhatTheirManifestsDocument(t *testing.T) {
	for name, sp := range exporterPackSpecs {
		m := manifestByName(t, name)
		if m.Module.Kind != name {
			t.Fatalf("%s: module kind %q", name, m.Module.Kind)
		}
		var body strings.Builder
		for _, d := range m.Metrics {
			raw := strings.TrimPrefix(d.Name, sp.rename) // the pack prepends rename to unprefixed names
			fmt.Fprintf(&body, "# TYPE %s gauge\n%s{a=\"b\"} 1\n", raw, raw)
		}
		body.WriteString("# TYPE unrelated_series gauge\nunrelated_series 1\n")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != strings.SplitN(sp.path, "?", 2)[0] {
				http.NotFound(w, r)
				return
			}
			if sp.basic && !basicOK(r) {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			io.WriteString(w, body.String())
		}))
		rec := runPack(PackCollectors()[name], fmt.Sprintf(`{"url":%q,"username":"u","password":"p"}`, srv.URL))
		srv.Close()
		checkPack(t, name, m, rec, metricSet(m))
	}
}

func TestJolokiaPacksMapAttributesToDocumentedMetrics(t *testing.T) {
	for name, jp := range jolokiaPacks {
		m := manifestByName(t, name)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqs []struct{ MBean string }
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &reqs)
			var resp []map[string]any
			for _, q := range reqs {
				var attrs map[string]any
				for _, rd := range jp.reads {
					if rd.MBean == q.MBean {
						attrs = map[string]any{}
						for _, a := range rd.Attributes {
							attrs[a] = 1
						}
					}
				}
				val := any(attrs)
				if strings.Contains(q.MBean, "*") {
					val = map[string]any{strings.NewReplacer(",*", ",Name=x", "*", "x").Replace(q.MBean): attrs}
				}
				resp = append(resp, map[string]any{"request": map[string]any{"mbean": q.MBean}, "status": 200, "value": val})
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		rec := runPack(PackCollectors()[name], fmt.Sprintf(`{"url":%q}`, srv.URL))
		srv.Close()
		checkPack(t, name, m, rec, metricSet(m))
	}
}

func TestSystemdReportsActiveAndFailedServices(t *testing.T) {
	const listing = "  nginx.service    loaded active   running  nginx\n● backup.service   loaded failed   failed   backup\n  cron.service     loaded inactive dead     cron\n  sshd.socket      loaded active   listening sshd\n"
	var r sink.Recorder
	emitSystemd(&r, listing, []string{"nginx.service", "back*"}, time.Now())
	if v, _ := value(&r, "systemd.units.failed"); v != 1 {
		t.Fatalf("failed: %v", v)
	}
	units := 0
	for _, s := range r.Samples {
		if s.Name == "systemd.unit.active" {
			units++
			want := map[string]float64{"nginx.service": 1, "backup.service": 0}[s.Attrs["unit"]]
			if s.Value != want || s.Attrs["sub_state"] == "" {
				t.Fatalf("unit %+v", s)
			}
		}
	}
	if units != 2 {
		t.Fatalf("units reported: %d", units)
	}
}

func TestNTPMeasuresOffsetAgainstAServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP on loopback")
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 48)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ahead := toNTP(time.Now().Add(2 * time.Second)) // the server's clock is 2 s ahead
		resp := make([]byte, 48)
		resp[0], resp[1] = 0x24, 2 // server mode, stratum 2
		binary.BigEndian.PutUint64(resp[32:], ahead)
		binary.BigEndian.PutUint64(resp[40:], ahead)
		_, _ = pc.WriteTo(resp, addr)
	}()
	off, _, stratum, err := sntpQuery(t.Context(), pc.LocalAddr().String())
	if err != nil || stratum != 2 || off < 1.9 || off > 2.1 {
		t.Fatalf("offset %v stratum %d err %v", off, stratum, err)
	}
	rec := runPack(NTP, `{"servers":["127.0.0.1:1"]}`) // nothing listens: the round fails, up=0
	if v, ok := value(rec, "wt.integration.up"); !ok || v != 0 {
		t.Fatalf("unreachable server must report up=0, got %v", v)
	}
}

func TestTLSCertReadsTargetsAndFiles(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "c.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	m := manifestByName(t, "tlscert")
	rec := runPack(TLSCert, fmt.Sprintf(`{"targets":[%q],"files":[%q]}`, srv.Listener.Addr().String(), file))
	checkPack(t, "tlscert", m, rec, metricSet(m))
	for _, s := range rec.Samples {
		if s.Name == "tls.cert.expiry_seconds" && s.Value <= 0 {
			t.Fatalf("httptest certificates are valid for a year: %+v", s)
		}
		if s.Name == "tls.cert.hostname_match" && s.Value != 1 {
			t.Fatalf("127.0.0.1 is in the httptest certificate: %+v", s)
		}
	}
	if _, err := x509.ParseCertificate(srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}

func TestStatusPagesParseSummaries(t *testing.T) {
	var r sink.Recorder
	body := `{"status":{"indicator":"minor"},"components":[{"name":"API","status":"degraded_performance"},{"name":"Git","status":"operational"}],"incidents":[{"status":"investigating"},{"status":"resolved"}]}`
	if err := emitStatusPage("github_status", false, []byte(body), &r, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(&r, "github_status.indicator"); v != 1 {
		t.Fatalf("indicator %v", v)
	}
	if v, _ := value(&r, "github_status.incidents.active"); v != 1 {
		t.Fatalf("incidents %v", v)
	}
	var s sink.Recorder
	if err := emitStatusPage("stripe_status", true, []byte(`{"largestatus":"down"}`), &s, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(&s, "stripe_status.indicator"); v != 3 {
		t.Fatalf("stripe %v", v)
	}
	if emitStatusPage("x", false, []byte(`{"status":{"indicator":"weird"}}`), &s, time.Now()) == nil {
		t.Fatal("an unknown indicator must fail the round")
	}
}

func TestStatusPageCollectorsReachTheirEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"status":{"indicator":"none"},"components":[{"name":"API","status":"operational"}],"incidents":[]}`)
	}))
	defer srv.Close()
	for _, name := range []string{"github_status", "twilio"} {
		m := manifestByName(t, name)
		rec := runPack(PackCollectors()[name], fmt.Sprintf(`{"url":%q}`, srv.URL))
		checkPack(t, name, m, rec, metricSet(m))
	}
}

func TestOktaCountsSystemLogEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS k" || r.URL.Path != "/api/v1/logs" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		now := time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(w, `[{"eventType":"user.session.start","published":%q,"outcome":{"result":"FAILURE"}},{"eventType":"user.session.start","published":%q,"outcome":{"result":"FAILURE"}}]`, now, now)
	}))
	defer srv.Close()
	evs, err := oktaEvents(t.Context(), &OktaConfig{URL: srv.URL, Token: "k"}, time.Now())
	if err != nil || len(evs) != 2 || evs[0].EventType != "user.session.start" || evs[0].Outcome.Result != "FAILURE" {
		t.Fatalf("events %+v err %v", evs, err)
	}
	if _, err := oktaEvents(t.Context(), &OktaConfig{URL: srv.URL, Token: "wrong"}, time.Now()); err == nil {
		t.Fatal("a bad token must fail the round")
	}
	if ValidateConfig("okta", json.RawMessage(`{"url":"http://x.okta.com","token":"k"}`)) == nil {
		t.Fatal("an org URL must be https")
	}
}

func TestEveryManifestWithLogsHasAParseablePipeline(t *testing.T) {
	noLogs := map[string]bool{"sqlite": true, "snmp": true, "kinesis": true, "pinecone": true, "memcached": true, "github-action": true,
		"tlscert": true, "twilio": true, "github_status": true, "stripe_status": true,
		"snowflake": true, "databricks": true, "vercel": true, "cloudflare": true,
		"dcgm": true} // dcgm: GPU metrics only // SaaS: their logs arrive at the gateway, not from agent files
	for _, m := range loadAll(t) {
		if (m.Logs == nil) != noLogs[m.Name] {
			t.Errorf("%s: logs present=%v, expected absent=%v", m.Name, m.Logs != nil, noLogs[m.Name])
		}
	}
	bad := strings.Split(readFile(t, manifestsDir+"/ntp/manifest.yaml"), "\nlogs:")[0] +
		"\nlogs: {paths: [x], pipeline: {version: 1, stages: [{type: nope}]}}\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("an unknown stage type must be refused")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSpecNamedIntegrationsAllHaveManifests(t *testing.T) {
	have := map[string]bool{}
	for _, m := range loadAll(t) {
		have[m.Name] = true
	}
	for _, n := range strings.Fields("gcp azure squid snowflake databricks dcgm vercel cloudflare linkerd jboss weblogic phpfpm gunicorn uwsgi puma hadoop spark airflow flink opensearch aerospike varnish systemd ntp tlscert argocd cilium calico certmanager karpenter bigquery gitlab_runner fastly akamai atlas confluent okta twilio stripe_status github_status") {
		if !have[n] {
			t.Errorf("missing manifest %s", n)
		}
	}
	if len(have) < 100 {
		t.Errorf("only %d manifests", len(have))
	}
}
