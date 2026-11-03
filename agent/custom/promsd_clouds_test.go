package custom

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudSDs(t *testing.T) {
	var uyuniCalls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(s string) { _, _ = w.Write([]byte(s)) }
		switch {
		case r.Header.Get("X-Amz-Target") != "":
			if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				w.WriteHeader(403)
				return
			}
			write(`{"instances":[{"name":"a","privateIpAddress":"10.0.0.1","state":{"name":"running"}},{"name":"b","privateIpAddress":"10.0.0.2","state":{"name":"stopped"}}]}`)
		case strings.Contains(r.URL.Path, "/datacenters/"):
			write(`{"items":[{"properties":{"name":"s","vmState":"RUNNING"},"entities":{"nics":{"items":[{"properties":{"ips":["10.0.0.3"]}}]}}},{"properties":{"vmState":"SHUTOFF"}}]}`)
		case r.URL.Path == "/vps":
			if !strings.HasPrefix(r.Header.Get("X-Ovh-Signature"), "$1$") {
				w.WriteHeader(403)
				return
			}
			write(`["v1"]`)
		case r.URL.Path == "/vps/v1/ips":
			write(`["2001:db8::1","10.0.0.4"]`)
		case r.URL.Path == "/dedicated/server":
			write(`[]`)
		case r.URL.Path == "/v1/discover":
			write(`{"containers":[{"vm_alias":"web","vm_uuid":"u1","server_uuid":"h"}]}`)
		case r.URL.Path == "/rpc":
			b, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(b), "auth.login"):
				write(`<methodResponse><params><param><value><string>sess</string></value></param></params></methodResponse>`)
			case strings.Contains(string(b), "system.listSystems"):
				write(`<methodResponse><params><param><value><array><data><value><struct><member><name>id</name><value><int>7</int></value></member><member><name>name</name><value><string>sys</string></value></member></struct></value></data></array></value></param></params></methodResponse>`)
			case strings.Contains(string(b), "system.getNetwork"):
				uyuniCalls = append(uyuniCalls, string(b))
				write(`<methodResponse><params><param><value><struct><member><name>ip</name><value><string>10.0.0.5</string></value></member></struct></value></param></params></methodResponse>`)
			default:
				write(`<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx, hc := context.Background(), srv.Client()
	for name, c := range map[string]struct {
		run  func() ([]TargetSpec, error)
		want string
	}{
		"lightsail": {func() ([]TargetSpec, error) {
			return SDConfig{Region: "r", AccessKeyID: "a", SecretAccessKey: "s", Endpoint: srv.URL + "/"}.lightsailSD(ctx, hc)
		}, "http://10.0.0.1:9100/metrics"},
		"ionos": {func() ([]TargetSpec, error) {
			return SDConfig{URL: srv.URL, DatacenterID: "d", Token: "t"}.ionosSD(ctx, hc)
		}, "http://10.0.0.3:9100/metrics"},
		"ovh": {func() ([]TargetSpec, error) {
			return SDConfig{URL: srv.URL, ApplicationKey: "a", ApplicationSecret: "s", ConsumerKey: "c"}.ovhSD(ctx, hc)
		}, "http://10.0.0.4:9100/metrics"},
		"triton": {func() ([]TargetSpec, error) { return SDConfig{URL: srv.URL, DNSSuffix: "cmon"}.tritonSD(ctx, hc) }, "http://u1.cmon:9163/metrics"},
		"uyuni": {func() ([]TargetSpec, error) {
			return SDConfig{URL: srv.URL + "/rpc", Username: "u", Password: "p"}.uyuniSD(ctx, hc)
		}, "http://10.0.0.5:9100/metrics"},
	} {
		got, err := c.run()
		if err != nil || len(got) != 1 || got[0].URL != c.want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	if len(uyuniCalls) != 1 || !strings.Contains(uyuniCalls[0], "<int>7</int>") {
		t.Fatal(uyuniCalls)
	}
}

func TestOvhSignature(t *testing.T) {
	// sha1 of "s+c+GET+https://x+"+"+1", from the API's documented construction
	if got := ovhSign("s", "c", "GET", "https://x", "", 1); len(got) != 43 || got[:3] != "$1$" {
		t.Fatal(got)
	}
}

func TestZKMemberParsers(t *testing.T) {
	c := SDConfig{}
	if tg, ok := c.parseServerset([]byte(`{"serviceEndpoint":{"host":"h","port":1},"status":"ALIVE","shard":2}`), ""); !ok || tg.URL != "http://h:1/metrics" || tg.Labels["shard"] != "2" {
		t.Fatal(tg)
	}
	if _, ok := c.parseServerset([]byte(`{"serviceEndpoint":{"host":"h","port":1},"status":"STOPPED"}`), ""); ok {
		t.Fatal("not alive")
	}
	if tg, ok := c.parseNerve([]byte(`{"host":"n","port":2,"name":"x"}`), ""); !ok || tg.URL != "http://n:2/metrics" {
		t.Fatal(tg)
	}
	if _, err := (SDConfig{}).serversetSD(context.Background(), nil); err == nil {
		t.Fatal("needs servers")
	}
}
