package custom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKubeletAndScalewaySD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pods" {
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"a","namespace":"n"},"spec":{"containers":[{"ports":[{"name":"metrics","containerPort":9102},{"name":"http","containerPort":80}]}]},"status":{"podIP":"10.0.0.5","phase":"Running"}},{"metadata":{"name":"b"},"status":{"podIP":"10.0.0.6","phase":"Pending"}}]}`))
			return
		}
		if r.Header.Get("X-Auth-Token") != "k" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"servers":[{"name":"s1","state":"running","private_ip":"10.1.0.1"},{"name":"s2","state":"stopped","private_ip":"10.1.0.2"}]}`))
	}))
	defer srv.Close()
	got, err := SDConfig{URL: srv.URL, Token: "t"}.kubeletSD(context.Background(), srv.Client())
	if err != nil || len(got) != 1 || got[0].URL != "http://10.0.0.5:9102/metrics" {
		t.Fatalf("%v %v", got, err)
	}
	got, err = SDConfig{URL: srv.URL, Token: "k"}.scalewaySD(context.Background(), srv.Client())
	if err != nil || len(got) != 1 || got[0].URL != "http://10.1.0.1:9100/metrics" {
		t.Fatalf("%v %v", got, err)
	}
}
