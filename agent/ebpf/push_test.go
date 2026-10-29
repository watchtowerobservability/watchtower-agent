package ebpf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostSendsGzipPprofWithCredential(t *testing.T) {
	var gotQuery, gotAuth, gotEnc string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotAuth, gotEnc = r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Encoding")
		body, _ = io.ReadAll(r.Body)
		if r.URL.Path != "/v1/profiles" {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ps, err := Fold(OffCPU, []Entry{{PID: 7, User: []uint64{0x401000}, Value: 2_000_000}}, fakeResolver{labels},
		time.Unix(1, 0), time.Minute, FoldOptions{StripArgs: true})
	if err != nil || len(ps) != 1 {
		t.Fatal(err)
	}
	if err := (Poster{Endpoint: srv.URL, Token: "wti_x"}).Post(context.Background(), ps[0]); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer wti_x" || gotEnc != "gzip" || len(body) == 0 {
		t.Fatalf("auth=%q enc=%q body=%d", gotAuth, gotEnc, len(body))
	}
	if gotQuery != "format=pprof&sample_type=offcpu&service=app&source=ebpf" {
		t.Fatalf("query = %s", gotQuery)
	}
	if d := decode(t, body); d.values[0][0] != 2_000_000 {
		t.Fatalf("offcpu value = %v", d.values)
	}
}

func TestPostReportsServerRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }))
	defer srv.Close()
	if err := (Poster{Endpoint: srv.URL, Token: "t"}).Post(context.Background(), Profile{Service: "a", Kind: CPU, Body: []byte{1}}); err == nil {
		t.Fatal("429 must be an error so the caller counts the drop")
	}
}
