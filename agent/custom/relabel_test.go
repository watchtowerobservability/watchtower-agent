package custom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sp(s string) *string { return &s }

func TestRelabelAllActionsGolden(t *testing.T) {
	base := map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod", "app_x": "a", "tmp": "t"}
	cases := []struct {
		name  string
		rules []RelabelRule
		want  map[string]string // nil: target dropped
	}{
		{"replace default $1", []RelabelRule{{SourceLabels: []string{"job"}, TargetLabel: "j"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod", "app_x": "a", "tmp": "t", "j": "Node"}},
		{"replace port rewrite", []RelabelRule{{SourceLabels: []string{"__address__"}, Regex: `([^:]+)(?::\d+)?`, Replacement: sp("$1:80"), TargetLabel: "__address__"}},
			map[string]string{"__address__": "host:80", "job": "Node", "env": "prod", "app_x": "a", "tmp": "t"}},
		{"replace empty deletes", []RelabelRule{{SourceLabels: []string{"nope"}, Regex: "(.*)", Replacement: sp(""), TargetLabel: "tmp"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod", "app_x": "a"}},
		{"keep match", []RelabelRule{{SourceLabels: []string{"env"}, Regex: "prod", Action: "keep"}}, base},
		{"keep miss", []RelabelRule{{SourceLabels: []string{"env"}, Regex: "dev", Action: "keep"}}, nil},
		{"drop match", []RelabelRule{{SourceLabels: []string{"env"}, Regex: "pro.", Action: "drop"}}, nil},
		{"regex is anchored", []RelabelRule{{SourceLabels: []string{"env"}, Regex: "pro", Action: "drop"}}, base},
		{"keepequal", []RelabelRule{{SourceLabels: []string{"env"}, TargetLabel: "env", Action: "keepequal"}}, base},
		{"dropequal", []RelabelRule{{SourceLabels: []string{"env"}, TargetLabel: "env", Action: "dropequal"}}, nil},
		{"two sources joined", []RelabelRule{{SourceLabels: []string{"job", "env"}, Separator: sp("-"), Regex: "(.*)", TargetLabel: "je"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod", "app_x": "a", "tmp": "t", "je": "Node-prod"}},
		{"lowercase", []RelabelRule{{SourceLabels: []string{"job"}, TargetLabel: "job", Action: "lowercase"}},
			map[string]string{"__address__": "host:9100", "job": "node", "env": "prod", "app_x": "a", "tmp": "t"}},
		{"uppercase", []RelabelRule{{SourceLabels: []string{"env"}, TargetLabel: "env", Action: "uppercase"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "PROD", "app_x": "a", "tmp": "t"}},
		{"labelmap", []RelabelRule{{Regex: "app_(.+)", Replacement: sp("x_$1"), Action: "labelmap"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod", "app_x": "a", "x_x": "a", "tmp": "t"}},
		{"labeldrop", []RelabelRule{{Regex: "tmp|app_.*", Action: "labeldrop"}},
			map[string]string{"__address__": "host:9100", "job": "Node", "env": "prod"}},
		{"labelkeep", []RelabelRule{{Regex: "job|env", Action: "labelkeep"}},
			map[string]string{"job": "Node", "env": "prod"}},
	}
	for _, c := range cases {
		got, ok := Relabel(base, c.rules)
		if c.want == nil {
			if ok {
				t.Errorf("%s: target kept: %v", c.name, got)
			}
			continue
		}
		if !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v ok=%v, want %v", c.name, got, ok, c.want)
		}
	}
	if base["job"] != "Node" || len(base) != 5 {
		t.Errorf("input labels mutated: %v", base)
	}
}

func TestRelabelHashmodStableAndBounded(t *testing.T) {
	r := []RelabelRule{{SourceLabels: []string{"__address__"}, Modulus: 4, TargetLabel: "shard", Action: "hashmod"}}
	a, _ := Relabel(map[string]string{"__address__": "h1:1"}, r)
	b, _ := Relabel(map[string]string{"__address__": "h1:1"}, r)
	if a["shard"] != b["shard"] || a["shard"] == "" || len(a["shard"]) != 1 || a["shard"] > "3" {
		t.Fatalf("hashmod: %v %v", a, b)
	}
	if err := ValidateRelabel([]RelabelRule{{Action: "hashmod", TargetLabel: "x"}}); err == nil {
		t.Fatal("hashmod without modulus must fail validation")
	}
}

func TestScrapeOpenMetricsExemplarsParsed(t *testing.T) {
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
		fmt.Fprint(w, "# TYPE reqs counter\n# HELP reqs requests\nreqs_total{code=\"200\"} 17 1700000000.5 # {trace_id=\"abc\",span_id=\"def\"} 1 1700000000.1\nreqs_created{code=\"200\"} 1700000000\n# EOF\n")
	}))
	defer srv.Close()
	rc := &rec{}
	if err := (Prometheus{}).Scrape(context.Background(), TargetSpec{URL: srv.URL}, rc, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(accept, "application/openmetrics-text") {
		t.Errorf("Accept = %q", accept)
	}
	s, ok := rc.find("sum", "reqs_total", map[string]string{"code": "200", "wt.exemplar.trace_id": "abc", "wt.exemplar.span_id": "def"})
	if !ok || s.value != 17 {
		t.Fatalf("counter with exemplar missing: %+v", rc.s)
	}
	if _, ok := rc.find("sum", "reqs_created", nil); ok {
		t.Error("_created series should be dropped")
	}
}

func TestSampleLimitFailsScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, "# TYPE g gauge\ng{i=\"1\"} 1\ng{i=\"2\"} 2\ng{i=\"3\"} 3\n")
	}))
	defer srv.Close()
	rc := &rec{}
	err := (Prometheus{}).Scrape(context.Background(), TargetSpec{URL: srv.URL, SampleLimit: 2}, rc, time.Now())
	if err == nil || !strings.Contains(err.Error(), "sample_limit") {
		t.Fatalf("want sample_limit error, got %v", err)
	}
	if len(rc.s) != 0 {
		t.Fatalf("a failed scrape must emit nothing, got %d", len(rc.s))
	}
}

func TestScrapeHonorLabelsAndMetricRelabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "# TYPE g gauge\ng{job=\"theirs\"} 1\nskipme 2\n")
	}))
	defer srv.Close()
	for _, honor := range []bool{false, true} {
		rc := &rec{}
		spec := TargetSpec{URL: srv.URL, Labels: map[string]string{"job": "mine"}, HonorLabels: honor,
			MetricRelabelConfigs: []RelabelRule{{SourceLabels: []string{"__name__"}, Regex: "skipme", Action: "drop"}}}
		if err := (Prometheus{}).Scrape(context.Background(), spec, rc, time.Now()); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"job": "mine", "exported_job": "theirs"}
		if honor {
			want = map[string]string{"job": "theirs"}
		}
		if _, ok := rc.find("gauge", "g", want); !ok {
			t.Errorf("honor=%v: %+v", honor, rc.s)
		}
		if _, ok := rc.find("gauge", "skipme", nil); ok {
			t.Errorf("honor=%v: metric_relabel drop ignored", honor)
		}
	}
}

func TestTextfileStaleSkipped(t *testing.T) {
	dir := t.TempDir()
	fresh, stale := filepath.Join(dir, "fresh.prom"), filepath.Join(dir, "stale.prom")
	for _, p := range []string{fresh, stale} {
		if err := os.WriteFile(p, []byte("# TYPE tf gauge\ntf{f=\""+filepath.Base(p)+"\"} 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(stale, now.Add(-11*time.Minute), now.Add(-11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rc := &rec{}
	ReadTextfiles(dir, rc, now)
	if _, ok := rc.find("gauge", "tf", map[string]string{"f": "fresh.prom"}); !ok {
		t.Errorf("fresh file not read: %+v", rc.s)
	}
	if _, ok := rc.find("gauge", "tf", map[string]string{"f": "stale.prom"}); ok {
		t.Error("stale file was read")
	}
	if s, ok := rc.find("gauge", "wt_textfile_stale_files", nil); !ok || s.value != 1 {
		t.Errorf("stale flag: %+v", rc.s)
	}
}
