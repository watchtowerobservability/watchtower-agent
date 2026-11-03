package recv

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestDecodeJSONGzAndProto(t *testing.T) {
	js := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"GET /","traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"0102030405060708"}]}]}]}`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(js)
	_ = zw.Close()
	b, err := Decode("year=2026/x.json.gz", gz.Bytes(), "traces")
	if err != nil {
		t.Fatal(err)
	}
	var m coltrace.ExportTraceServiceRequest
	if proto.Unmarshal(b, &m) != nil || m.GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()[0].GetName() != "GET /" {
		t.Fatalf("%v", &m)
	}
	if b2, err := Decode("x.binpb", b, "traces"); err != nil || !bytes.Equal(b2, b) {
		t.Fatalf("proto round trip: %v", err)
	}
	if b3, _ := Decode("readme.txt", nil, "traces"); b3 != nil {
		t.Fatal("non-OTLP object must be skipped")
	}
}

func TestFileStatsAndECS(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.log"), []byte("hello"), 0o600)
	r := &sink.Recorder{}
	EmitFileStats(r, []string{filepath.Join(dir, "*.log")}, time.Now())
	var size float64
	for _, s := range r.Samples {
		if s.Name == "file.size" {
			size = s.Value
		}
	}
	if size != 5 {
		t.Fatalf("file.size = %v", size)
	}
	task := ecsTask{Cluster: "c", TaskARN: "arn"}
	task.Containers = append(task.Containers, struct {
		DockerID string `json:"DockerId"`
		Name     string `json:"Name"`
	}{"d1", "web"})
	st := ecsStats{}
	st.Memory.Usage = 100
	r2 := &sink.Recorder{}
	EmitECS(r2, task, map[string]ecsStats{"d1": st}, time.Now())
	if len(r2.Samples) < 3 || r2.Samples[0].Attrs["aws.ecs.task.arn"] != "arn" {
		t.Fatalf("%+v", r2.Samples)
	}
}
