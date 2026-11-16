package logs

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func rec(m map[string]any) map[string]any { return m }

func TestForwardRecordMapping(t *testing.T) {
	id := "0123456789ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123"
	r, ok := ParseForwardRecord(rec(map[string]any{
		"log": "hello", "container_id": id, "container_name": "/proj-api-1", "source": "stderr",
		"com.docker.compose.service": "api", "wt.team": []byte("pay"),
		"OTEL_SERVICE_NAME": "checkout", "SECRET": 5,
	}))
	if !ok || r.Name != "proj-api-1" || r.Labels["wt.team"] != "pay" || len(r.Env) != 1 {
		t.Fatalf("%+v", r)
	}
	if _, has := r.Labels["OTEL_SERVICE_NAME"]; has {
		t.Fatal("env must not become a label")
	}
	out := &sink.Recorder{}
	r.Apply(nil, out, time.Now())
	s := out.Snapshot()
	if len(s) != 1 || s[0].Body != "hello" || s[0].Attrs["container.id"] != id || s[0].Attrs["container.name"] != "proj-api-1" || s[0].Attrs["log.iostream"] != "stderr" {
		t.Fatalf("%+v", s)
	}
	if got := s[0].Attrs; got["service.name"] == "" && got[sink.ResourcePrefix+"service.name"] == "" {
		t.Fatalf("no service identity in %v", got)
	}
	// names and labels were learned for the cgroup series
	if l, ok := container.Lookup(id); !ok || l.Name != "proj-api-1" || l.Service != "api" || l.Labels["wt.team"] != "pay" {
		t.Fatalf("learned %+v", l)
	}
	// the label filter drops other containers' lines
	out2 := &sink.Recorder{}
	r.Apply(container.LabelSet{"wt.team": {"other"}}, out2, time.Now())
	if len(out2.Snapshot()) != 0 {
		t.Fatal("label filter")
	}
	if _, ok := ParseForwardRecord(rec(map[string]any{"log": "x"})); ok {
		t.Fatal("record without container id")
	}
}

func TestForwardMessageAck(t *testing.T) {
	id := "fedcba987654" + "0123456789abcdef0123456789abcdef0123456789abcdef0123"
	out := &sink.Recorder{}
	m := []any{"docker.x", uint64(1700000000), map[string]any{"log": "l", "container_id": id, "container_name": "/a-b-1"}, map[string]any{"chunk": "abc"}}
	ack, err := fwdMessage(m, ForwardConf{}, out)
	if err != nil || string(ack) != "\x81\xa3ack\xa3abc" || len(out.Snapshot()) != 1 {
		t.Fatalf("%q %v %v", ack, err, out.Snapshot())
	}
}
