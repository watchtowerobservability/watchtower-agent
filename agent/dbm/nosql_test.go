package dbm

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestShapeDropsEveryValue(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"status":"paid","total":{"$gt":100},"tags":{"$in":["a","b"]},"email":"x@y.z"}`), &doc)
	got := ShapeText(doc)
	if got != `{"email":"?","status":"?","tags":{"$in":["?"]},"total":{"$gt":"?"}}` {
		t.Fatal(got)
	}
	for _, leak := range []string{"paid", "100", "x@y.z"} {
		if strings.Contains(got, leak) {
			t.Fatalf("value %q leaked: %s", leak, got)
		}
	}
	var other any
	_ = json.Unmarshal([]byte(`{"tags":{"$in":["z"]},"total":{"$gt":5},"email":"q","status":"new"}`), &other)
	if Hash(ShapeText(other)) != Hash(got) {
		t.Fatal("equal shapes must hash equally")
	}
}

func TestRedactKeepsCommandAndKeyPattern(t *testing.T) {
	if got := Redact([]string{"set", "user:1234:cart", "secret-value"}, 1); got != "SET user:*:cart ?" {
		t.Fatal(got)
	}
	if got := KeyPattern("sess:9f8e7d6c5b4a"); got != "sess:*" {
		t.Fatal(got)
	}
}

func TestEmitSampleNamesEvent(t *testing.T) {
	rec := &sink.Recorder{}
	EmitSample(rec, "mongodb", "query.sample", "INFO", map[string]any{"ms": 5}, map[string]string{"db.namespace": "shop"}, time.Now())
	s := rec.Samples[0]
	if s.Attrs["event.name"] != "db.query.sample" || s.Attrs["db.system.name"] != "mongodb" || s.Attrs["db.namespace"] != "shop" || s.Body != `{"ms":5}` {
		t.Fatalf("%+v", s)
	}
}
