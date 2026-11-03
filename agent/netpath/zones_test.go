package netpath

import (
	"context"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestZonesStampSourceAndDestination(t *testing.T) {
	var rec sink.Recorder
	ts := []Target{{Name: "db", Host: "10.0.0.5", Zone: "eu/data"}, {Name: "web", Host: "10.0.1.5"}}
	Once(context.Background(), fake, ts, withZones(&rec, "eu/app", ts), time.Now())
	var db, web int
	for _, s := range rec.Samples {
		if s.Attrs["path.src_zone"] != "eu/app" {
			t.Fatalf("no source zone: %v", s.Attrs)
		}
		switch s.Attrs["path.target"] {
		case "db":
			if s.Attrs["path.dst_zone"] == "eu/data" {
				db++
			}
		case "web":
			if _, ok := s.Attrs["path.dst_zone"]; !ok {
				web++
			}
		}
	}
	if db != 3 || web != 3 {
		t.Fatalf("db %d web %d", db, web)
	}
	if withZones(&rec, "", []Target{{Name: "x"}}) != sink.Sink(&rec) {
		t.Fatal("no zones should leave the sink unwrapped")
	}
}
