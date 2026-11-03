package logs

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func frame(stream byte, s string) []byte {
	h := []byte{stream, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestDemuxSplitsStreamsAndJoinsPartialLines(t *testing.T) {
	var b bytes.Buffer
	b.Write(frame(1, "2026-10-31T10:00:00Z hel"))
	b.Write(frame(2, "2026-10-31T10:00:01Z boom\n"))
	b.Write(frame(1, "lo\n"))
	var got []string
	_ = demux(&b, func(stream, line string) { got = append(got, stream+"|"+line) })
	if len(got) != 2 || got[0] != "stderr|2026-10-31T10:00:01Z boom" || got[1] != "stdout|2026-10-31T10:00:00Z hello" {
		t.Fatalf("%q", got)
	}
}

func TestKafkaRecordUnwrapsJSONMessage(t *testing.T) {
	r := &sink.Recorder{}
	KafkaRecord(r, &kgo.Record{Topic: "app", Value: []byte(`{"message":"ERROR db down","pod":"api-1"}`), Timestamp: time.Now()})
	if len(r.Samples) != 1 || r.Samples[0].Body != "ERROR db down" || r.Samples[0].Attrs["pod"] != "api-1" || r.Samples[0].Attrs["messaging.destination.name"] != "app" {
		t.Fatalf("%+v", r.Samples)
	}
}
