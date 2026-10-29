package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// fakeAWS stands in for CloudWatch (the SDK speaks a versioned wire protocol, so the double sits
// behind the poller's own interface).
type fakeAWS struct {
	mu    sync.Mutex
	calls int
	lists int
	slow  string    // namespace whose list call blocks until ctx ends
	at    time.Time // fixed datapoint timestamp, so a later poll sees the same point
}

func (f *fakeAWS) list(ctx context.Context, ns string, _ int) ([]metricRef, error) {
	f.mu.Lock()
	f.lists++
	f.mu.Unlock()
	if ns == f.slow {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []metricRef{{Namespace: ns, Name: "Invocations", Dims: []dim{{"FunctionName", "f1"}}}}, nil
}

func (f *fakeAWS) get(_ context.Context, qs []query, start, end time.Time) (map[string]point, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if !start.Before(end) {
		return nil, fmt.Errorf("bad window")
	}
	out := map[string]point{}
	for _, q := range qs {
		v := 3.0
		if q.Stat == "Sum" {
			v = 9
		}
		out[q.ID] = point{At: f.at, Value: v}
	}
	return out, nil
}

func TestCloudWatchPollerAgainstFakeAWS(t *testing.T) {
	rec := &sink.Recorder{}
	now := time.Now()
	api := &fakeAWS{slow: "AWS/Slow", at: now.Add(-10 * time.Minute)}
	p := &poller{api: api, region: "eu-west-1", max: 10, stats: []string{"Average", "Sum"}, period: 5 * time.Minute, last: map[string]time.Time{}, listed: map[string]listing{}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	p.pollNamespaces(ctx, []string{"AWS/Lambda", "AWS/Slow"}, rec, now)
	var metrics []sink.Sample // Average and Sum of the one Lambda metric; the slow namespace did not stall it
	var billed float64
	for _, s := range rec.Snapshot() {
		if s.Name == "wt_agent_cloudwatch_metric_requests" {
			billed = s.Value
		} else {
			metrics = append(metrics, s)
		}
	}
	if len(metrics) != 2 || billed != 2 {
		t.Fatalf("%+v billed=%v", metrics, billed)
	}
	for _, s := range metrics {
		if s.Name != "amazonaws.com/AWS/Lambda/Invocations" || s.Attrs["aws.dim.FunctionName"] != "f1" || s.Attrs["cloud.region"] != "eu-west-1" {
			t.Fatalf("%+v", s)
		}
	}
	// same timestamps: nothing re-sent, and the metric list comes from the 15-minute cache
	p.pollNamespaces(context.Background(), []string{"AWS/Lambda"}, rec, now.Add(time.Minute))
	if n := len(rec.Snapshot()); n != 4 { // 2 metrics + 2 request-counter samples
		t.Fatalf("duplicate emission: %d", n)
	}
	if api.lists != 2 { // Lambda once, the slow namespace once
		t.Fatalf("ListMetrics not cached: %d calls", api.lists)
	}
}

func TestInventoryEmitsCloudEntityResource(t *testing.T) {
	rec := &sink.Recorder{}
	arn := "arn:aws:lambda:eu-west-1:123456789012:function:f1"
	EmitInventory(rec, []Tagged{{ARN: arn, Tags: map[string]string{"env": "prod", "resource.evil": "x"}}, {ARN: "nonsense"}}, time.Now())
	if len(rec.Samples) != 1 {
		t.Fatalf("%+v", rec.Samples)
	}
	a := rec.Samples[0].Attrs
	if a["resource.cloud.resource_id"] != arn || a["resource.cloud.account.id"] != "123456789012" ||
		a["resource.cloud.tag.env"] != "prod" || a["resource.cloud.tag.resource.evil"] != "x" || a["resource.host.name"] != "" {
		t.Fatalf("%v", a)
	}
	for k := range a {
		if strings.HasPrefix(k, "resource.wt.") || k == "wt.entity.parent" {
			t.Fatalf("forbidden key %s", k)
		}
	}
}

func TestProcessAzureRecords(t *testing.T) {
	rec := &sink.Recorder{}
	msg := `{"records":[
	 {"time":"2026-10-28T10:00:00Z","resourceId":"/SUBSCRIPTIONS/S/RG/R","category":"AuditEvent","operationName":"Get","level":"Warning"},
	 {"time":"2026-10-28T10:00:00Z","resourceId":"/SUBSCRIPTIONS/S/RG/R","metricName":"Percentage CPU","average":12.5,"timeGrain":"PT1M"}]}`
	Process(rec, []byte(msg), time.Now())
	if len(rec.Samples) != 2 || rec.Samples[0].Sev != "WARN" || rec.Samples[1].Value != 12.5 ||
		rec.Samples[1].Attrs["resource.cloud.resource_id"] != "/subscriptions/s/rg/r" {
		t.Fatalf("%+v", rec.Samples)
	}
}

func TestEventHubConsumerAgainstLocalKafka(t *testing.T) {
	brokers := os.Getenv("WT_KAFKA")
	if brokers == "" {
		t.Skip("WT_KAFKA not set")
	}
	topic := fmt.Sprintf("%s.eh-%d", os.Getenv("WT_RUN_ID"), time.Now().UnixNano())
	pc, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(brokers, ",")...), kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	msg := `{"records":[{"time":"2026-10-28T10:00:00Z","resourceId":"/s/r","category":"c","level":"Error"}]}`
	if err := pc.ProduceSync(context.Background(), &kgo.Record{Topic: topic, Value: []byte(msg)}).FirstErr(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(EventHubConfig{Brokers: strings.Split(brokers, ","), Topics: []string{topic}, Group: "g-" + topic, Plaintext: true, StartAtEarliest: true})
	rec := &sink.Recorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunEventHub(ctx, cfg, rec) }()
	for ctx.Err() == nil {
		if len(rec.Snapshot()) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done
	if got := rec.Snapshot(); len(got) == 0 || got[0].Sev != "ERROR" {
		t.Fatalf("%+v", got)
	}
}
