package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func find(r *sink.Recorder, name string, want map[string]string) (float64, bool) {
next:
	for _, s := range r.Snapshot() {
		if s.Name != name {
			continue
		}
		for k, v := range want {
			if s.Attrs[k] != v {
				continue next
			}
		}
		return s.Value, true
	}
	return 0, false
}

// SQS and Kinesis through the real AWS SDK against a CloudWatch double: ListMetrics names the
// queues and streams, GetMetricData answers a value per metric.
func TestSQSAndKinesisFeedTheQueuesArea(t *testing.T) {
	values := map[string]float64{
		"ApproximateNumberOfMessagesVisible":    42,
		"ApproximateNumberOfMessagesNotVisible": 6,
		"ApproximateAgeOfOldestMessage":         95,
		"GetRecords.IteratorAgeMilliseconds":    8000,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "text/xml")
		const ns = `xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/"`
		switch f.Get("Action") {
		case "ListMetrics":
			var m strings.Builder
			for _, n := range []string{"ApproximateNumberOfMessagesVisible", "ApproximateNumberOfMessagesNotVisible", "ApproximateAgeOfOldestMessage"} {
				fmt.Fprintf(&m, `<member><Namespace>AWS/SQS</Namespace><MetricName>%s</MetricName><Dimensions><member><Name>QueueName</Name><Value>orders-dlq</Value></member></Dimensions></member>`, n)
			}
			if f.Get("Namespace") == "AWS/Kinesis" {
				m.Reset()
				m.WriteString(`<member><Namespace>AWS/Kinesis</Namespace><MetricName>GetRecords.IteratorAgeMilliseconds</MetricName><Dimensions><member><Name>StreamName</Name><Value>clicks</Value></member></Dimensions></member>`)
			}
			fmt.Fprintf(w, `<ListMetricsResponse %s><ListMetricsResult><Metrics>%s</Metrics></ListMetricsResult></ListMetricsResponse>`, ns, m.String())
		case "GetMetricData":
			var res strings.Builder
			for i := 1; f.Get(fmt.Sprintf("MetricDataQueries.member.%d.Id", i)) != ""; i++ {
				p := fmt.Sprintf("MetricDataQueries.member.%d.", i)
				fmt.Fprintf(&res, `<member><Id>%s</Id><Label>x</Label><StatusCode>Complete</StatusCode><Timestamps><member>2026-10-30T10:00:00Z</member></Timestamps><Values><member>%v</member></Values></member>`,
					f.Get(p+"Id"), values[f.Get(p+"MetricStat.Metric.MetricName")])
			}
			fmt.Fprintf(w, `<GetMetricDataResponse %s><GetMetricDataResult><MetricDataResults>%s</MetricDataResults></GetMetricDataResult></GetMetricDataResponse>`, ns, res.String())
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	cw := cloudwatch.New(cloudwatch.Options{Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), HTTPClient: srv.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")})
	p := &poller{api: sdkCW{c: cw, period: 300}, region: "eu-west-1", max: 50, stats: []string{"Maximum"}, period: 5 * time.Minute,
		last: map[string]time.Time{}, listed: map[string]listing{}}
	rec := &sink.Recorder{}
	p.pollNamespaces(context.Background(), []string{"AWS/SQS", "AWS/Kinesis"}, sink.QueueContract(rec), time.Date(2026, 10, 30, 10, 30, 0, 0, time.UTC))
	q := map[string]string{"queue": "orders-dlq", "framework": "sqs"}
	for state, want := range map[string]float64{"ready": 42, "unacked": 6} {
		if v, ok := find(rec, "messaging.queue.depth", map[string]string{"queue": "orders-dlq", "framework": "sqs", "state": state}); !ok || v != want {
			t.Errorf("sqs %s depth = %v %v, want %v", state, v, ok, want)
		}
	}
	if v, ok := find(rec, "messaging.queue.oldest_age_seconds", q); !ok || v != 95 {
		t.Errorf("sqs age = %v %v", v, ok)
	}
	if v, ok := find(rec, "messaging.consumer.lag_seconds", map[string]string{"queue": "clicks", "framework": "kinesis"}); !ok || v != 8 {
		t.Errorf("kinesis lag = %v %v (iterator age 8000 ms)", v, ok)
	}
}

// Service Bus: the namespace is asked for one series per entity, and each becomes a queue.
func TestServiceBusEntitiesFeedTheQueuesArea(t *testing.T) {
	var filter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			fmt.Fprint(w, `{"access_token":"az1","expires_in":3600}`)
		case strings.Contains(r.URL.Path, "/providers/microsoft.insights/metrics"):
			filter = r.URL.Query().Get("$filter")
			fmt.Fprint(w, `{"value":[
			 {"name":{"value":"ActiveMessages"},"unit":"Count","timeseries":[
			  {"metadatavalues":[{"name":{"value":"entityname"},"value":"invoices"}],"data":[{"timeStamp":"2026-10-30T10:00:00Z","average":17}]}]},
			 {"name":{"value":"DeadletteredMessages"},"unit":"Count","timeseries":[
			  {"metadatavalues":[{"name":{"value":"entityname"},"value":"invoices"}],"data":[{"timeStamp":"2026-10-30T10:00:00Z","average":2}]}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"tenant_id":"t1","client_id":"c1","client_secret":"shh","presets":["azure_service_bus"],
		"resources":["/subscriptions/sub1/resourceGroups/g/providers/Microsoft.ServiceBus/namespaces/bus1"],
		"login_endpoint":%q,"endpoint":%q}`, srv.URL, srv.URL)
	p, err := newAzure(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "azure")); err != nil {
		t.Fatal(err)
	}
	if filter != "EntityName eq '*'" {
		t.Fatalf("the namespace must be split by entity, $filter=%q", filter)
	}
	for state, want := range map[string]float64{"ready": 17, "dead": 2} {
		if v, ok := find(rec, "messaging.queue.depth", map[string]string{"queue": "invoices", "framework": "servicebus", "state": state}); !ok || v != want {
			t.Errorf("service bus %s depth = %v %v, want %v", state, v, ok, want)
		}
	}
}

// Pub/Sub: the subscription is named on the monitored resource, not on the metric.
func TestPubSubSubscriptionsFeedTheQueuesArea(t *testing.T) {
	_, pemKey := testKeyPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			fmt.Fprint(w, `{"access_token":"tok1","expires_in":3600}`)
		case strings.HasPrefix(r.URL.Path, "/v3/projects/proj1/timeSeries"):
			fmt.Fprint(w, `{"timeSeries":[
			 {"metric":{"type":"pubsub.googleapis.com/subscription/num_undelivered_messages"},"resource":{"type":"pubsub_subscription","labels":{"subscription_id":"orders-sub"}},
			  "points":[{"interval":{"endTime":"2026-10-30T10:00:00Z"},"value":{"int64Value":"31"}}]},
			 {"metric":{"type":"pubsub.googleapis.com/subscription/oldest_unacked_message_age"},"resource":{"type":"pubsub_subscription","labels":{"subscription_id":"orders-sub"}},
			  "points":[{"interval":{"endTime":"2026-10-30T10:00:00Z"},"value":{"int64Value":"120"}}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"project":"proj1","metrics":["pubsub.googleapis.com/subscription/num_undelivered_messages"],
		"endpoint":%q,"service_account":{"client_email":"sa@p.iam","private_key":%q,"token_uri":%q}}`, srv.URL, pemKey, srv.URL+"/token")
	p, err := newGCP(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "gcp")); err != nil {
		t.Fatal(err)
	}
	if v, ok := find(rec, "messaging.queue.depth", map[string]string{"queue": "orders-sub", "framework": "pubsub", "state": "ready"}); !ok || v != 31 {
		t.Errorf("pubsub depth = %v %v", v, ok)
	}
	if v, ok := find(rec, "messaging.queue.oldest_age_seconds", map[string]string{"queue": "orders-sub", "framework": "pubsub"}); !ok || v != 120 {
		t.Errorf("pubsub age = %v %v", v, ok)
	}
}
