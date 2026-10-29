package cloud

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// TestCloudWatchGetMetricDataWire runs the real AWS SDK against an httptest server and checks the
// SigV4 header shape, the Query-protocol request body and the XML response parse.
func TestCloudWatchGetMetricDataWire(t *testing.T) {
	var auth string
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<GetMetricDataResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/"><GetMetricDataResult>
<MetricDataResults><member><Id>q0</Id><Label>CPUUtilization</Label><StatusCode>Complete</StatusCode>
<Timestamps><member>2026-10-30T10:05:00Z</member><member>2026-10-30T10:00:00Z</member></Timestamps>
<Values><member>42.5</member><member>40</member></Values></member></MetricDataResults>
</GetMetricDataResult></GetMetricDataResponse>`)
	}))
	defer srv.Close()
	cw := cloudwatch.New(cloudwatch.Options{
		Region: "eu-west-1", BaseEndpoint: aws.String(srv.URL), HTTPClient: srv.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
	})
	api := sdkCW{c: cw, period: 300}
	end := time.Date(2026, 10, 30, 10, 10, 0, 0, time.UTC)
	got, err := api.get(context.Background(), []query{{
		ID: "q0", Stat: "Average",
		Ref: metricRef{Namespace: "AWS/RDS", Name: "CPUUtilization", Dims: []dim{{"DBInstanceIdentifier", "db1"}}},
	}}, end.Add(-10*time.Minute), end)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/\d{8}/eu-west-1/monitoring/aws4_request, SignedHeaders=[a-z0-9;-]*host[a-z0-9;-]*, Signature=[0-9a-f]{64}$`)
	if !re.MatchString(auth) {
		t.Fatalf("authorization header shape: %q", auth)
	}
	const m = "MetricDataQueries.member.1.MetricStat."
	for k, want := range map[string]string{
		"Action":                               "GetMetricData",
		"MetricDataQueries.member.1.Id":        "q0",
		m + "Stat":                             "Average",
		m + "Period":                           "300",
		m + "Metric.Namespace":                 "AWS/RDS",
		m + "Metric.MetricName":                "CPUUtilization",
		m + "Metric.Dimensions.member.1.Name":  "DBInstanceIdentifier",
		m + "Metric.Dimensions.member.1.Value": "db1",
		"ScanBy":                               "TimestampDescending",
	} {
		if form.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, form.Get(k), want)
		}
	}
	if !strings.HasPrefix(form.Get("StartTime"), "2026-10-30T10:00:00") {
		t.Errorf("StartTime = %q", form.Get("StartTime"))
	}
	p, ok := got["q0"]
	if !ok || p.Value != 42.5 || !p.At.Equal(time.Date(2026, 10, 30, 10, 5, 0, 0, time.UTC)) {
		t.Fatalf("latest point not parsed: %+v", got)
	}
}
