package commands

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

const (
	extLayer  = "arn:aws:lambda:eu-west-1:123456789012:layer:watchtower-extension-x86_64:7"
	otelLayer = "arn:aws:lambda:eu-west-1:184161586896:layer:opentelemetry-nodejs:3"
	secretARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:wt-key-AbCdEf"
)

func fakeLambda(t *testing.T, cur string, put *map[string]any) *lambdaClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") || r.URL.Path != "/2015-03-31/functions/orders/configuration" {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, put)
		}
		_, _ = io.WriteString(w, cur)
	}))
	t.Cleanup(srv.Close)
	return &lambdaClient{base: srv.URL, hc: srv.Client(), creds: credentials.NewStaticCredentialsProvider("AKIA", "secret", "")}
}

func params(action string) map[string]any {
	return map[string]any{"action": action, "function": "orders", "region": "eu-west-1", "layer_arn": extLayer,
		"otel_layer_arn": otelLayer, "endpoint": "https://gw.example.com", "secret_arn": secretARN, "profiling": true}
}

func TestLambdaEnableThenDisable(t *testing.T) {
	var put map[string]any
	cur := `{"Layers":[{"Arn":"arn:aws:lambda:eu-west-1:123456789012:layer:mine:1"}],"Environment":{"Variables":{"KEEP":"1"}},"RevisionId":"rev1"}`
	c := fakeLambda(t, cur, &put)
	p, err := lambdaParse(params("enable"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.instrument(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	layers, _ := put["Layers"].([]any)
	env := put["Environment"].(map[string]any)["Variables"].(map[string]any)
	if len(layers) != 3 || env["KEEP"] != "1" || env["AWS_LAMBDA_EXEC_WRAPPER"] != "/opt/otel-instrument" ||
		env["WT_ENDPOINT"] != "https://gw.example.com" || env["WT_PROFILING"] != "1" || env["WT_INGEST_KEY"] != "extension" || put["RevisionId"] != "rev1" {
		t.Fatalf("put: %v", put)
	}

	put = nil
	cur = `{"Layers":[{"Arn":"` + extLayer + `"},{"Arn":"` + otelLayer + `"},{"Arn":"arn:aws:lambda:eu-west-1:123456789012:layer:mine:1"}],"Environment":{"Variables":{"KEEP":"1","WT_ENDPOINT":"x","AWS_LAMBDA_EXEC_WRAPPER":"/opt/otel-instrument"}}}`
	c = fakeLambda(t, cur, &put)
	p, _ = lambdaParse(params("disable"))
	if _, err := c.instrument(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	layers, _ = put["Layers"].([]any)
	env = put["Environment"].(map[string]any)["Variables"].(map[string]any)
	if len(layers) != 1 || len(env) != 1 || env["KEEP"] != "1" {
		t.Fatalf("disable left %v", put)
	}
}

func TestLambdaStatusChangesNothing(t *testing.T) {
	var put map[string]any
	c := fakeLambda(t, `{"Layers":[{"Arn":"`+extLayer+`"}],"Environment":{"Variables":{"WT_ENDPOINT":"https://gw"}}}`, &put)
	p, _ := lambdaParse(params("status"))
	msg, err := c.instrument(context.Background(), p)
	if err != nil || put != nil || !strings.Contains(msg, "watchtower layer true") {
		t.Fatalf("%q %v %v", msg, err, put)
	}
}

func TestLambdaParseRefuses(t *testing.T) {
	for name, mut := range map[string]func(map[string]any){
		"arn as function": func(a map[string]any) { a["function"] = "arn:aws:lambda:eu-west-1:1:function:x" },
		"bad region":      func(a map[string]any) { a["region"] = "mars" },
		"http endpoint":   func(a map[string]any) { a["endpoint"] = "http://gw" },
		"unversioned":     func(a map[string]any) { a["layer_arn"] = "arn:aws:lambda:eu-west-1:123456789012:layer:x" },
		"missing layer":   func(a map[string]any) { delete(a, "layer_arn") },
		"extra arg":       func(a map[string]any) { a["role"] = "x" },
	} {
		a := params("enable")
		mut(a)
		if _, err := lambdaParse(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLambdaBuiltinNeedsMatchingName(t *testing.T) {
	if err := ValidateAllowlist([]Command{{Name: "lambda_instrument", Builtin: "lambda_instrument"}}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAllowlist([]Command{{Name: "x", Builtin: "lambda_instrument"}}); err == nil {
		t.Fatal("a differently named builtin must be refused")
	}
	var _ aws.CredentialsProvider = credentials.StaticCredentialsProvider{}
}
