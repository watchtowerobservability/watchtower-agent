package commands

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// BuiltinLambdaInstrument is the Lambda remote-instrumentation command: it attaches (or detaches)
// the Watchtower extension layer, an optional OpenTelemetry language layer and the matching
// environment of one function through the Lambda API (GetFunctionConfiguration, then
// UpdateFunctionConfiguration). It runs with the agent's own AWS credential chain, so what it may
// change is bounded by that role's IAM policy (lambda:GetFunctionConfiguration and
// lambda:UpdateFunctionConfiguration on the functions to manage). The operator opts in with
// `builtin: lambda_instrument` in the agent's `commands:`; as with every command, the fleet server
// delivers it only after the action run is approved.
const BuiltinLambdaInstrument = "lambda_instrument"

var (
	lambdaName   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	lambdaRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	lambdaLayer  = regexp.MustCompile(`^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:layer:[A-Za-z0-9_-]{1,64}:\d+$`)
	lambdaSecret = regexp.MustCompile(`^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`)
	lambdaURL    = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$`)
)

// LambdaInstrumentSchema is the argument schema of the command.
func LambdaInstrumentSchema() Schema {
	s := func(max int) Prop { return Prop{Type: "string", MaxLength: max} }
	return Schema{
		Required: []string{"action", "function", "region"},
		Properties: map[string]Prop{
			"action":         {Type: "string", Enum: []string{"enable", "disable", "status"}},
			"function":       s(64),
			"region":         s(32),
			"layer_arn":      s(256), // the Watchtower extension layer (enable)
			"otel_layer_arn": s(256), // the OpenTelemetry layer of the function's language (optional)
			"endpoint":       s(256), // WT_ENDPOINT, the gateway base URL (enable)
			"secret_arn":     s(512), // WT_API_KEY_SECRET_ARN (enable)
			"profiling":      {Type: "boolean"},
		},
	}
}

type lambdaParams struct {
	action, function, region, layer, otelLayer, endpoint, secret string
	profiling                                                    bool
}

func lambdaParse(a map[string]any) (p lambdaParams, err error) {
	if err = Validate(LambdaInstrumentSchema(), a); err != nil {
		return p, err
	}
	str := func(k string) string { s, _ := a[k].(string); return s }
	p = lambdaParams{str("action"), str("function"), str("region"), str("layer_arn"), str("otel_layer_arn"), str("endpoint"), str("secret_arn"), a["profiling"] == true}
	switch {
	case !lambdaName.MatchString(p.function):
		return p, errors.New("function must be a function name, not an ARN")
	case !lambdaRegion.MatchString(p.region):
		return p, errors.New("region is not an AWS region")
	case p.layer != "" && !lambdaLayer.MatchString(p.layer), p.otelLayer != "" && !lambdaLayer.MatchString(p.otelLayer):
		return p, errors.New("layer ARNs must be versioned Lambda layer ARNs")
	case p.secret != "" && !lambdaSecret.MatchString(p.secret):
		return p, errors.New("secret_arn must be a Secrets Manager secret ARN")
	case p.endpoint != "" && !lambdaURL.MatchString(p.endpoint):
		return p, errors.New("endpoint must be an https URL")
	case p.action == "enable" && (p.layer == "" || p.endpoint == "" || p.secret == ""):
		return p, errors.New("enable needs layer_arn, endpoint and secret_arn")
	}
	return p, nil
}

// lambdaClient is the Lambda REST API, SigV4-signed.
type lambdaClient struct {
	base  string
	creds aws.CredentialsProvider
	hc    *http.Client
}

type lambdaConfig struct {
	Layers      []struct{ Arn string } `json:"Layers"`
	Environment struct {
		Variables map[string]string `json:"Variables"`
	} `json:"Environment"`
	RevisionID string `json:"RevisionId"`
}

func (c *lambdaClient) do(ctx context.Context, method, region, fn string, body []byte, out any) error {
	u := c.base + "/2015-03-31/functions/" + url.PathEscape(fn) + "/configuration"
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("lambda: bad request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cr, err := c.creds.Retrieve(ctx)
	if err != nil {
		return errors.New("lambda: aws credentials unavailable")
	}
	sum := sha256.Sum256(body)
	if v4.NewSigner().SignHTTP(ctx, cr, req, hex.EncodeToString(sum[:]), "lambda", region, time.Now()) != nil {
		return errors.New("lambda: sigv4 signing failed")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return errors.New("lambda: request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Type string `json:"Type"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("lambda %s: HTTP %d %s", method, resp.StatusCode, e.Type)
	}
	return json.Unmarshal(b, out)
}

// lambdaEnv is what enable sets, and disable removes.
func lambdaEnv(p lambdaParams) map[string]string {
	env := map[string]string{
		"WT_ENDPOINT":                 p.endpoint,
		"WT_API_KEY_SECRET_ARN":       p.secret,
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
	}
	if p.otelLayer != "" {
		env["AWS_LAMBDA_EXEC_WRAPPER"] = "/opt/otel-instrument"
	}
	if p.profiling {
		// the Node, Python, Java and Go profilers all start from this flag; they post to the extension, which adds the key
		env["WT_PROFILING"] = "1"
		env["WT_OTLP_ENDPOINT"] = "http://localhost:4318"
		env["WT_INGEST_KEY"] = "extension"
	}
	return env
}

// lambdaDisableKeys are removed on disable whatever the args said.
var lambdaDisableKeys = []string{"WT_ENDPOINT", "WT_API_KEY_SECRET_ARN", "OTEL_EXPORTER_OTLP_ENDPOINT", "AWS_LAMBDA_EXEC_WRAPPER", "WT_PROFILING"}

// Instrument applies p to the function and returns a one-line summary.
func (c *lambdaClient) instrument(ctx context.Context, p lambdaParams) (string, error) {
	var cur lambdaConfig
	if err := c.do(ctx, http.MethodGet, p.region, p.function, nil, &cur); err != nil {
		return "", err
	}
	layers := make([]string, 0, len(cur.Layers)+2)
	for _, l := range cur.Layers {
		layers = append(layers, l.Arn)
	}
	env := cur.Environment.Variables
	if env == nil {
		env = map[string]string{}
	}
	has := func(arn string) bool { return arn != "" && slices.Contains(layers, arn) }
	switch p.action {
	case "status":
		return fmt.Sprintf("function %s: watchtower layer %t, endpoint %q, profiling %t", p.function, has(p.layer), env["WT_ENDPOINT"], env["WT_PROFILING"] == "1"), nil
	case "enable":
		for _, a := range []string{p.layer, p.otelLayer} {
			if a != "" && !has(a) {
				layers = append(layers, a)
			}
		}
		for k, v := range lambdaEnv(p) {
			env[k] = v
		}
	case "disable":
		layers = slices.DeleteFunc(layers, func(a string) bool { return a == p.layer || a == p.otelLayer })
		for _, k := range lambdaDisableKeys {
			delete(env, k)
		}
		if env["WT_OTLP_ENDPOINT"] == "http://localhost:4318" { // only what enable set
			delete(env, "WT_OTLP_ENDPOINT")
		}
		if env["WT_INGEST_KEY"] == "extension" {
			delete(env, "WT_INGEST_KEY")
		}
	}
	if len(layers) > 5 {
		return "", errors.New("a function holds at most 5 layers")
	}
	body, _ := json.Marshal(map[string]any{"Layers": layers, "Environment": map[string]any{"Variables": env}, "RevisionId": cur.RevisionID})
	var out lambdaConfig
	if err := c.do(ctx, http.MethodPut, p.region, p.function, body, &out); err != nil {
		return "", err
	}
	return fmt.Sprintf("function %s: %s applied, %d layer(s)", p.function, p.action, len(out.Layers)), nil
}

// runLambdaInstrument is the command: real credentials, regional endpoint.
func runLambdaInstrument(ctx context.Context, args map[string]any) (Output, error) {
	p, err := lambdaParse(args)
	if err != nil {
		return Output{}, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(p.region))
	if err != nil {
		return Output{}, errors.New("lambda: aws credentials unavailable")
	}
	c := &lambdaClient{base: "https://lambda." + p.region + ".amazonaws.com", creds: cfg.Credentials, hc: netguard.Guarded("agent", 30*time.Second)}
	msg, err := c.instrument(ctx, p)
	if err != nil {
		return Output{}, err
	}
	return Output{Stdout: msg + "\n"}, nil
}
