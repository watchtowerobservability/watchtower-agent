package cloud

// AWS Step Functions execution tracing (INF-024): every interval the poller lists the
// executions of each state machine (the configured ARNs, else every STANDARD machine of the
// account; EXPRESS machines keep no history), reads the history of each execution that finished
// in the window and has not been sent yet, and ships it as one trace (executionSpans in
// stepfunctions_spans.go). Calls are SigV4-signed with the agent's own AWS credential chain and
// go only to the regional states endpoint built here. The same error is logged once until it
// changes.

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
	"regexp"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

const (
	sfnMaxPages      = 10
	sfnMaxMachines   = 100
	sfnMaxExecutions = 200
	sfnMaxBody       = 8 << 20
	sfnMaxSeen       = 50_000
)

// SFNConfig is the aws_stepfunctions module's config (agent file only).
type SFNConfig struct {
	Enabled       *bool    `json:"enabled"`
	Interval      string   `json:"interval"` // default 60s, at least 30s
	Region        string   `json:"region"`
	StateMachines []string `json:"state_machines"` // ARNs; empty: every STANDARD machine
	MaxExecutions int      `json:"max_executions"` // per machine and round, default 50
}

type sfnExecution struct {
	ExecutionArn    string  `json:"executionArn"`
	StateMachineArn string  `json:"stateMachineArn"`
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	StartDate       float64 `json:"startDate"`
	StopDate        float64 `json:"stopDate"`
}

type sfnCall func(ctx context.Context, op string, in, out any) error

type sfnPoller struct {
	cfg     SFNConfig
	call    sfnCall
	ship    func(map[string]string, []*tracepb.Span)
	out     sink.Sink
	region  string
	every   time.Duration
	seen    map[string]float64 // execution ARN -> stop date, so each is sent once
	lastErr string
}

func newSFNPoller(cfg SFNConfig, call sfnCall, ship func(map[string]string, []*tracepb.Span), out sink.Sink) *sfnPoller {
	return &sfnPoller{cfg: cfg, call: call, ship: ship, out: out, region: cfg.Region,
		every: max(host.Duration(cfg.Interval, time.Minute, 30*time.Second), 30*time.Second), seen: map[string]float64{}}
}

func machineName(arn string) string { return arn[strings.LastIndex(arn, ":")+1:] }

func (p *sfnPoller) machines(ctx context.Context) ([]string, error) {
	if len(p.cfg.StateMachines) > 0 {
		return p.cfg.StateMachines, nil
	}
	var out []string
	token := ""
	for range sfnMaxPages {
		in := map[string]any{"maxResults": 1000}
		if token != "" {
			in["nextToken"] = token
		}
		var r struct {
			StateMachines []struct {
				ARN  string `json:"stateMachineArn"`
				Type string `json:"type"`
			} `json:"stateMachines"`
			NextToken string `json:"nextToken"`
		}
		if err := p.call(ctx, "ListStateMachines", in, &r); err != nil {
			return nil, err
		}
		for _, m := range r.StateMachines {
			if m.Type != "EXPRESS" && len(out) < sfnMaxMachines {
				out = append(out, m.ARN)
			}
		}
		if token = r.NextToken; token == "" {
			break
		}
	}
	return out, nil
}

func (p *sfnPoller) history(ctx context.Context, arn string) ([]sfnEvent, error) {
	var events []sfnEvent
	token := ""
	for range sfnMaxPages {
		in := map[string]any{"executionArn": arn, "maxResults": 1000, "includeExecutionData": false}
		if token != "" {
			in["nextToken"] = token
		}
		var page struct {
			Events    []sfnEvent `json:"events"`
			NextToken string     `json:"nextToken"`
		}
		if err := p.call(ctx, "GetExecutionHistory", in, &page); err != nil {
			return nil, err
		}
		events = append(events, page.Events...)
		if token = page.NextToken; token == "" {
			break
		}
	}
	return events, nil
}

func (p *sfnPoller) report(err error, now time.Time) {
	if err == nil {
		p.lastErr = ""
		return
	}
	if msg := err.Error(); msg != p.lastErr && p.out != nil {
		p.lastErr = msg
		p.out.Log("WARN", "step functions pull failed: "+msg, map[string]string{"cloud.provider": "aws", "aws.service": "states"}, now)
	}
}

// poll sends every execution that stopped within the last two intervals and was not sent yet.
func (p *sfnPoller) poll(ctx context.Context, now time.Time) {
	from := float64(now.Add(-2*p.every).UnixNano()) / 1e9
	for arn, stop := range p.seen {
		if stop < from || len(p.seen) > sfnMaxSeen {
			delete(p.seen, arn)
		}
	}
	limit := p.cfg.MaxExecutions
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, sfnMaxExecutions)
	ms, err := p.machines(ctx)
	if err != nil {
		p.report(err, now)
		return
	}
	var first error
	for _, m := range ms {
		var list struct {
			Executions []sfnExecution `json:"executions"`
		}
		if err := p.call(ctx, "ListExecutions", map[string]any{"stateMachineArn": m, "maxResults": 100}, &list); err != nil {
			first = cmpFirst(first, err)
			continue
		}
		res := map[string]string{"service.name": machineName(m), "cloud.provider": "aws",
			"cloud.platform": "aws_step_functions", "cloud.region": p.region}
		n := 0
		for _, x := range list.Executions {
			if _, done := p.seen[x.ExecutionArn]; done || x.Status == "RUNNING" || x.StopDate < from || n >= limit {
				continue
			}
			n++
			events, err := p.history(ctx, x.ExecutionArn)
			if err != nil {
				first = cmpFirst(first, err)
				continue
			}
			if x.StateMachineArn == "" {
				x.StateMachineArn = m
			}
			if x.Name == "" {
				x.Name = machineName(x.ExecutionArn)
			}
			p.ship(res, executionSpans(x, events))
			p.seen[x.ExecutionArn] = x.StopDate
		}
	}
	p.report(first, now)
}

func cmpFirst(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

// sfnHTTP is the real call: AWS JSON 1.0 over HTTPS, SigV4 with the default credential chain.
func sfnHTTP(region string) sfnCall {
	hc := netguard.Guarded("agent", 30*time.Second)
	endpoint := "https://states." + region + ".amazonaws.com/"
	return func(ctx context.Context, op string, in, out any) error {
		body, err := json.Marshal(in)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("stepfunctions: bad request")
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", "AWSStepFunctions."+op)
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return errors.New("stepfunctions: aws credentials unavailable")
		}
		cr, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return errors.New("stepfunctions: aws credentials unavailable")
		}
		sum := sha256.Sum256(body)
		if v4.NewSigner().SignHTTP(ctx, cr, req, hex.EncodeToString(sum[:]), "states", region, time.Now()) != nil {
			return errors.New("stepfunctions: sigv4 signing failed")
		}
		resp, err := hc.Do(req)
		if err != nil {
			return errors.New("stepfunctions: request failed")
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, sfnMaxBody))
		if err != nil {
			return errors.New("stepfunctions: read failed")
		}
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Type string `json:"__type"`
			}
			_ = json.Unmarshal(b, &e)
			return fmt.Errorf("stepfunctions %s: HTTP %d %s", op, resp.StatusCode, e.Type[strings.LastIndex(e.Type, "#")+1:])
		}
		return json.Unmarshal(b, out)
	}
}

var (
	sfnRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	sfnARN    = regexp.MustCompile(`^arn:aws[a-z-]*:states:[a-z0-9-]+:\d{12}:stateMachine:[A-Za-z0-9_-]{1,80}$`)
)

// RunStepFunctions polls until ctx ends. It does nothing unless the local config sets
// enabled: true and a region.
func RunStepFunctions(ctx context.Context, raw json.RawMessage, out sink.Sink, ship func(map[string]string, []*tracepb.Span)) error {
	var c SFNConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("aws_stepfunctions config: %w", err)
		}
	}
	if c.Enabled == nil || !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	if !sfnRegion.MatchString(c.Region) {
		return errors.New("aws_stepfunctions: region is required")
	}
	if len(c.StateMachines) > sfnMaxMachines {
		return errors.New("aws_stepfunctions: too many state machines")
	}
	for _, m := range c.StateMachines {
		if !sfnARN.MatchString(m) {
			return errors.New("aws_stepfunctions: state_machines must be state machine ARNs")
		}
	}
	p := newSFNPoller(c, sfnHTTP(c.Region), ship, out)
	t := time.NewTicker(p.every)
	defer t.Stop()
	for {
		p.poll(ctx, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
