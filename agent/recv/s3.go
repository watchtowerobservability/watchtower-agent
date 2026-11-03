package recv

// `s3_otlp` (CFT-A11, otelcol awss3 receiver parity): replays OTLP files an archive wrote to a
// bucket (the OTel awss3exporter layout: .json = otlp_json, .binpb = otlp_proto, optionally
// .gz) into Watchtower. Objects are read in key order after the last one done; that key is kept
// in the state dir, so a restart resumes (at-least-once: an object cut off mid-send is resent).
// Credentials come from the AWS default chain; endpoint may name an S3-compatible store.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// S3Config selects the archive.
type S3Config struct {
	Bucket   string `json:"bucket"`
	Region   string `json:"region"`
	Prefix   string `json:"prefix"`
	Signal   string `json:"signal"`   // traces, metrics or logs
	Endpoint string `json:"endpoint"` // S3-compatible base URL (path-style); default AWS
	Interval string `json:"interval"` // default 60s
}

// SendRaw posts one OTLP protobuf body to /v1/<signal>.
type SendRaw func(ctx context.Context, path string, body []byte) error

func emptyMsg(signal string) proto.Message {
	switch signal {
	case "traces":
		return &coltrace.ExportTraceServiceRequest{}
	case "metrics":
		return &colmetrics.ExportMetricsServiceRequest{}
	case "logs":
		return &collogs.ExportLogsServiceRequest{}
	}
	return nil
}

// Decode turns one archived object into OTLP protobuf bytes.
func Decode(key string, body []byte, signal string) ([]byte, error) {
	if strings.HasSuffix(key, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if body, err = io.ReadAll(io.LimitReader(zr, 64<<20)); err != nil {
			return nil, err
		}
		key = strings.TrimSuffix(key, ".gz")
	}
	m := emptyMsg(signal)
	switch {
	case strings.HasSuffix(key, ".binpb"):
		if err := proto.Unmarshal(body, m); err != nil {
			return nil, fmt.Errorf("%s: not OTLP protobuf", key)
		}
	case strings.HasSuffix(key, ".json"):
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, m); err != nil {
			return nil, fmt.Errorf("%s: not OTLP JSON", key)
		}
	default:
		return nil, nil // not an OTLP file: skipped
	}
	return proto.Marshal(m)
}

type s3Lister struct {
	c    S3Config
	hc   *http.Client
	base string
}

func (s *s3Lister) do(ctx context.Context, u string) ([]byte, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(s.c.Region))
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	empty := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(empty[:]))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(empty[:]), "s3", s.c.Region, time.Now()); err != nil {
		return nil, errors.New("sigv4 signing failed")
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, errors.New("s3 unreachable")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("s3: HTTP %d", resp.StatusCode)
	}
	return b, nil
}

func (s *s3Lister) list(ctx context.Context, after string) ([]string, error) {
	q := url.Values{"list-type": {"2"}, "max-keys": {"200"}, "prefix": {s.c.Prefix}}
	if after != "" {
		q.Set("start-after", after)
	}
	b, err := s.do(ctx, s.base+"/?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var r struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil, errors.New("s3: malformed list")
	}
	keys := make([]string, 0, len(r.Contents))
	for _, c := range r.Contents {
		keys = append(keys, c.Key)
	}
	return keys, nil
}

func objectPath(key string) string {
	parts := strings.Split(key, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return "/" + strings.Join(parts, "/")
}

// RunS3 replays the archive until ctx ends.
func RunS3(ctx context.Context, raw json.RawMessage, stateDir string, send SendRaw) error {
	var c S3Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("s3_otlp: %w", err)
	}
	if c.Bucket == "" || c.Region == "" || emptyMsg(c.Signal) == nil {
		return errors.New("s3_otlp: bucket, region and signal (traces, metrics or logs) are required")
	}
	every, err := interval(c.Interval, time.Minute)
	if err != nil {
		return fmt.Errorf("s3_otlp: %w", err)
	}
	s := &s3Lister{c: c, hc: netguard.Guarded("agent", 60*time.Second), base: "https://" + c.Bucket + ".s3." + c.Region + ".amazonaws.com"}
	if c.Endpoint != "" {
		s.base = strings.TrimRight(c.Endpoint, "/") + "/" + url.PathEscape(c.Bucket)
	}
	state := filepath.Join(stateDir, "s3-otlp-"+c.Bucket+"-"+c.Signal+".last")
	last := ""
	if b, err := os.ReadFile(state); err == nil {
		last = strings.TrimSpace(string(b))
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		keys, err := s.list(ctx, last)
		if err != nil {
			slog.Warn("s3_otlp: list failed", "error", err)
		}
		for _, k := range keys {
			obj, err := s.do(ctx, s.base+objectPath(k))
			if err != nil {
				slog.Warn("s3_otlp: object not read", "error", err)
				break
			}
			body, err := Decode(k, obj, c.Signal)
			if err != nil {
				slog.Warn("s3_otlp: object skipped", "error", err)
			} else if body != nil {
				if err := send(ctx, "/v1/"+c.Signal, body); err != nil {
					slog.Warn("s3_otlp: send failed, retrying next round", "error", err)
					break
				}
			}
			last = k
			_ = os.WriteFile(state, []byte(last), 0o600)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
