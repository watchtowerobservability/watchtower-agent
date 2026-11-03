package integrations

// Cloud snapshot age (INF-027): the newest completed EBS snapshot of a volume (EC2
// DescribeSnapshots) or the newest available RDS snapshot of an instance (DescribeDBSnapshots),
// signed with SigV4 using the agent's own AWS credentials. Requests only go to the regional AWS
// endpoint built here; no endpoint is configurable, so the credentials cannot be sent elsewhere.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

const (
	maxSnapshotPages = 10
	maxSnapshotBody  = 8 << 20
)

// Snapshot names one volume or instance whose snapshots are watched.
type Snapshot struct {
	Name     string `json:"name"`
	Provider string `json:"provider"` // aws_ebs or aws_rds
	Region   string `json:"region"`
	Resource string `json:"resource"` // vol-... or the DB instance identifier
	MaxAge   string `json:"max_age"`
}

var (
	regionRe   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	resourceRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
)

func (s Snapshot) check() error {
	if s.Name == "" || (s.Provider != "aws_ebs" && s.Provider != "aws_rds") {
		return errors.New("backup: snapshots need name and provider aws_ebs or aws_rds")
	}
	if !regionRe.MatchString(s.Region) || !resourceRe.MatchString(s.Resource) {
		return errors.New("backup: snapshot region or resource is malformed")
	}
	return nil
}

type snapshotClient struct {
	hc *http.Client
	// endpoint builds the regional URL; tests point it at a local server.
	endpoint func(service, region string) string
	unsigned bool // tests only: a local server needs no signature
}

func newSnapshotClient() *snapshotClient {
	return &snapshotClient{
		hc:       netguard.Guarded("agent", 30*time.Second),
		endpoint: func(service, region string) string { return "https://" + service + "." + region + ".amazonaws.com/" },
	}
}

type ebsResp struct {
	Items []struct {
		Status    string  `xml:"status"`
		StartTime string  `xml:"startTime"`
		Size      float64 `xml:"volumeSize"` // GiB
	} `xml:"snapshotSet>item"`
	NextToken string `xml:"nextToken"`
}

type rdsResp struct {
	Items []struct {
		Status     string  `xml:"Status"`
		CreateTime string  `xml:"SnapshotCreateTime"`
		Storage    float64 `xml:"AllocatedStorage"` // GiB
	} `xml:"DescribeDBSnapshotsResult>DBSnapshots>DBSnapshot"`
	Marker string `xml:"DescribeDBSnapshotsResult>Marker"`
}

func (c *snapshotClient) get(ctx context.Context, service, region string, q url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(service, region)+"?"+q.Encode(), nil)
	if err != nil {
		return errors.New("backup: bad snapshot request")
	}
	if !c.unsigned {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return errors.New("backup: aws credentials unavailable")
		}
		cr, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return errors.New("backup: aws credentials unavailable")
		}
		empty := sha256.Sum256(nil)
		if v4.NewSigner().SignHTTP(ctx, cr, req, hex.EncodeToString(empty[:]), service, region, time.Now()) != nil {
			return errors.New("backup: sigv4 signing failed")
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return errors.New("backup: snapshot request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backup: %s HTTP %d", service, resp.StatusCode)
	}
	return xml.NewDecoder(io.LimitReader(resp.Body, maxSnapshotBody)).Decode(v)
}

func newer(cur time.Time, s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !t.After(cur) {
		return cur
	}
	return t
}

func (c *snapshotClient) emit(ctx context.Context, out sink.Sink, s Snapshot, now time.Time) error {
	var last time.Time
	var size float64
	switch s.Provider {
	case "aws_ebs":
		q := url.Values{"Action": {"DescribeSnapshots"}, "Version": {"2016-11-15"}, "Owner.1": {"self"},
			"Filter.1.Name": {"volume-id"}, "Filter.1.Value.1": {s.Resource}}
		for range maxSnapshotPages {
			var r ebsResp
			if err := c.get(ctx, "ec2", s.Region, q, &r); err != nil {
				return err
			}
			for _, it := range r.Items {
				if it.Status == "completed" {
					if t := newer(last, it.StartTime); t != last {
						last, size = t, it.Size*(1<<30)
					}
				}
			}
			if r.NextToken == "" {
				break
			}
			q.Set("NextToken", r.NextToken)
		}
	case "aws_rds":
		q := url.Values{"Action": {"DescribeDBSnapshots"}, "Version": {"2014-10-31"}, "DBInstanceIdentifier": {s.Resource}}
		for range maxSnapshotPages {
			var r rdsResp
			if err := c.get(ctx, "rds", s.Region, q, &r); err != nil {
				return err
			}
			for _, it := range r.Items {
				if it.Status == "available" {
					if t := newer(last, it.CreateTime); t != last {
						last, size = t, it.Storage*(1<<30)
					}
				}
			}
			if r.Marker == "" {
				break
			}
			q.Set("Marker", r.Marker)
		}
	}
	emitBackup(out, map[string]string{"backup.name": s.Name, "backup.kind": s.Provider + "_snapshot", "backup.target": s.Resource},
		last, size, maxAge(s.MaxAge), now)
	return nil
}
