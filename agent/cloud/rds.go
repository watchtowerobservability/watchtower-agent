package cloud

// Managed database discovery. DBDiscovery lists AWS RDS/Aurora, Azure SQL/Flexible Server and GCP
// Cloud SQL, and emits each database as a `cloud.resource.info` entity (kind cloud).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Entity is one discovered database: resource attributes, tags as cloud.tag.<key>.
type Entity struct{ Attrs map[string]string }

// DBConfig lists the providers to discover. Credentials live in the sealed local agent config.
type DBConfig struct {
	AWS      *rdsConfig      `json:"aws"`
	Azure    *azureDBConfig  `json:"azure"`
	GCP      *cloudSQLConfig `json:"gcp"`
	Interval string          `json:"interval"` // default 10m, floor 1m
}

type rdsConfig struct {
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"` // test double / VPC endpoint
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"` // empty = SDK default chain
}

const (
	rdsVersion  = "2014-10-31"
	maxDBPages  = 50
	dbDiscEvery = 10 * time.Minute
)

type rdsTag struct{ Key, Value string }

type rdsItem struct {
	ID      string   `xml:"DBInstanceIdentifier"`
	Cluster string   `xml:"DBClusterIdentifier"`
	Engine  string   `xml:"Engine"`
	Version string   `xml:"EngineVersion"`
	ARN     string   `xml:"DBInstanceArn"`
	CARN    string   `xml:"DBClusterArn"`
	Tags    []rdsTag `xml:"TagList>Tag"`
}

type rdsPage struct {
	Instances []rdsItem `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	Clusters  []rdsItem `xml:"DescribeDBClustersResult>DBClusters>DBCluster"`
	Marker    string    `xml:"DescribeDBInstancesResult>Marker"`
	CMarker   string    `xml:"DescribeDBClustersResult>Marker"`
}

// dbSystem maps an RDS engine name to the OTel db.system value.
func dbSystem(engine string) string {
	e := strings.ToLower(engine)
	switch {
	case strings.Contains(e, "postgres"):
		return "postgresql"
	case strings.Contains(e, "mariadb"):
		return "mariadb"
	case strings.Contains(e, "mysql"):
		return "mysql"
	case strings.HasPrefix(e, "sqlserver"):
		return "mssql"
	case strings.HasPrefix(e, "oracle"):
		return "oracle"
	}
	return e
}

func (c *rdsConfig) credentials(ctx context.Context) (aws.CredentialsProvider, error) {
	if c.AccessKeyID != "" && c.SecretAccessKey != "" {
		return credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), nil
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	return cfg.Credentials, nil
}

// call sends one SigV4-signed RDS Query API request and decodes the XML answer.
func (c *rdsConfig) call(ctx context.Context, cp aws.CredentialsProvider, action, marker string) (*rdsPage, error) {
	form := url.Values{"Action": {action}, "Version": {rdsVersion}, "MaxRecords": {"100"}}
	if marker != "" {
		form.Set("Marker", marker)
	}
	body := form.Encode()
	ep := c.Endpoint
	if ep == "" {
		ep = "https://rds." + c.Region + ".amazonaws.com/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("bad rds endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	creds, err := cp.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	sum := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "rds", c.Region, time.Now()); err != nil {
		return nil, errors.New("sigv4 signing failed")
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, errors.New("rds request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxPullBody))
	if resp.StatusCode >= 300 {
		return nil, errors.New("rds http " + resp.Status)
	}
	var p rdsPage
	if err := xml.Unmarshal(b, &p); err != nil {
		return nil, errors.New("malformed rds response")
	}
	return &p, nil
}

func (c *rdsConfig) discover(ctx context.Context) ([]Entity, error) {
	cp, err := c.credentials(ctx)
	if err != nil {
		return nil, err
	}
	var out []Entity
	for _, action := range []string{"DescribeDBInstances", "DescribeDBClusters"} {
		marker := ""
		for range maxDBPages {
			p, err := c.call(ctx, cp, action, marker)
			if err != nil {
				return nil, err
			}
			items, next := p.Instances, p.Marker
			if action == "DescribeDBClusters" {
				items, next = p.Clusters, p.CMarker
			}
			for _, it := range items {
				id, arn, kind := it.ID, it.ARN, "instance"
				if action == "DescribeDBClusters" {
					id, arn, kind = it.Cluster, it.CARN, "cluster"
				}
				tags := map[string]string{}
				for _, t := range it.Tags {
					tags[t.Key] = t.Value
				}
				out = append(out, dbEntity("aws", c.Region, arn, "aws_rds_"+kind, id, dbSystem(it.Engine), it.Engine, it.Version, tags))
			}
			if next == "" {
				break
			}
			marker = next
		}
	}
	return out, nil
}

func dbEntity(provider, region, id, platform, name, system, engine, version string, tags map[string]string) Entity {
	a := map[string]string{
		"cloud.provider": provider, "cloud.platform": platform, "cloud.region": region, "cloud.resource_id": id,
		"db.system": system, "db.engine": engine, "db.version": version, "service.name": name,
		"host.id": "", "host.name": "", // a managed database does not run on the agent host
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= maxTags {
			break
		}
		a["cloud.tag."+k] = tags[k]
	}
	return Entity{Attrs: a}
}

// DBDiscovery remembers the last good answer per provider: a failed refresh keeps it.
type DBDiscovery struct {
	cfg  DBConfig
	mu   sync.Mutex
	last map[string][]Entity
}

// NewDBDiscovery returns a discoverer for cfg.
func NewDBDiscovery(cfg DBConfig) *DBDiscovery {
	return &DBDiscovery{cfg: cfg, last: map[string][]Entity{}}
}

// Discover refreshes every configured provider and returns all known databases.
func (d *DBDiscovery) Discover(ctx context.Context) []Entity {
	d.mu.Lock()
	defer d.mu.Unlock()
	run := map[string]func(context.Context) ([]Entity, error){}
	if d.cfg.AWS != nil {
		run["aws"] = d.cfg.AWS.discover
	}
	if d.cfg.Azure != nil {
		run["azure"] = d.cfg.Azure.discover
	}
	if d.cfg.GCP != nil {
		run["gcp"] = d.cfg.GCP.discover
	}
	var all []Entity
	for _, name := range []string{"aws", "azure", "gcp"} {
		f, ok := run[name]
		if !ok {
			continue
		}
		es, err := f(ctx)
		if err != nil {
			host.Warn("db discovery "+name, err)
			es = d.last[name]
		}
		d.last[name] = es
		all = append(all, es...)
	}
	return all
}

// DiscoverDatabases does one discovery pass with no memory of earlier passes.
func DiscoverDatabases(ctx context.Context, cfg DBConfig) []Entity {
	return NewDBDiscovery(cfg).Discover(ctx)
}

// EmitEntities writes one `cloud.resource.info` gauge per entity.
func EmitEntities(out sink.Sink, es []Entity, at time.Time) {
	for _, e := range es {
		out.Gauge("cloud.resource.info", "", 1, sink.Res(e.Attrs), at)
	}
}

// RunDBDiscovery refreshes every 10 minutes until ctx ends.
func RunDBDiscovery(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c DBConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return errors.New("database discovery config: malformed")
	}
	out = sink.Hoist(out)
	d := NewDBDiscovery(c)
	host.Every(ctx, host.Duration(c.Interval, dbDiscEvery, time.Minute), func(ctx context.Context) {
		cctx, cancel := context.WithTimeout(ctx, 2*callTimeout)
		defer cancel()
		EmitEntities(out, d.Discover(cctx), time.Now())
	})
	return nil
}
