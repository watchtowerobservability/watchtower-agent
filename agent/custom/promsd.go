package custom

// Prometheus-style service discovery for the scrape module (ING-014): http_sd, dns_sd, consul_sd
// and ec2_sd, hashmod agent sharding, and staleness markers for targets that vanish or fail.
// SD configs can only come from the agent's own config file (Overlay rejects them from remote
// config) because they name URLs the agent would fetch.

import (
	"context"
	"crypto/md5" //nolint:gosec // hashmod sharding is defined on MD5 by Prometheus; not a security use
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"gopkg.in/yaml.v3"
)

const (
	sdEveryDefault = time.Minute
	sdMaxBody      = 5 << 20
	sdMaxPages     = 20
)

// SDConfig is one discovery source. Type is http, dns, consul or ec2.
type SDConfig struct {
	Type    string `json:"type"`
	Refresh string `json:"refresh_interval"` // default 1m, 5s to 1h
	// URL is the http_sd document or the consul HTTP API base (http://127.0.0.1:8500).
	URL string `json:"url"`
	// Scheme and Path shape the scrape URL for dns, consul and ec2 targets (http, /metrics).
	Scheme string `json:"scheme"`
	Path   string `json:"path"`
	// dns: Names to resolve, RecordType A, AAAA or SRV; Port is required for A and AAAA.
	Names      []string `json:"names"`
	RecordType string   `json:"record_type"`
	Port       int      `json:"port"`
	// consul: Services to scrape (empty: every service), Datacenter and ACL Token optional.
	Services   []string `json:"services"`
	Datacenter string   `json:"datacenter"`
	Token      string   `json:"token"`
	// ec2: Region, optional static keys (else the SDK default chain), Endpoint for tests, Filters
	// such as {"tag:env": "prod"}; Port is the exporter port (default 9100). Only running instances.
	Region          string            `json:"region"`
	AccessKeyID     string            `json:"access_key_id"`
	SecretAccessKey string            `json:"secret_access_key"`
	Endpoint        string            `json:"endpoint"`
	Filters         map[string]string `json:"filters"`
}

func (c SDConfig) scrapeURL(host string, port int) string {
	scheme, path := c.Scheme, c.Path
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/metrics"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path
}

// discover runs the source once.
func (c SDConfig) discover(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	switch c.Type {
	case "http":
		return c.httpSD(ctx, hc)
	case "dns":
		return c.dnsSD(ctx)
	case "consul":
		return c.consulSD(ctx, hc)
	case "ec2":
		return c.ec2SD(ctx, hc)
	}
	return nil, fmt.Errorf("unknown sd type %q", c.Type)
}

func (c SDConfig) validate() error {
	switch c.Type {
	case "http", "consul":
		if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("sd %s: url must be http(s)", c.Type)
		}
	case "dns":
		if len(c.Names) == 0 {
			return errors.New("sd dns: names required")
		}
		if t := strings.ToUpper(c.RecordType); t != "SRV" && c.Port <= 0 {
			return errors.New("sd dns: port required for A and AAAA")
		}
	case "ec2":
		if c.Region == "" && c.Endpoint == "" {
			return errors.New("sd ec2: region required")
		}
	default:
		return fmt.Errorf("unknown sd type %q", c.Type)
	}
	return nil
}

func getBody(ctx context.Context, hc *http.Client, u string, hdr map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sd %s: status %d", redact(u), resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, sdMaxBody))
}

func (c SDConfig) httpSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	b, err := getBody(ctx, hc, c.URL, nil)
	if err != nil {
		return nil, err
	}
	var groups []fileGroup
	if err := yaml.Unmarshal(b, &groups); err != nil {
		return nil, fmt.Errorf("sd %s: %w", redact(c.URL), err)
	}
	return groupSpecs(groups), nil
}

func (c SDConfig) dnsSD(ctx context.Context) ([]TargetSpec, error) {
	var out []TargetSpec
	r := net.DefaultResolver
	for _, name := range c.Names {
		labels := map[string]string{"dns_name": name}
		switch strings.ToUpper(c.RecordType) {
		case "SRV":
			_, srv, err := r.LookupSRV(ctx, "", "", name)
			if err != nil {
				return nil, err
			}
			for _, s := range srv {
				out = append(out, TargetSpec{URL: c.scrapeURL(strings.TrimSuffix(s.Target, "."), int(s.Port)), Labels: labels})
			}
		default:
			network := "ip4"
			if strings.ToUpper(c.RecordType) == "AAAA" {
				network = "ip6"
			}
			ips, err := r.LookupIP(ctx, network, name)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				out = append(out, TargetSpec{URL: c.scrapeURL(ip.String(), c.Port), Labels: labels})
			}
		}
	}
	return out, nil
}

type consulEntry struct {
	Node           string
	Address        string
	ServiceAddress string
	ServiceName    string
	ServicePort    int
	ServiceTags    []string
	Datacenter     string
}

func (c SDConfig) consulSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	base := strings.TrimSuffix(c.URL, "/")
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["X-Consul-Token"] = c.Token
	}
	dc := ""
	if c.Datacenter != "" {
		dc = "?dc=" + url.QueryEscape(c.Datacenter)
	}
	services := c.Services
	if len(services) == 0 {
		b, err := getBody(ctx, hc, base+"/v1/catalog/services"+dc, hdr)
		if err != nil {
			return nil, err
		}
		var m map[string][]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("sd consul: %w", err)
		}
		for s := range m {
			services = append(services, s)
		}
		sort.Strings(services)
	}
	var out []TargetSpec
	for _, svc := range services {
		b, err := getBody(ctx, hc, base+"/v1/catalog/service/"+url.PathEscape(svc)+dc, hdr)
		if err != nil {
			return nil, err
		}
		var entries []consulEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, fmt.Errorf("sd consul: %w", err)
		}
		for _, e := range entries {
			host := e.ServiceAddress
			if host == "" {
				host = e.Address
			}
			if host == "" || e.ServicePort <= 0 {
				continue
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(host, e.ServicePort), Labels: map[string]string{
				"consul_service": svc, "consul_node": e.Node, "consul_datacenter": e.Datacenter,
				"consul_tags": "," + strings.Join(e.ServiceTags, ",") + ",",
			}})
		}
	}
	return out, nil
}

type ec2Page struct {
	Next         string `xml:"nextToken"`
	Reservations []struct {
		Instances []struct {
			ID    string `xml:"instanceId"`
			IP    string `xml:"privateIpAddress"`
			State struct {
				Name string `xml:"name"`
			} `xml:"instanceState"`
			AZ struct {
				Name string `xml:"availabilityZone"`
			} `xml:"placement"`
			Tags []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"instancesSet>item"`
	} `xml:"reservationSet>item"`
}

func (c SDConfig) awsCreds(ctx context.Context) (aws.CredentialsProvider, error) {
	if c.AccessKeyID != "" && c.SecretAccessKey != "" {
		return credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, ""), nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.Region))
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	return cfg.Credentials, nil
}

func (c SDConfig) ec2SD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	cp, err := c.awsCreds(ctx)
	if err != nil {
		return nil, err
	}
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	keys := make([]string, 0, len(c.Filters))
	for k := range c.Filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []TargetSpec
	token := ""
	for range sdMaxPages {
		form := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "MaxResults": {"500"},
			"Filter.1.Name": {"instance-state-name"}, "Filter.1.Value.1": {"running"}}
		for i, k := range keys {
			form.Set(fmt.Sprintf("Filter.%d.Name", i+2), k)
			form.Set(fmt.Sprintf("Filter.%d.Value.1", i+2), c.Filters[k])
		}
		if token != "" {
			form.Set("NextToken", token)
		}
		p, err := c.ec2Call(ctx, hc, cp, form)
		if err != nil {
			return nil, err
		}
		for _, r := range p.Reservations {
			for _, in := range r.Instances {
				if in.IP == "" || in.State.Name != "running" {
					continue
				}
				labels := map[string]string{"ec2_instance_id": in.ID, "ec2_az": in.AZ.Name}
				for _, t := range in.Tags {
					labels["ec2_tag_"+t.Key] = t.Value
				}
				out = append(out, TargetSpec{URL: c.scrapeURL(in.IP, port), Labels: labels})
			}
		}
		if token = p.Next; token == "" {
			break
		}
	}
	return out, nil
}

func (c SDConfig) ec2Call(ctx context.Context, hc *http.Client, cp aws.CredentialsProvider, form url.Values) (*ec2Page, error) {
	ep := c.Endpoint
	if ep == "" {
		ep = "https://ec2." + c.Region + ".amazonaws.com/"
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("bad ec2 endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	creds, err := cp.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("aws credentials unavailable")
	}
	sum := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "ec2", c.Region, time.Now()); err != nil {
		return nil, errors.New("sigv4 signing failed")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, errors.New("ec2 request failed")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, sdMaxBody))
	if resp.StatusCode >= 300 {
		return nil, errors.New("ec2 http " + resp.Status)
	}
	var p ec2Page
	if err := xml.Unmarshal(b, &p); err != nil {
		return nil, errors.New("malformed ec2 response")
	}
	return &p, nil
}

// inShard reports whether this agent owns the target: md5(url) mod total == index (Prometheus
// hashmod), so N agents given the same SD config split the targets with no coordination.
// total <= 1 keeps everything.
func inShard(targetURL string, total, index int) bool {
	if total <= 1 {
		return true
	}
	sum := md5.Sum([]byte(targetURL))                                      //nolint:gosec
	return binary.BigEndian.Uint64(sum[8:])%uint64(total) == uint64(index) //nolint:gosec // total > 1
}

// markStale tells the backend a target's series have ended (it was removed or stopped answering):
// `wt_scrape_up` 0 and `wt_scrape_stale` 1, which queries use to cut the line instead of
// carrying the last value forward.
func markStale(out Sink, spec TargetSpec, now time.Time) {
	a := map[string]string{"target": redact(spec.URL)}
	out.Gauge("wt_scrape_up", "", 0, a, now)
	out.Gauge("wt_scrape_stale", "", 1, a, now)
}

// watchSource polls list every `every`, starting new targets and stopping (with a staleness
// marker) the ones that left. A failing poll keeps the targets already running.
func (p Prometheus) watchSource(ctx context.Context, every time.Duration, fixed, total, index int, list func(context.Context) ([]TargetSpec, error), out Sink) {
	running := map[string]context.CancelFunc{}
	specs := map[string]TargetSpec{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if found, err := list(ctx); err == nil {
			want := map[string]TargetSpec{}
			for _, s := range found {
				if len(want)+fixed < maxTargets && inShard(s.URL, total, index) {
					want[s.URL+"|"+fmt.Sprint(s.Labels)] = s
				}
			}
			for k, cancel := range running {
				if _, ok := want[k]; !ok {
					cancel()
					markStale(out, specs[k], time.Now())
					delete(running, k)
					delete(specs, k)
				}
			}
			for k, s := range want {
				if _, ok := running[k]; !ok {
					cctx, cancel := context.WithCancel(ctx)
					running[k], specs[k] = cancel, s
					go p.loop(cctx, s, out)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// startSD validates the sd_configs and starts one watcher each.
func (p Prometheus) startSD(ctx context.Context, c PromConfig, out Sink) error {
	hc := p.Client
	if hc == nil {
		hc = netguard.GuardedNoRedirect("agent", 0)
	}
	for _, sd := range c.SDConfigs {
		if err := sd.validate(); err != nil {
			return err
		}
		go p.watchSource(ctx, parseDur(sd.Refresh, sdEveryDefault, minInterval, time.Hour), len(c.Targets), c.ShardTotal, c.ShardIndex,
			func(ctx context.Context) ([]TargetSpec, error) { return sd.discover(ctx, hc) }, out)
	}
	return nil
}
