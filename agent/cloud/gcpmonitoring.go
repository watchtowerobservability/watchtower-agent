package cloud

// GCP Cloud Monitoring pull: REST timeSeries.list with a service-account JWT built from the
// standard library (RS256), exchanged at the token endpoint for a short-lived access token.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	gcpScope    = "https://www.googleapis.com/auth/monitoring.read"
	gcpTokenURI = "https://oauth2.googleapis.com/token"
	gcpEndpoint = "https://monitoring.googleapis.com"
	gcpMaxPages = 20
)

type gcpConfig struct {
	Project        string   `json:"project"`
	Metrics        []string `json:"metrics"` // metric types, e.g. compute.googleapis.com/instance/cpu/utilization
	Presets        []string `json:"presets"` // named metric sets added to metrics: cloud_run, pubsub
	Region         string   `json:"region"`
	Endpoint       string   `json:"endpoint"` // override (tests, private service connect)
	ServiceAccount struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	} `json:"service_account"`
	// Inventory lists assets with Cloud Asset Inventory (gcp_assets.go).
	Inventory *gcpInventory `json:"inventory"`
}

type gcpPull struct {
	c      gcpConfig
	key    *rsa.PrivateKey
	cl     *http.Client
	tok    tokenCache
	assets gcpAssetCache
}

func newGCP(raw json.RawMessage) (puller, error) {
	var c gcpConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("gcp config: malformed")
	}
	c.Metrics = expandPresets(gcpPresets, c.Metrics, c.Presets)
	if c.Project == "" || (len(c.Metrics) == 0 && c.Inventory == nil) || c.ServiceAccount.ClientEmail == "" {
		return nil, errors.New("gcp config: project, metrics or inventory, and service_account are required")
	}
	if c.Inventory != nil {
		if err := c.Inventory.check(c.Project); err != nil {
			return nil, err
		}
	}
	key, err := parseRSAKey(c.ServiceAccount.PrivateKey)
	if err != nil {
		return nil, err
	}
	if c.Endpoint == "" {
		c.Endpoint = gcpEndpoint
	}
	if c.ServiceAccount.TokenURI == "" {
		c.ServiceAccount.TokenURI = gcpTokenURI
	}
	return &gcpPull{c: c, key: key, cl: httpClient()}, nil
}

func parseRSAKey(p string) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, errors.New("gcp config: private_key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("gcp config: private_key is not RSA")
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("gcp config: private_key unreadable")
	}
	return k, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// gcpJWT builds the RS256 assertion for the OAuth jwt-bearer grant.
func gcpJWT(key *rsa.PrivateKey, email, aud string, now time.Time) (string, error) {
	return gcpJWTScope(key, email, aud, gcpScope, now)
}

func gcpJWTScope(key *rsa.PrivateKey, email, aud, scope string, now time.Time) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": email, "scope": scope, "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	in := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("jwt signing failed")
	}
	return in + "." + b64(sig), nil
}

func (g *gcpPull) token(ctx context.Context, now time.Time) (string, error) {
	return g.tok.get(now, func() (string, time.Duration, error) {
		jwt, err := gcpJWT(g.key, g.c.ServiceAccount.ClientEmail, g.c.ServiceAccount.TokenURI, now)
		if err != nil {
			return "", 0, err
		}
		return tokenForm(ctx, g.cl, g.c.ServiceAccount.TokenURI, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt},
		})
	})
}

type gcpSeries struct {
	Metric struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"metric"`
	Resource struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Points []struct {
		Interval struct {
			EndTime time.Time `json:"endTime"`
		} `json:"interval"`
		Value struct {
			Double       *float64 `json:"doubleValue"`
			Int64        string   `json:"int64Value"`
			Distribution *struct {
				Mean float64 `json:"mean"`
			} `json:"distributionValue"`
		} `json:"value"`
	} `json:"points"`
}

// gcpName maps "compute.googleapis.com/instance/cpu/utilization" to
// "cloud.gcp.compute.instance.cpu.utilization".
func gcpName(metricType string) string {
	svc, rest, _ := strings.Cut(metricType, "/")
	svc, _, _ = strings.Cut(svc, ".")
	return "cloud.gcp." + svc + "." + strings.ReplaceAll(rest, "/", ".")
}

func (g *gcpPull) pull(ctx context.Context, from, to time.Time, e *emitter) error {
	projects := []string{g.c.Project}
	if g.c.Inventory != nil {
		found, err := g.discovered(ctx, to, e.out)
		if err != nil {
			// Reported, not returned: the metric window must keep moving.
			e.out.Log("WARN", "gcp asset inventory: "+err.Error(), map[string]string{"cloud.provider": "gcp"}, to)
		}
		projects = found
	}
	if len(g.c.Metrics) == 0 {
		return nil
	}
	tok, err := g.token(ctx, to)
	if err != nil {
		return err
	}
	for i, project := range projects {
		if err := g.pullProject(ctx, project, tok, from, to, e); err != nil && i == 0 {
			return err // a discovered project the account cannot read must not stop the rest
		}
	}
	return nil
}

func (g *gcpPull) pullProject(ctx context.Context, project, tok string, from, to time.Time, e *emitter) error {
	for _, mt := range g.c.Metrics {
		page := ""
		for range gcpMaxPages {
			q := url.Values{
				"filter":             {`metric.type="` + mt + `"`},
				"interval.startTime": {from.UTC().Format(time.RFC3339)},
				"interval.endTime":   {to.UTC().Format(time.RFC3339)},
			}
			if page != "" {
				q.Set("pageToken", page)
			}
			var r struct {
				TimeSeries    []gcpSeries `json:"timeSeries"`
				NextPageToken string      `json:"nextPageToken"`
			}
			u := g.c.Endpoint + "/v3/projects/" + url.PathEscape(project) + "/timeSeries?" + q.Encode()
			if err := doJSON(ctx, g.cl, "GET", u, map[string]string{"Authorization": "Bearer " + tok}, nil, &r); err != nil {
				return err
			}
			g.emitFor(e, &r.TimeSeries, project)
			if page = r.NextPageToken; page == "" {
				break
			}
		}
	}
	return nil
}

func (g *gcpPull) emit(e *emitter, ts *[]gcpSeries) { g.emitFor(e, ts, g.c.Project) }

func (g *gcpPull) emitFor(e *emitter, ts *[]gcpSeries, project string) {
	for i := range *ts {
		s := &(*ts)[i]
		res := map[string]string{"cloud.account.id": project, "cloud.region": g.c.Region}
		for _, k := range []string{"instance_id", "service_name", "job_name", "function_name", "database_id", "cluster_name"} {
			if v := s.Resource.Labels[k]; v != "" {
				res["cloud.resource_id"] = v
				break
			}
		}
		if z := s.Resource.Labels["zone"]; z != "" && g.c.Region == "" {
			res["cloud.region"] = z
		}
		cloudRunResource(s.Resource.Type, s.Resource.Labels, res)
		attrs := map[string]string{"gcp.resource_type": s.Resource.Type}
		for _, k := range []string{"subscription_id", "topic_id"} { // Pub/Sub names the queue on the resource
			if v := s.Resource.Labels[k]; v != "" {
				attrs["gcp.resource."+k] = v
			}
		}
		for k, v := range s.Metric.Labels {
			attrs["gcp.label."+k] = v
		}
		for _, p := range s.Points {
			var v float64
			switch {
			case p.Value.Double != nil:
				v = *p.Value.Double
			case p.Value.Int64 != "":
				n, err := strconv.ParseFloat(p.Value.Int64, 64)
				if err != nil {
					continue
				}
				v = n
			case p.Value.Distribution != nil:
				v = p.Value.Distribution.Mean
			default:
				continue
			}
			e.gauge(gcpName(s.Metric.Type), "", v, p.Interval.EndTime, res, attrs)
		}
	}
}
