package main

// Per-target outbound HTTP proxy (`http_proxy`, `no_proxy`) and AWS role assumption for sigv4
// (`role_arn`, `external_id`) on `forward:` targets (CON-023). The proxy URL may carry
// credentials as a `${provider:ref}` secret reference; the destination host is still checked
// against the agent's egress policy before the request goes to the proxy.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// noProxyMatch reports whether host bypasses the proxy: "*", an exact host, or a domain that
// matches itself and its subdomains (a leading dot is optional).
func noProxyMatch(host string, list []string) bool {
	host = strings.ToLower(host)
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		d := strings.TrimPrefix(e, ".")
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// forwardClient is the target's HTTP client: the guarded agent client, routed through the
// target's proxy when one is set.
func forwardClient(ctx context.Context, t ForwardTarget) (*http.Client, error) {
	if t.Proxy == "" {
		return netguard.GuardedNoRedirect("agent", exportTimeout), nil
	}
	raw, err := resolveRef(ctx, t.Proxy)
	if err != nil {
		return nil, err
	}
	pu, err := url.Parse(raw)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return nil, errors.New("forward: http_proxy must be an http(s) URL")
	}
	pol := netguard.FromEnv("agent")
	proxy := func(r *http.Request) (*url.URL, error) {
		host := r.URL.Hostname()
		if !pol.HostAllowed(host) {
			return nil, &netguard.ErrEgressDenied{Host: host, Purpose: "agent"}
		}
		if noProxyMatch(host, t.NoProxy) {
			return nil, nil
		}
		return pu, nil
	}
	c := netguard.NewClientWith(pol, netguard.Options{}, func(tr *http.Transport) { tr.Proxy = proxy })
	c.Timeout = exportTimeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

// awsCreds caches the sigv4 credential provider of one target: the default chain, or an STS
// AssumeRole on top of it when role_arn is set. A failed load is retried on the next request.
type awsCreds struct {
	mu   sync.Mutex
	prov aws.CredentialsProvider
}

func (a *awsCreds) get(ctx context.Context, s *ForwardSigV4) (aws.Credentials, error) {
	a.mu.Lock()
	if a.prov == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(s.Region))
		if err != nil {
			a.mu.Unlock()
			return aws.Credentials{}, errors.New("aws credentials unavailable")
		}
		a.prov = cfg.Credentials
		if s.RoleARN != "" {
			a.prov = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), s.RoleARN,
				func(o *stscreds.AssumeRoleOptions) {
					o.RoleSessionName = "watchtower-agent"
					if s.ExternalID != "" {
						o.ExternalID = aws.String(s.ExternalID)
					}
				}))
		}
	}
	p := a.prov
	a.mu.Unlock()
	if p == nil {
		return aws.Credentials{}, errors.New("aws credentials unavailable")
	}
	return p.Retrieve(ctx)
}
