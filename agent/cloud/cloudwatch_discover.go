package cloud

// AWS cloud connection (CON-026): cross-account access by assuming a role with an external id,
// and `namespaces: ["auto"]`, which polls every AWS/* namespace that has metrics in the account
// and region instead of a hand-kept list.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	autoNamespaces    = "auto"
	maxAutoNamespaces = 40 // each namespace is polled concurrently, MaxMetrics per namespace
	discoverPages     = 20 // ListMetrics pages read per discovery (500 metrics each)
)

// assumeRole replaces cfg's credentials with an STS AssumeRole session on top of them.
func assumeRole(cfg *aws.Config, roleARN, externalID string) {
	if roleARN == "" {
		return
	}
	cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(*cfg), roleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "watchtower-agent"
			if externalID != "" {
				o.ExternalID = aws.String(externalID)
			}
		}))
}

func isAuto(ns []string) bool { return len(ns) == 1 && strings.EqualFold(ns[0], autoNamespaces) }

// pickNamespaces keeps the distinct AWS/* namespaces, sorted, at most maxAutoNamespaces.
func pickNamespaces(seen []string) []string {
	set := map[string]bool{}
	for _, n := range seen {
		if strings.HasPrefix(n, "AWS/") {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > maxAutoNamespaces {
		out = out[:maxAutoNamespaces]
	}
	return out
}

// nsDiscovery caches the discovered namespaces for listCacheTTL; a failed walk keeps the last list.
type nsDiscovery struct {
	cw   *cloudwatch.Client
	mu   sync.Mutex
	list []string
	at   time.Time
}

func (d *nsDiscovery) namespaces(ctx context.Context, now time.Time) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.list != nil && now.Sub(d.at) < listCacheTTL {
		return d.list
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var seen []string
	p := cloudwatch.NewListMetricsPaginator(d.cw, &cloudwatch.ListMetricsInput{RecentlyActive: "PT3H"})
	for i := 0; i < discoverPages && p.HasMorePages(); i++ {
		page, err := p.NextPage(cctx)
		if err != nil {
			break
		}
		for _, m := range page.Metrics {
			seen = append(seen, aws.ToString(m.Namespace))
		}
	}
	if ns := pickNamespaces(seen); len(ns) > 0 || d.list == nil {
		d.list, d.at = ns, now
	}
	return d.list
}
