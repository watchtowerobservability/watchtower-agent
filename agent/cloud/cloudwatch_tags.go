package cloud

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
)

const tagIndexTTL = 5 * time.Minute

// listTaggedBy lists the resources that match every tag filter (the API ANDs keys and ORs the
// values of one key).
func listTaggedBy(ctx context.Context, c *resourcegroupstaggingapi.Client, filters map[string][]string) ([]Tagged, error) {
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	in := &resourcegroupstaggingapi.GetResourcesInput{ResourcesPerPage: aws.Int32(100)}
	for _, k := range keys {
		in.TagFilters = append(in.TagFilters, rgtypes.TagFilter{Key: aws.String(k), Values: filters[k]})
	}
	var out []Tagged
	p := resourcegroupstaggingapi.NewGetResourcesPaginator(c, in)
	for p.HasMorePages() && len(out) < maxInventory {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, m := range page.ResourceTagMappingList {
			out = append(out, Tagged{ARN: aws.ToString(m.ResourceARN)})
		}
	}
	return out, nil
}

// ResourceID is the part of an ARN a CloudWatch dimension carries: what follows the last ':' or
// '/' of the resource part (function:orders -> orders, instance/i-0abc -> i-0abc).
func ResourceID(arn string) string {
	if i := strings.LastIndexAny(arn, ":/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// tagIndex is the set of resource ids that match the tag filters, refreshed every tagIndexTTL.
// If it cannot be loaded and nothing was loaded before, no metric is polled (fail closed: the
// filter is a scoping control, so an outage must not widen it).
type tagIndex struct {
	load func(context.Context) ([]Tagged, error)

	mu  sync.Mutex
	ids map[string]bool
	exp time.Time
}

func (x *tagIndex) idSet(ctx context.Context, now time.Time) map[string]bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.ids == nil || !now.Before(x.exp) {
		rs, err := x.load(ctx)
		host.Warn("aws tag filter", err)
		if err == nil || len(rs) > 0 || x.ids == nil {
			ids := make(map[string]bool, len(rs))
			for _, r := range rs {
				ids[ResourceID(r.ARN)] = true
			}
			x.ids = ids
		}
		x.exp = now.Add(tagIndexTTL)
	}
	return x.ids
}

// filter keeps the metrics with a dimension value that is a tagged resource id. A nil index
// keeps everything.
func (x *tagIndex) filter(ctx context.Context, refs []metricRef, now time.Time) []metricRef {
	if x == nil {
		return refs
	}
	ids := x.idSet(ctx, now)
	out := make([]metricRef, 0, len(refs))
	for _, r := range refs {
		for _, d := range r.Dims {
			if ids[d.Value] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
