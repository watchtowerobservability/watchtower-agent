package cloud

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxInventory = 5_000 // resources per walk: the export buffer holds about 8 MiB
	maxTags      = 20    // tags kept per resource
)

// Tagged is one resource from the Resource Groups Tagging API.
type Tagged struct {
	ARN  string
	Tags map[string]string
}

func listTagged(ctx context.Context, c *resourcegroupstaggingapi.Client) ([]Tagged, error) {
	var out []Tagged
	p := resourcegroupstaggingapi.NewGetResourcesPaginator(c, &resourcegroupstaggingapi.GetResourcesInput{ResourcesPerPage: aws.Int32(100)})
	for p.HasMorePages() && len(out) < maxInventory {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, m := range page.ResourceTagMappingList {
			t := Tagged{ARN: aws.ToString(m.ResourceARN), Tags: map[string]string{}}
			for _, tag := range m.Tags {
				t.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			out = append(out, t)
		}
	}
	return out, nil
}

// ParseARN splits arn:partition:service:region:account:resource (resource keeps its colons).
func ParseARN(arn string) (service, region, account string, ok bool) {
	f := strings.SplitN(arn, ":", 6)
	if len(f) != 6 || f[0] != "arn" || f[5] == "" {
		return "", "", "", false
	}
	return f[2], f[3], f[4], true
}

// EmitInventory writes one `cloud.resource.info` gauge (value 1) per resource, carrying the
// entity resource the worker turns into an infra_entities row (kind cloud, keyed by
// cloud.resource_id). The agent host's own host.* is blanked: a cloud resource does not run on it.
// Tags become cloud.tag.<key> properties; keys are prefixed, so no tag can name a resource attribute.
func EmitInventory(out sink.Sink, rs []Tagged, at time.Time) {
	for _, r := range rs {
		svc, region, account, ok := ParseARN(r.ARN)
		if !ok {
			continue
		}
		emitResourceInfo(out, map[string]string{
			"cloud.provider": "aws", "cloud.platform": "aws_" + svc, "cloud.resource_id": r.ARN,
			"cloud.region": region, "cloud.account.id": account, "cloud.service": svc,
		}, r.Tags, at)
	}
}

// emitResourceInfo writes one `cloud.resource.info` point for res plus up to maxTags tags (as
// cloud.tag.<key>, sorted by key). Shared by the AWS, Azure and GCP inventories.
func emitResourceInfo(out sink.Sink, res, tags map[string]string, at time.Time) {
	res["host.id"], res["host.name"] = "", ""
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= maxTags {
			break
		}
		res["cloud.tag."+k] = tags[k]
	}
	out.Gauge("cloud.resource.info", "", 1, sink.Res(res), at)
}
