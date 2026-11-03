package virt

// vSphere datastores (INF-032): capacity, free, uncommitted (thin-provisioned promise) and
// accessibility per datastore, and read/write latency per host and datastore. Each datastore is
// an entity of kind datastore (datastore.id/name/type on the resource). A datastore is shared by
// many hosts, so its resource blanks host.*: no host parent, and the agent's own host identity
// is not borrowed.

import (
	"context"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// dsLatency maps the host counters (instance = datastore uuid) to metrics, in milliseconds.
var dsLatency = map[string]string{
	"datastore.totalReadLatency.average":  "vsphere.datastore.latency.read",
	"datastore.totalWriteLatency.average": "vsphere.datastore.latency.write",
}

// dsUUID is the last path element of a datastore url (ds:///vmfs/volumes/<uuid>/), the instance
// name the host datastore counters use.
func dsUUID(u string) string {
	u = strings.TrimRight(u, "/")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return ""
}

// datastoreRes is the resource of one datastore entity.
func datastoreRes(target string, d mo.Datastore) map[string]string {
	return sink.Res(map[string]string{
		"datastore.id": target + "/" + d.Reference().Value, "datastore.name": d.Summary.Name,
		"datastore.type": d.Summary.Type, "host.name": "", "host.id": "", "os.type": "",
	})
}

func pollDatastores(ctx context.Context, c *govmomi.Client, m *view.Manager, target string, hosts []mo.HostSystem, out sink.Sink, at time.Time) error {
	dv, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"Datastore"}, true)
	if err != nil {
		return err
	}
	defer func() { _ = dv.Destroy(context.WithoutCancel(ctx)) }()
	var dss []mo.Datastore
	if err := dv.Retrieve(ctx, []string{"Datastore"}, []string{"name", "summary", "overallStatus"}, &dss); err != nil {
		return err
	}
	byUUID := map[string]map[string]string{}
	for _, d := range dss {
		s := d.Summary
		res := datastoreRes(target, d)
		capacity, free := float64(s.Capacity), float64(s.FreeSpace)
		out.Gauge("vsphere.datastore.capacity", "By", capacity, res, at)
		out.Gauge("vsphere.datastore.free", "By", free, res, at)
		out.Gauge("vsphere.datastore.usage", "By", capacity-free, res, at)
		out.Gauge("vsphere.datastore.uncommitted", "By", float64(s.Uncommitted), res, at)
		if capacity > 0 {
			out.Gauge("vsphere.datastore.utilization", "%", (capacity-free)/capacity*100, res, at)
			// provisioned = used + uncommitted; above 100 % the datastore is overcommitted
			out.Gauge("vsphere.datastore.provisioned.utilization", "%", (capacity-free+float64(s.Uncommitted))/capacity*100, res, at)
		}
		out.Gauge("vsphere.datastore.accessible", "1", upGauge(s.Accessible), sink.With(res, "vsphere.status", string(d.OverallStatus)), at)
		if u := dsUUID(s.Url); u != "" {
			byUUID[u] = res
		}
	}
	host.Warn("vsphere "+target+" datastore latency", datastoreLatency(ctx, c, hosts, byUUID, out, at))
	return nil
}

// datastoreLatency reads one real-time sample of the per-datastore latency of every host. It is
// best effort: a vCenter without these counters still reports capacity.
func datastoreLatency(ctx context.Context, c *govmomi.Client, hosts []mo.HostSystem, byUUID map[string]map[string]string, out sink.Sink, at time.Time) error {
	if len(hosts) == 0 || len(byUUID) == 0 {
		return nil
	}
	refs := make([]types.ManagedObjectReference, 0, len(hosts))
	hostName := map[types.ManagedObjectReference]string{}
	for _, h := range hosts {
		refs = append(refs, h.Reference())
		hostName[h.Reference()] = h.Name
	}
	pm := performance.NewManager(c.Client)
	names := make([]string, 0, len(dsLatency))
	for n := range dsLatency {
		names = append(names, n)
	}
	raw, err := pm.SampleByName(ctx, types.PerfQuerySpec{MaxSample: 1, IntervalId: 20}, names, refs)
	if err != nil {
		return err
	}
	ems, err := pm.ToMetricSeries(ctx, raw)
	if err != nil {
		return err
	}
	for _, em := range ems {
		for _, s := range em.Value {
			res, ok := byUUID[s.Instance]
			metric := dsLatency[s.Name]
			if !ok || metric == "" || len(s.Value) == 0 {
				continue
			}
			out.Gauge(metric, "ms", float64(s.Value[len(s.Value)-1]), sink.With(res, "vsphere.host", hostName[em.Entity]), at)
		}
	}
	return nil
}
