package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MBeanRead is one Jolokia read: an MBean (a `*` pattern is allowed) and the attributes to read.
type MBeanRead struct {
	MBean      string   `json:"mbean"`
	Attributes []string `json:"attributes"`
}

// JolokiaConfig is the jmx and activemq config: the Jolokia agent's URL (for example
// http://host:8778/jolokia) and, for jmx, the reads to make (a JVM default is used when empty).
type JolokiaConfig struct {
	HTTPConfig
	Reads []MBeanRead `json:"reads"`
}

func (c *JolokiaConfig) check() error {
	if err := c.HTTPConfig.check(); err != nil {
		return err
	}
	for _, r := range c.Reads {
		if r.MBean == "" || len(r.Attributes) == 0 {
			return errors.New("every read needs an mbean and attributes")
		}
	}
	return nil
}

var jvmReads = []MBeanRead{
	{MBean: "java.lang:type=Memory", Attributes: []string{"HeapMemoryUsage", "NonHeapMemoryUsage"}},
	{MBean: "java.lang:type=Threading", Attributes: []string{"ThreadCount", "DaemonThreadCount", "PeakThreadCount"}},
	{MBean: "java.lang:type=OperatingSystem", Attributes: []string{"ProcessCpuLoad", "SystemLoadAverage", "OpenFileDescriptorCount"}},
	{MBean: "java.lang:type=ClassLoading", Attributes: []string{"LoadedClassCount"}},
	{MBean: "java.lang:type=GarbageCollector,name=*", Attributes: []string{"CollectionCount", "CollectionTime"}},
}

// activemqReads is the queue topology: depth, consumers, producers and throughput per queue.
var activemqReads = []MBeanRead{{
	MBean:      "org.apache.activemq:type=Broker,brokerName=*,destinationType=Queue,destinationName=*",
	Attributes: []string{"QueueSize", "ConsumerCount", "ProducerCount", "EnqueueCount", "DequeueCount", "InFlightCount"},
}}

type jolokiaResp struct {
	Request struct {
		MBean string `json:"mbean"`
	} `json:"request"`
	Value  json.RawMessage `json:"value"`
	Status int             `json:"status"`
}

func runJolokia(ctx context.Context, name string, def []MBeanRead, raw json.RawMessage, out sink.Sink,
	emit func(sink.Sink, []jolokiaResp, time.Time),
) error {
	c := &JolokiaConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if len(c.Reads) == 0 {
		c.Reads = def
	}
	return Loop(ctx, name, c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		rs, err := jolokiaRead(ctx, c.HTTPConfig, c.Reads)
		if err != nil {
			return err
		}
		emit(out, rs, now)
		return nil
	})
}

func jolokiaRead(ctx context.Context, c HTTPConfig, reads []MBeanRead) ([]jolokiaResp, error) {
	body := make([]map[string]any, 0, len(reads))
	for _, r := range reads {
		body = append(body, map[string]any{"type": "read", "mbean": r.MBean, "attribute": r.Attributes, "ignoreErrors": true})
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jolokia: HTTP %d", resp.StatusCode)
	}
	var rs []jolokiaResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&rs); err != nil {
		return nil, fmt.Errorf("jolokia: bad response: %w", err)
	}
	return rs, nil
}

// numbers flattens a Jolokia value into dotted-key numbers (a composite attribute such as
// HeapMemoryUsage becomes HeapMemoryUsage.used).
func numbers(prefix string, v any, f func(key string, x float64)) {
	switch t := v.(type) {
	case float64:
		f(prefix, t)
	case map[string]any:
		for k, x := range t {
			numbers(prefix+"."+k, x, f)
		}
	}
}

// perMBean calls f for each (mbean, attributes) of one response: a pattern read returns
// {mbeanName: {attr: value}}, a plain read {attr: value}.
func perMBean(r jolokiaResp, f func(mbean string, attrs map[string]any)) {
	var m map[string]any
	if r.Status != http.StatusOK || json.Unmarshal(r.Value, &m) != nil {
		return
	}
	if !strings.Contains(r.Request.MBean, "*") {
		f(r.Request.MBean, m)
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a, ok := m[k].(map[string]any); ok {
			f(k, a)
		}
	}
}

// JMX reads JVM (or any MBean) numbers through a Jolokia agent as `jmx.attribute{mbean,attribute}`.
func JMX(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runJolokia(ctx, "jmx", jvmReads, raw, out, emitJMX)
}

// emitJMX emits every numeric leaf of the responses (at most 2000 points).
func emitJMX(out sink.Sink, rs []jolokiaResp, now time.Time) {
	n := 0
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			for k, v := range attrs {
				numbers(k, v, func(key string, x float64) {
					if n++; n <= 2000 {
						out.Gauge("jmx.attribute", "1", x, map[string]string{"mbean": mbean, "attribute": key}, now)
					}
				})
			}
		})
	}
}

// ActiveMQ reads the queue topology of a classic broker through its Jolokia agent.
func ActiveMQ(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runJolokia(ctx, "activemq", activemqReads, raw, out, emitActiveMQ)
}

var activemqMetric = map[string]struct {
	name, unit string
	sum        bool
}{
	"QueueSize":     {"activemq.queue.size", "{messages}", false},
	"ConsumerCount": {"activemq.queue.consumers", "{consumers}", false},
	"ProducerCount": {"activemq.queue.producers", "{producers}", false},
	"InFlightCount": {"activemq.queue.in_flight", "{messages}", false},
	"EnqueueCount":  {"activemq.queue.enqueued", "{messages}", true},
	"DequeueCount":  {"activemq.queue.dequeued", "{messages}", true},
}

// emitActiveMQ emits the 200 deepest queues; broker and queue name come from the MBean name.
func emitActiveMQ(out sink.Sink, rs []jolokiaResp, now time.Time) {
	type queue struct {
		attrs map[string]string
		vals  map[string]float64
	}
	var qs []queue
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			p := mbeanProps(mbean)
			q := queue{attrs: map[string]string{"queue": p["destinationName"], "broker": p["brokerName"]}, vals: map[string]float64{}}
			for k, v := range attrs {
				if f, ok := v.(float64); ok {
					q.vals[k] = f
				}
			}
			qs = append(qs, q)
		})
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].vals["QueueSize"] > qs[j].vals["QueueSize"] })
	for _, q := range qs[:min(len(qs), 200)] {
		for k, v := range q.vals {
			m, ok := activemqMetric[k]
			switch {
			case !ok:
			case m.sum:
				out.Sum(m.name, m.unit, v, q.attrs, now)
			default:
				out.Gauge(m.name, m.unit, v, q.attrs, now)
			}
		}
	}
}

// mbeanProps splits "domain:k=v,k=v" into its key properties.
func mbeanProps(mbean string) map[string]string {
	_, props, _ := strings.Cut(mbean, ":")
	out := map[string]string{}
	for _, kv := range strings.Split(props, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out
}
