package srcconv

// Datadog distribution sketches (/api/beta/sketches), split from datadog_pb.go.

import (
	"math"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

// The agent's DDSketch has relative accuracy 1/128: key k covers (gamma^(k-1), gamma^k] with
// gamma = (1+1/128)/(1-1/128) ~ 1.0157. Each key is re-binned into the OTLP base-2 scale-5 histogram
// at the geometric middle of its bucket, so counts are exact and bucket bounds are within one OTLP
// bucket (2.2%) of the sketch's.
const (
	sketchScale      = 5
	sketchMaxBuckets = 4096
)

var (
	sketchGamma  = (1 + 1.0/128) / (1 - 1.0/128)
	sketchFactor = math.Log2(sketchGamma) * (1 << sketchScale)
)

type ddDogsketch struct {
	ts, cnt       int64
	min, max, sum float64
	k             []int32
	n             []uint32
}

func (d *ddDogsketch) field(num protowire.Number, v []byte, n uint64) error {
	switch num {
	case 1:
		d.ts = int64(n) //nolint:gosec // wire value
	case 2:
		d.cnt = int64(n) //nolint:gosec // wire value
	case 3:
		d.min = math.Float64frombits(n)
	case 4:
		d.max = math.Float64frombits(n)
	case 6:
		d.sum = math.Float64frombits(n)
	case 7, 8:
		vals, err := ddPackedVarints(v, n)
		if err != nil || len(d.k)+len(vals) > 1<<16 {
			return ErrDatadog
		}
		for _, x := range vals {
			if num == 7 {
				d.k = append(d.k, int32(protowire.DecodeZigZag(x))) //nolint:gosec // sint32
			} else {
				d.n = append(d.n, uint32(x)) //nolint:gosec // uint32 field
			}
		}
	}
	return nil
}

// ddPackedVarints reads a packed varint field, or the single value of an unpacked one (v == nil).
func ddPackedVarints(v []byte, n uint64) ([]uint64, error) {
	if v == nil {
		return []uint64{n}, nil
	}
	var out []uint64
	for len(v) > 0 {
		x, l := protowire.ConsumeVarint(v)
		if l < 0 {
			return nil, ErrDatadog
		}
		out = append(out, x)
		v = v[l:]
	}
	return out, nil
}

func sketchBucketIndex(k int32) int32 {
	return int32(math.Floor((math.Abs(float64(k)) - 0.5) * sketchFactor))
}

func sketchBuckets(m map[int32]uint64) (*metricspb.ExponentialHistogramDataPoint_Buckets, error) {
	if len(m) == 0 {
		return nil, nil
	}
	lo, hi := int32(math.MaxInt32), int32(math.MinInt32)
	for i := range m {
		lo, hi = min(lo, i), max(hi, i)
	}
	if int64(hi)-int64(lo) >= sketchMaxBuckets {
		return nil, ErrDatadog
	}
	counts := make([]uint64, hi-lo+1)
	for i, c := range m {
		counts[i-lo] = c
	}
	return &metricspb.ExponentialHistogramDataPoint_Buckets{Offset: lo, BucketCounts: counts}, nil
}

func (d *ddDogsketch) point(attrs []*commonpb.KeyValue) (*metricspb.ExponentialHistogramDataPoint, error) {
	if len(d.k) != len(d.n) {
		return nil, ErrDatadog
	}
	pos, neg := map[int32]uint64{}, map[int32]uint64{}
	var zero, total uint64
	for i, k := range d.k {
		c := uint64(d.n[i])
		total += c
		switch {
		case k == 0:
			zero += c
		case k > 0:
			pos[sketchBucketIndex(k)] += c
		default:
			neg[sketchBucketIndex(k)] += c
		}
	}
	p, err := sketchBuckets(pos)
	if err != nil {
		return nil, err
	}
	n, err := sketchBuckets(neg)
	if err != nil {
		return nil, err
	}
	end := uint64(max(d.ts, 0)) * uint64(time.Second) //nolint:gosec // non-negative
	dp := &metricspb.ExponentialHistogramDataPoint{
		Attributes: attrs, TimeUnixNano: end, StartTimeUnixNano: end - min(end, uint64(10*time.Second)),
		Count: total, Sum: &d.sum, Scale: sketchScale, ZeroCount: zero, Positive: p, Negative: n,
	}
	if total > 0 {
		dp.Min, dp.Max = &d.min, &d.max
	}
	return dp, nil
}

// ParseSketches decodes a SketchPayload into exponential histogram metrics; more than max sketches
// is ErrTooLarge.
func ParseSketches(b []byte, maxSketches int) ([]*metricspb.Metric, error) {
	var out []*metricspb.Metric
	err := pw(b, func(num protowire.Number, v []byte, _ uint64) error {
		if num != 1 {
			return nil
		}
		if len(out) >= maxSketches {
			return ErrTooLarge
		}
		m, err := parseSketch(v)
		if err == nil && m != nil {
			out = append(out, m)
		}
		return err
	})
	return out, err
}

func parseSketch(b []byte) (*metricspb.Metric, error) {
	var (
		name, host string
		tags       []string
		sketches   []*ddDogsketch
	)
	err := pw(b, func(num protowire.Number, v []byte, _ uint64) error {
		switch num {
		case 1:
			name = string(v)
		case 2:
			host = string(v)
		case 4:
			tags = append(tags, string(v))
		case 7:
			d := &ddDogsketch{}
			if err := pw(v, d.field); err != nil {
				return err
			}
			sketches = append(sketches, d)
		}
		return nil
	})
	if err != nil || name == "" || len(sketches) == 0 {
		return nil, err
	}
	var attrs []*commonpb.KeyValue
	if host != "" {
		attrs = AppendKV(attrs, "host.name", StrVal(host))
	}
	attrs = TagAttrs(attrs, tags)
	h := &metricspb.ExponentialHistogram{AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA}
	for _, d := range sketches {
		dp, err := d.point(attrs)
		if err != nil {
			return nil, err
		}
		h.DataPoints = append(h.DataPoints, dp)
	}
	return &metricspb.Metric{Name: name, Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: h}}, nil
}
