package gpu

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

// GPU attribution to Kubernetes pods (INF-010) through the kubelet pod-resources API
// (v1.PodResourcesLister/List on the kubelet's local unix socket). The messages are read on the
// protobuf wire format directly, so no kubelet module is needed.

// PodGPU is the pod container a device is assigned to.
type PodGPU struct {
	Pod, Namespace, Container string
}

const listMethod = "/v1.PodResourcesLister/List"

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.(*[]byte); ok {
		return *b, nil
	}
	return nil, fmt.Errorf("pod-resources codec: cannot marshal %T", v)
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = append((*b)[:0], data...)
		return nil
	}
	return fmt.Errorf("pod-resources codec: cannot unmarshal into %T", v)
}

// eachBytes calls f with every length-delimited field of a message; other wire types are skipped.
func eachBytes(b []byte, f func(protowire.Number, []byte)) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			f(num, v)
			b = b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return protowire.ParseError(m)
		}
		b = b[m:]
	}
	return nil
}

// ParsePodResources reads a ListPodResourcesResponse into device id -> pod container, keeping
// only devices of a GPU resource (nvidia.com/gpu, amd.com/gpu, ...). Field numbers follow
// k8s.io/kubelet/pkg/apis/podresources/v1: response 1 = pods; pod 1 name, 2 namespace,
// 3 containers; container 1 name, 2 devices; devices 1 resource_name, 2 device_ids.
func ParsePodResources(b []byte) (map[string]PodGPU, error) {
	out := map[string]PodGPU{}
	var perr error
	keep := func(err error) {
		if err != nil && perr == nil {
			perr = err
		}
	}
	keep(eachBytes(b, func(n protowire.Number, pod []byte) {
		if n != 1 {
			return
		}
		var p PodGPU
		var ctrs [][]byte
		keep(eachBytes(pod, func(n protowire.Number, v []byte) {
			switch n {
			case 1:
				p.Pod = string(v)
			case 2:
				p.Namespace = string(v)
			case 3:
				ctrs = append(ctrs, v)
			}
		}))
		for _, ctr := range ctrs {
			c := p
			var devs [][]byte
			keep(eachBytes(ctr, func(n protowire.Number, v []byte) {
				switch n {
				case 1:
					c.Container = string(v)
				case 2:
					devs = append(devs, v)
				}
			}))
			for _, d := range devs {
				var res string
				var ids []string
				keep(eachBytes(d, func(n protowire.Number, v []byte) {
					switch n {
					case 1:
						res = string(v)
					case 2:
						ids = append(ids, string(v))
					}
				}))
				if strings.HasSuffix(res, "/gpu") {
					for _, id := range ids {
						out[id] = c
					}
				}
			}
		}
	}))
	if perr != nil {
		return nil, fmt.Errorf("pod-resources response: %w", perr)
	}
	return out, nil
}

// ListPodResources asks the kubelet at socket (a local path from the agent's own config, e.g.
// /var/lib/kubelet/pod-resources/kubelet.sock) which pod holds which GPU.
func ListPodResources(ctx context.Context, socket string) (map[string]PodGPU, error) {
	cc, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, resp := []byte{}, []byte{}
	if err := cc.Invoke(ctx, listMethod, &req, &resp, grpc.ForceCodec(rawCodec{}), grpc.MaxCallRecvMsgSize(16<<20)); err != nil {
		return nil, fmt.Errorf("pod-resources: %w", err)
	}
	return ParsePodResources(resp)
}

// Attribute marks each reading with the pod that holds it (matched by device UUID, then index).
// A reading not in pods is unallocated; Tracked says the lookup ran at all.
func Attribute(rs []Reading, pods map[string]PodGPU) {
	for i := range rs {
		rs[i].Tracked = true
		if p, ok := pods[rs[i].ID]; ok && rs[i].ID != "" {
			rs[i].Pod = &p
		} else if p, ok := pods[rs[i].Index]; ok {
			rs[i].Pod = &p
		}
	}
}
