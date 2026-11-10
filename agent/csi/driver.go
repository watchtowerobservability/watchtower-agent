// Package csi is the Watchtower agent socket CSI driver (spec: "CSI driver for agent sockets").
// It is a node-only, ephemeral (inline) CSI plugin: a pod declares
//
//	volumes: [{name: wt, csi: {driver: socket.csi.watchtower.io, readOnly: true}}]
//
// and the driver bind-mounts the node agent's socket directory (its dogstatsd unixgram socket
// and OTLP unix socket) into the pod, so workloads reach the agent without hostPath (which
// Pod Security "baseline" and "restricted" forbid) and without a node IP. The CSI and kubelet
// plugin-registration messages are tiny, so they are read and written on the protobuf wire
// format directly (the same approach as gpu/podresources.go); no CSI module is needed.
package csi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

// DriverName is the CSIDriver object name the chart installs.
const DriverName = "socket.csi.watchtower.io"

// Mounter is the OS part, faked in tests.
type Mounter interface {
	BindMount(src, dst string, readOnly bool) error
	Unmount(dst string) error
	IsMounted(dst string) (bool, error)
}

// Driver serves the CSI Identity and Node services.
type Driver struct {
	NodeID  string
	Version string
	// SocketRoot bounds which host directories a pod may ask for: the requested socketDir must be
	// SocketRoot or below it, so a pod cannot mount arbitrary host paths through this driver.
	SocketRoot string
	Mount      Mounter
}

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.(*[]byte); ok {
		return *b, nil
	}
	return nil, fmt.Errorf("csi codec: cannot marshal %T", v)
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = append((*b)[:0], data...)
		return nil
	}
	return fmt.Errorf("csi codec: cannot unmarshal into %T", v)
}

type handler func(ctx context.Context, req []byte) ([]byte, error)

func method(name string, h handler) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var req []byte
		if err := dec(&req); err != nil {
			return nil, err
		}
		out, err := h(ctx, req)
		if err != nil {
			return nil, err
		}
		return &out, nil
	}}
}

// Serve listens on the unix socket endpoint and serves until ctx ends. register, when set, is
// the kubelet plugin-registration socket (/var/lib/kubelet/plugins_registry/<name>-reg.sock).
func (d *Driver) Serve(ctx context.Context, endpoint, register string) error {
	if d.Mount == nil || d.NodeID == "" || d.SocketRoot == "" {
		return errors.New("csi: Mount, NodeID and SocketRoot are required")
	}
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	srv.RegisterService(&grpc.ServiceDesc{ServiceName: "csi.v1.Identity", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
		method("GetPluginInfo", d.pluginInfo), method("GetPluginCapabilities", empty), method("Probe", empty),
	}}, struct{}{})
	srv.RegisterService(&grpc.ServiceDesc{ServiceName: "csi.v1.Node", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
		method("NodePublishVolume", d.publish), method("NodeUnpublishVolume", d.unpublish),
		method("NodeGetCapabilities", empty), method("NodeGetInfo", d.nodeInfo),
	}}, struct{}{})
	lis, err := listenUnix(endpoint)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(lis) }()
	var reg *grpc.Server
	if register != "" {
		reg = grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
		reg.RegisterService(&grpc.ServiceDesc{ServiceName: "pluginregistration.Registration", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
			method("GetInfo", func(context.Context, []byte) ([]byte, error) { return registrationInfo(endpoint), nil }),
			method("NotifyRegistrationStatus", func(_ context.Context, b []byte) ([]byte, error) {
				if msg := registrationError(b); msg != "" {
					slog.Error("csi: kubelet refused the registration", "error", msg)
				}
				return nil, nil
			}),
		}}, struct{}{})
		rl, err := listenUnix(register)
		if err != nil {
			srv.Stop()
			return err
		}
		go func() { errc <- reg.Serve(rl) }()
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	srv.Stop()
	if reg != nil {
		reg.Stop()
	}
	return err
}

func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // a stale socket of a previous run
	return net.Listen("unix", path)
}

func empty(context.Context, []byte) ([]byte, error) { return nil, nil }

func (d *Driver) pluginInfo(context.Context, []byte) ([]byte, error) {
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	b = protowire.AppendString(b, DriverName)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendString(b, d.Version), nil
}

func (d *Driver) nodeInfo(context.Context, []byte) ([]byte, error) {
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	return protowire.AppendString(b, d.NodeID), nil
}

// registrationInfo is the kubelet pluginregistration PluginInfo: type CSIPlugin, our name and
// endpoint, CSI 1.0.0.
func registrationInfo(endpoint string) []byte {
	var b []byte
	for i, s := range []string{"CSIPlugin", DriverName, endpoint, "1.0.0"} {
		b = protowire.AppendTag(b, protowire.Number(i+1), protowire.BytesType)
		b = protowire.AppendString(b, s)
	}
	return b
}

func registrationError(b []byte) string {
	var msg string
	_ = eachField(b, func(n protowire.Number, v []byte) {
		if n == 2 {
			msg = string(v)
		}
	})
	return msg
}

func eachField(b []byte, f func(protowire.Number, []byte)) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return protowire.ParseError(m)
		}
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b)
			f(num, v)
		}
		b = b[m:]
	}
	return nil
}

// publishReq is the part of NodePublishVolumeRequest the driver uses.
type publishReq struct {
	volumeID, target string
	readOnly         bool
	attrs            map[string]string
}

func parsePublish(b []byte) (publishReq, error) {
	r := publishReq{attrs: map[string]string{}}
	var bad error
	// readonly (field 6) is a varint, which eachField skips, so it is read separately.
	r.readOnly = varintField(b, 6) != 0
	err := eachField(b, func(n protowire.Number, v []byte) {
		switch n {
		case 1:
			r.volumeID = string(v)
		case 4:
			r.target = string(v)
		case 8: // map<string,string> entry: key=1, value=2
			var k, val string
			if e := eachField(v, func(n protowire.Number, x []byte) {
				if n == 1 {
					k = string(x)
				} else if n == 2 {
					val = string(x)
				}
			}); e != nil {
				bad = e
			}
			r.attrs[k] = val
		}
	})
	return r, errors.Join(err, bad)
}

func varintField(b []byte, want protowire.Number) uint64 {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return 0
		}
		b = b[n:]
		if typ == protowire.VarintType && num == want {
			v, _ := protowire.ConsumeVarint(b)
			return v
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return 0
		}
		b = b[m:]
	}
	return 0
}

// Source resolves the host directory a pod asked for and checks it is inside SocketRoot.
func (d *Driver) Source(attrs map[string]string) (string, error) {
	dir := attrs["socketDir"]
	if dir == "" {
		dir = d.SocketRoot
	}
	dir = filepath.Clean(dir)
	root := filepath.Clean(d.SocketRoot)
	if dir != root && !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		return "", status.Errorf(codes.InvalidArgument, "socketDir %q is outside %q", dir, root)
	}
	return dir, nil
}

func (d *Driver) publish(_ context.Context, b []byte) ([]byte, error) {
	r, err := parsePublish(b)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if r.volumeID == "" || r.target == "" {
		return nil, status.Error(codes.InvalidArgument, "volume_id and target_path are required")
	}
	src, err := d.Source(r.attrs)
	if err != nil {
		return nil, err
	}
	if fi, e := os.Stat(src); e != nil || !fi.IsDir() {
		return nil, status.Errorf(codes.FailedPrecondition, "%s is not a directory on this node (is the agent running here?)", src)
	}
	if err := os.MkdirAll(r.target, 0o750); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if ok, _ := d.Mount.IsMounted(r.target); ok {
		return nil, nil // kubelet retries NodePublishVolume; publishing twice is a no-op
	}
	if err := d.Mount.BindMount(src, r.target, r.readOnly); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	slog.Info("csi: published agent sockets", "volume", r.volumeID, "source", src, "target", r.target)
	return nil, nil
}

func (d *Driver) unpublish(_ context.Context, b []byte) ([]byte, error) {
	var target string
	if err := eachField(b, func(n protowire.Number, v []byte) {
		if n == 2 {
			target = string(v)
		}
	}); err != nil || target == "" {
		return nil, status.Error(codes.InvalidArgument, "target_path is required")
	}
	if ok, _ := d.Mount.IsMounted(target); ok {
		if err := d.Mount.Unmount(target); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	_ = os.Remove(target)
	return nil, nil
}
