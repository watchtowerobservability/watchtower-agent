package csi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

type fakeMounter struct {
	mounted map[string]string
	ro      map[string]bool
}

func (f *fakeMounter) BindMount(src, dst string, ro bool) error {
	f.mounted[dst], f.ro[dst] = src, ro
	return nil
}
func (f *fakeMounter) Unmount(dst string) error { delete(f.mounted, dst); return nil }
func (f *fakeMounter) IsMounted(dst string) (bool, error) {
	_, ok := f.mounted[dst]
	return ok, nil
}

func str(b []byte, n protowire.Number, s string) []byte {
	return protowire.AppendString(protowire.AppendTag(b, n, protowire.BytesType), s)
}

func publishBody(vol, target string, ro bool, attrs map[string]string) []byte {
	b := str(nil, 1, vol)
	b = str(b, 4, target)
	if ro {
		b = protowire.AppendVarint(protowire.AppendTag(b, 6, protowire.VarintType), 1)
	}
	for k, v := range attrs {
		e := str(str(nil, 1, k), 2, v)
		b = protowire.AppendBytes(protowire.AppendTag(b, 8, protowire.BytesType), e)
	}
	return b
}

func TestPublishUnpublish(t *testing.T) {
	root := t.TempDir()
	m := &fakeMounter{mounted: map[string]string{}, ro: map[string]bool{}}
	d := &Driver{NodeID: "n1", SocketRoot: root, Mount: m}
	target := filepath.Join(t.TempDir(), "pods", "v1")
	if _, err := d.publish(context.Background(), publishBody("v1", target, true, nil)); err != nil {
		t.Fatal(err)
	}
	if m.mounted[target] != root || !m.ro[target] {
		t.Fatalf("mount: %v ro=%v", m.mounted, m.ro)
	}
	if _, err := d.publish(context.Background(), publishBody("v1", target, true, nil)); err != nil {
		t.Fatalf("second publish must be a no-op: %v", err)
	}
	un := str(str(nil, 1, "v1"), 2, target)
	if _, err := d.unpublish(context.Background(), un); err != nil {
		t.Fatal(err)
	}
	if len(m.mounted) != 0 {
		t.Fatalf("still mounted: %v", m.mounted)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("target dir should be removed")
	}
}

func TestPublishRejectsPathsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	d := &Driver{NodeID: "n1", SocketRoot: root, Mount: &fakeMounter{mounted: map[string]string{}, ro: map[string]bool{}}}
	for _, dir := range []string{"/etc", root + "/../etc", root + "x"} {
		_, err := d.publish(context.Background(), publishBody("v", t.TempDir(), false, map[string]string{"socketDir": dir}))
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("socketDir %q: want InvalidArgument, got %v", dir, err)
		}
	}
	sub := filepath.Join(root, "dogstatsd")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := d.publish(context.Background(), publishBody("v", t.TempDir(), false, map[string]string{"socketDir": sub})); err != nil {
		t.Fatalf("a subdirectory is allowed: %v", err)
	}
}

func TestIdentityAndRegistration(t *testing.T) {
	d := &Driver{NodeID: "node-7", Version: "1.2.3"}
	b, _ := d.pluginInfo(context.Background(), nil)
	var name, ver string
	_ = eachField(b, func(n protowire.Number, v []byte) {
		if n == 1 {
			name = string(v)
		} else {
			ver = string(v)
		}
	})
	if name != DriverName || ver != "1.2.3" {
		t.Fatalf("plugin info %q %q", name, ver)
	}
	var got []string
	_ = eachField(registrationInfo("/csi/csi.sock"), func(_ protowire.Number, v []byte) { got = append(got, string(v)) })
	if len(got) != 4 || got[0] != "CSIPlugin" || got[2] != "/csi/csi.sock" {
		t.Fatalf("registration info %v", got)
	}
}
