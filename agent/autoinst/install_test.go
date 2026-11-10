package autoinst

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func tgz(t *testing.T, files map[string]string, link bool) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	for n, c := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(c))
	}
	if link {
		_ = tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	}
	_ = tw.Close()
	_ = zw.Close()
	return b.Bytes()
}

func TestInstallBundleUnpacksUnderVersionsAndRefusesEscapes(t *testing.T) {
	c := Config{AgentsDir: t.TempDir()}
	if err := InstallBundle(c, "java", "2.1.0", tgz(t, map[string]string{"javaagent.jar": "x", "lib/a.txt": "y"}, false)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(c.AgentsDir, "versions", "2.1.0", "java", "lib", "a.txt")); string(b) != "y" {
		t.Fatalf("unpacked %q", b)
	}
	if !Installed(c, "java", "2.1.0") || Installed(c, "python", "2.1.0") {
		t.Fatal("Installed is per language and version")
	}
	for name, data := range map[string][]byte{
		"escape": tgz(t, map[string]string{"../evil": "x"}, false),
		"abs":    tgz(t, map[string]string{"/etc/evil": "x"}, false),
		"link":   tgz(t, map[string]string{"a": "x"}, true),
		"notgz":  []byte("plain"),
	} {
		if err := InstallBundle(c, "python", "9.9.9", data); err == nil {
			t.Fatalf("%s must be refused", name)
		}
		if Installed(c, "python", "9.9.9") {
			t.Fatalf("%s left a partial install", name)
		}
	}
	if err := InstallBundle(c, "java", "../x", nil); err == nil {
		t.Fatal("bad version")
	}
}
