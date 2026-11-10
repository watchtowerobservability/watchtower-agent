package autoinst

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxEntries   = 50000
	maxUnpacked  = 1 << 30
	bundleDirMod = 0o755
)

// InstallBundle unpacks a verified tar.gz of one language's auto-instrumentation into
// AgentsDir/versions/<version>/<lang>. The archive holds the language directory's contents; it
// may hold directories and regular files only (no links, no paths that leave the directory).
// The unpack goes to a temporary directory first, so a failed install leaves nothing behind.
func InstallBundle(c Config, lang, version string, tgz []byte) error {
	if !versionRe.MatchString(version) {
		return errors.New("malformed version")
	}
	parent := filepath.Join(c.agentsDir(), "versions", version)
	if err := os.MkdirAll(parent, bundleDirMod); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".unpack-"+lang+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := untar(tmp, tgz); err != nil {
		return err
	}
	dst := filepath.Join(parent, lang)
	if err := os.RemoveAll(dst); err != nil { // a half-installed earlier try
		return err
	}
	return os.Rename(tmp, dst)
}

func untar(root string, tgz []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return fmt.Errorf("bundle is not a gzip archive: %w", err)
	}
	tr := tar.NewReader(zr)
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if n >= maxEntries || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("bundle entry %q is not allowed", h.Name)
		}
		dst := filepath.Join(root, name)
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, bundleDirMod)
		case tar.TypeReg:
			total += h.Size
			if total > maxUnpacked {
				return errors.New("bundle unpacks to more than 1 GiB")
			}
			if err = os.MkdirAll(filepath.Dir(dst), bundleDirMod); err == nil {
				err = writeEntry(dst, tr, h.FileInfo().Mode().Perm()|0o444)
			}
		default:
			return fmt.Errorf("bundle entry %q is a link or special file", h.Name)
		}
		if err != nil {
			return err
		}
	}
}

func writeEntry(dst string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode&0o755) //nolint:gosec // path cleaned and rooted by the caller
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(r, maxUnpacked)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
