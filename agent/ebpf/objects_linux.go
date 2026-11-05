//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// embedded holds the CO-RE objects built by `make ebpf-gen` (scripts/ebpf-gen.sh writes the
// _bpfel.o files into objects/). The committed tree carries only a placeholder, so a binary built
// without that step embeds no object and LoadSpec falls back to object_dir on disk; once the step
// has run, the objects ship inside the agent and enabling a module is config-only.
//
//go:embed objects
var embedded embed.FS

// LoadSpec loads a BPF collection by base name (e.g. "http" -> http_bpfel.o), preferring the copy
// embedded at build time and falling back to dir on disk. shortcut: only the little-endian object
// is embedded (ebpf-gen builds _bpfel.o); a big-endian target must install objects into object_dir,
// upgrade by building and embedding a _bpfeb.o too.
func LoadSpec(dir, name string) (*ebpf.CollectionSpec, error) {
	file := name + "_bpfel.o"
	if b, err := embedded.ReadFile("objects/" + file); err == nil {
		return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(b))
	}
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(dir, file))
	if err != nil {
		return nil, fmt.Errorf("%w (build and embed the objects with `make ebpf-gen`, or install them into object_dir)", err)
	}
	return spec, nil
}
