package ascode

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ManagedByKey is the label every manifest-managed object carries.
const ManagedByKey = "managed-by"

// Manifest is a parsed watchtower.yaml: the as-code kinds of one repository file.
type Manifest struct {
	Repo, Path string
	Docs       []Doc
}

// ManagedBy is the label value for objects created from repo's file at path.
func ManagedBy(repo, path string) string { return "manifest:" + repo + "@" + path }

// ParseManifest decodes a watchtower.yaml. Unknown fields beside apiVersion/kind/metadata/spec are
// errors (a typo must not silently drop a section); every doc is labelled managed-by.
func ParseManifest(src []byte, repo, path string) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	for {
		var d Doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
	}
	docs, err := ParseDocs(src)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	for i := range docs {
		if docs[i].Metadata.Labels == nil {
			docs[i].Metadata.Labels = map[string]string{}
		}
		docs[i].Metadata.Labels[ManagedByKey] = ManagedBy(repo, path)
	}
	return &Manifest{Repo: repo, Path: path, Docs: docs}, nil
}

// Kinds is the set of kinds the file names; applying never touches any other kind.
func (m *Manifest) Kinds() map[string]bool {
	out := map[string]bool{}
	for _, d := range m.Docs {
		out[d.Kind] = true
	}
	return out
}
