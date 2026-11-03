package ascode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Doc is one manifest: kind + metadata.name identify it inside a project.
type Doc struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   Metadata       `yaml:"metadata" json:"metadata"`
	Spec       map[string]any `yaml:"spec" json:"spec"`
}

// Metadata names the resource.
type Metadata struct {
	Name   string            `yaml:"name" json:"name"`
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// LoadDocs reads a file, or every .yaml/.yml/.json file below a directory (multi-document YAML allowed).
func LoadDocs(path string) ([]Doc, error) {
	var files []string
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && slices.Contains([]string{".yaml", ".yml", ".json"}, filepath.Ext(p)) {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	var docs []Doc
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		got, err := ParseDocs(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		docs = append(docs, got...)
	}
	return docs, nil
}

// ParseDocs decodes and validates a multi-document YAML (or JSON) stream.
func ParseDocs(src []byte) ([]Doc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var docs []Doc
	seen := map[string]bool{}
	for {
		var d Doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return docs, nil
		} else if err != nil {
			return nil, err
		}
		if d.Kind == "" && d.Metadata.Name == "" && d.Spec == nil {
			continue // empty document between separators
		}
		if d.APIVersion != APIVersion {
			return nil, fmt.Errorf("%s/%s: apiVersion must be %s", d.Kind, d.Metadata.Name, APIVersion)
		}
		k := ByKind(d.Kind)
		if k == nil {
			return nil, fmt.Errorf("unknown kind %q (known: %s)", d.Kind, strings.Join(KindNames(), ", "))
		}
		if d.Metadata.Name == "" {
			return nil, fmt.Errorf("%s: metadata.name is required", d.Kind)
		}
		if id := d.Kind + "/" + d.Metadata.Name; seen[id] {
			return nil, fmt.Errorf("%s is defined twice", id)
		} else {
			seen[id] = true
		}
		spec, err := normalize(d.Spec)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", d.Kind, d.Metadata.Name, err)
		}
		d.Spec = spec
		if err := checkSecretRefs(k, d.Spec); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", d.Kind, d.Metadata.Name, err)
		}
		docs = append(docs, d)
	}
}

// normalize round-trips through JSON so numbers and maps look like the API's.
func normalize(m map[string]any) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(b, &out)
}

var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// secretValues calls f for every secret string of the spec with a setter.
func secretValues(k *Kind, spec map[string]any, f func(field string, v any, set func(string)) error) error {
	for _, field := range k.SecretFields {
		switch v := spec[field].(type) {
		case nil:
		case map[string]any:
			for sub, x := range v {
				if err := f(field+"."+sub, x, func(s string) { v[sub] = s }); err != nil {
					return err
				}
			}
		default:
			if err := f(field, v, func(s string) { spec[field] = s }); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkSecretRefs rejects a secret field that holds anything but a ${ENV} reference.
func checkSecretRefs(k *Kind, spec map[string]any) error {
	return secretValues(k, spec, func(field string, v any, _ func(string)) error {
		if s, ok := v.(string); !ok || !envRef.MatchString(s) {
			return fmt.Errorf("secret field %s must be a ${ENV} reference, never a literal value", field)
		}
		return nil
	})
}

// LookupEnv resolves ${ENV} references; tests and the Terraform provider may swap it.
var LookupEnv = os.LookupEnv

// ExpandSecrets returns a copy of spec with its secret references replaced by environment values.
func ExpandSecrets(k *Kind, spec map[string]any) (map[string]any, error) {
	out, err := normalize(spec)
	if err != nil {
		return nil, err
	}
	err = secretValues(k, out, func(field string, v any, set func(string)) error {
		s, _ := v.(string)
		m := envRef.FindStringSubmatch(s)
		if m == nil {
			return fmt.Errorf("secret field %s must be a ${ENV} reference, never a literal value", field)
		}
		val, ok := LookupEnv(m[1])
		if !ok || val == "" {
			return fmt.Errorf("secret field %s: environment variable %s is not set", field, m[1])
		}
		set(val)
		return nil
	})
	return out, err
}

// withoutSecrets drops the secret fields: the API never returns them, so they take no part in comparisons.
func withoutSecrets(k *Kind, spec map[string]any) map[string]any {
	out := make(map[string]any, len(spec))
	for f, v := range spec {
		out[f] = v
	}
	for _, f := range k.SecretFields {
		delete(out, f)
	}
	return out
}
