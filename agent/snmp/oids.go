// Package snmp polls devices over SNMP v1, v2c and v3, receives traps and turns both into
// metrics and logs. OID sets come from YAML manifests (integrations/snmp/, embedded copies in
// manifests/), hand-written or compiled from vendor MIBs by package mibc (`wtctl mib compile`).
//
// Everything that names a device or holds a credential (address, community, v3 users and
// passphrases) comes from the agent's own file. None of it is exported, logged or put in an
// error.
package snmp

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed manifests/*.yaml
var builtinFS embed.FS

// Item is one metric: a scalar OID, or a column of a table.
type Item struct {
	OID    string            `yaml:"oid,omitempty"`     // scalars: the full instance OID
	Col    string            `yaml:"col,omitempty"`     // table items: the column sub-identifier
	MulCol string            `yaml:"mul_col,omitempty"` // table items: multiply by this column of the same row
	Metric string            `yaml:"metric,omitempty"`
	Unit   string            `yaml:"unit,omitempty"`
	Kind   string            `yaml:"kind,omitempty"`  // gauge (default) or counter (reported as a rate)
	Scale  float64           `yaml:"scale,omitempty"` // 0 means 1
	Attrs  map[string]string `yaml:"attrs,omitempty"`
	// SpeedLimit marks a byte counter whose rate cannot exceed the interface speed (the table's
	// SpeedCol); a bigger rate is a counter reset, not traffic.
	SpeedLimit bool `yaml:"speed_limit,omitempty"`
}

// Extra is a descriptive attribute read from a column of another table with the same row index.
type Extra struct {
	OID  string `yaml:"oid,omitempty"` // the column OID, e.g. ifName 1.3.6.1.2.1.31.1.1.1.1
	Attr string `yaml:"attr,omitempty"`
}

// Table is a conceptual table walked from OID.
type Table struct {
	Name      string `yaml:"name"`
	OID       string `yaml:"oid,omitempty"`
	LabelCol  string `yaml:"label_col,omitempty"`  // column holding the row's name; the row index otherwise
	LabelAttr string `yaml:"label_attr,omitempty"` // attribute that carries the label
	Items     []Item `yaml:"items,omitempty"`
	Sensor    bool   `yaml:"sensor,omitempty"`   // an ENTITY-SENSOR-MIB table (type, scale, precision, value)
	NameOID   string `yaml:"name_oid,omitempty"` // sensor rows are named from this column
	// Priority orders the walks of one poll, highest first, so that when the varbind cap is hit
	// the low-value tables are the ones cut.
	Priority   int     `yaml:"priority,omitempty"`
	Extra      []Extra `yaml:"extra,omitempty"`
	SpeedCol   string  `yaml:"speed_col,omitempty"`   // column with the interface speed
	SpeedScale float64 `yaml:"speed_scale,omitempty"` // multiplier to bit/s (ifHighSpeed is in Mbit/s); 0 means 1
}

// columnOIDs lists the column subtrees to walk: only the columns the manifest reads, never the
// whole table.
func (t Table) columnOIDs() []string {
	cols := map[string]bool{}
	add := func(c string) {
		if c != "" {
			cols[c] = true
		}
	}
	add(t.LabelCol)
	add(t.SpeedCol)
	for _, it := range t.Items {
		add(it.Col)
		add(it.MulCol)
	}
	if t.Sensor {
		for _, c := range []string{"1", "2", "3", "4", "5"} {
			add(c)
		}
	}
	out := make([]string, 0, len(cols)+len(t.Extra)+1)
	for c := range cols {
		out = append(out, t.OID+"."+c)
	}
	sort.Strings(out)
	for _, e := range t.Extra {
		out = append(out, norm(e.OID))
	}
	if t.NameOID != "" {
		out = append(out, norm(t.NameOID))
	}
	return out
}

// Manifest is one MIB's worth of OIDs.
type Manifest struct {
	Name    string   `yaml:"name"`
	Tables  []Table  `yaml:"tables,omitempty"`
	Scalars []Item   `yaml:"scalars,omitempty"`
	Walk    []string `yaml:"walk,omitempty"` // subtrees for other modules (LLDP); not polled here
}

func parseManifest(b []byte) (Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return m, err
	}
	if m.Name == "" {
		return m, fmt.Errorf("manifest has no name")
	}
	return m, nil
}

// Manifests returns the manifests by name: the embedded ones, then any *.yaml in dir (local
// config only) replacing those of the same name.
func Manifests(dir string) (map[string]Manifest, error) {
	out := map[string]Manifest{}
	ents, err := builtinFS.ReadDir("manifests")
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		b, err := builtinFS.ReadFile("manifests/" + e.Name())
		if err != nil {
			return nil, err
		}
		m, err := parseManifest(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[m.Name] = m
	}
	if dir == "" {
		return out, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		m, err := parseManifest(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		out[m.Name] = m
	}
	return out, nil
}

// defaultSet is polled when a target names no manifests.
var defaultSet = []string{"entity-sensor-mib", "host-resources-mib", "if-mib", "ups-mib"}

// pick returns the manifests a target polls, in name order.
func pick(all map[string]Manifest, names []string) ([]Manifest, error) {
	if len(names) == 0 {
		names = defaultSet
	}
	names = append([]string(nil), names...)
	sort.Strings(names)
	var out []Manifest
	for _, n := range names {
		m, ok := all[n]
		if !ok {
			return nil, fmt.Errorf("unknown manifest %q", n)
		}
		out = append(out, m)
	}
	return out, nil
}

// norm strips the leading dot gosnmp puts on OIDs.
func norm(oid string) string { return strings.TrimPrefix(oid, ".") }

// suffix returns the part of oid below prefix ("" when it is not below it).
func suffix(oid, prefix string) string {
	s, ok := strings.CutPrefix(norm(oid), prefix+".")
	if !ok {
		return ""
	}
	return s
}
