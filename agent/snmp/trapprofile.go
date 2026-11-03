package snmp

// Per-vendor trap profiles (INF-014): a trap OID gets a name, a severity and names (and enum
// labels) for its varbinds. Built-in profiles are embedded from trapprofiles/*.yaml; the agent's
// own trap.profile_dir adds or replaces them, for example with files written by `wtctl mib
// compile` from the vendor's MIBs.

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

//go:embed trapprofiles/*.yaml
var trapProfileFS embed.FS

// TrapVarbind names one varbind column (the instance suffix is ignored when matching).
type TrapVarbind struct {
	OID  string            `yaml:"oid"`
	Name string            `yaml:"name"`
	Enum map[string]string `yaml:"enum,omitempty"` // integer value -> label
}

// TrapDef is one notification.
type TrapDef struct {
	OID         string        `yaml:"oid"`
	Name        string        `yaml:"name"`
	Severity    string        `yaml:"severity,omitempty"` // INFO, WARN, ERROR; default WARN
	Description string        `yaml:"description,omitempty"`
	Varbinds    []TrapVarbind `yaml:"varbinds,omitempty"`
}

// TrapProfileFile is one vendor's (or one MIB's) file.
type TrapProfileFile struct {
	Vendor string    `yaml:"vendor"`
	Traps  []TrapDef `yaml:"traps"`
}

// TrapEntry is a resolved trap: its definition and the vendor that defines it.
type TrapEntry struct {
	TrapDef
	Vendor string
}

// TrapProfiles maps a trap OID (no leading dot) to its definition.
type TrapProfiles map[string]TrapEntry

var severities = map[string]bool{"INFO": true, "WARN": true, "ERROR": true}

func (ps TrapProfiles) add(name string, b []byte) error {
	var f TrapProfileFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, t := range f.Traps {
		t.OID = norm(t.OID)
		if t.OID == "" || t.Name == "" || t.Severity != "" && !severities[t.Severity] {
			return fmt.Errorf("%s: bad trap %q", name, t.Name)
		}
		for i := range t.Varbinds {
			t.Varbinds[i].OID = norm(t.Varbinds[i].OID)
		}
		ps[t.OID] = TrapEntry{TrapDef: t, Vendor: f.Vendor}
	}
	return nil
}

// LoadTrapProfiles reads the embedded profiles, then *.yaml in dir (local config only), whose
// entries replace built-in ones with the same OID.
func LoadTrapProfiles(dir string) (TrapProfiles, error) {
	ps := TrapProfiles{}
	ents, err := trapProfileFS.ReadDir("trapprofiles")
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		b, err := trapProfileFS.ReadFile("trapprofiles/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := ps.add(e.Name(), b); err != nil {
			return nil, err
		}
	}
	if dir == "" {
		return ps, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := ps.add(filepath.Base(f), b); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// varbind returns the varbind definition whose column OID prefixes oid (longest wins).
func (e TrapEntry) varbind(oid string) (TrapVarbind, bool) {
	oid = norm(oid)
	best, ok := TrapVarbind{}, false
	for _, v := range e.Varbinds {
		if (oid == v.OID || strings.HasPrefix(oid, v.OID+".")) && len(v.OID) > len(best.OID) {
			best, ok = v, true
		}
	}
	return best, ok
}

// Label renders a varbind value, with its enum label when the profile has one.
func (v TrapVarbind) Label(val string) string {
	if l, ok := v.Enum[val]; ok {
		return l
	}
	return val
}
