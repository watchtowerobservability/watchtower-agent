package autoinst

import (
	"encoding/json"
	"os"
	"path"
	"regexp"
)

var (
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	unitRe    = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,200}\.(service|socket)$`)
)

const defaultStateFile = "/var/lib/watchtower/autoinst-versions.json"

func (c Config) stateFile() string {
	if c.StateFile != "" {
		return c.StateFile
	}
	return defaultStateFile
}

// WithState returns c with the versions a remote upgrade stored on this host laid over its own.
func WithState(c Config) Config {
	b, err := os.ReadFile(c.stateFile())
	if err != nil {
		return c
	}
	var st map[string]string
	if json.Unmarshal(b, &st) != nil {
		return c
	}
	v := map[string]string{}
	for k, x := range c.Versions {
		v[k] = x
	}
	for k, x := range st {
		v[k] = x
	}
	c.Versions = v
	return c
}

// Applies reports whether a service of lang runs on this host under a local rule: a rule whose
// Service is svc, or with no Service and an executable base name of svc.
func Applies(c Config, lang, svc string) bool { return len(matching(c, lang, svc)) > 0 }

// Services lists the (language, service) pairs the local rules cover: what this host reports so
// the server makes one upgrade target per host that runs a service.
func Services(c Config) [][2]string {
	var out [][2]string
	for _, r := range c.Rules {
		svc := r.Service
		if svc == "" {
			svc = path.Base(r.Exe)
		}
		out = append(out, [2]string{r.Lang, svc})
	}
	return out
}

// Installed reports whether version of lang is unpacked under AgentsDir/versions/<version>/<lang>.
func Installed(c Config, lang, version string) bool {
	st, err := os.Stat(c.agentsDir() + "/versions/" + version + "/" + lang)
	return err == nil && st.IsDir()
}

func matching(c Config, lang, svc string) []Rule {
	var out []Rule
	for _, r := range c.Rules {
		if r.Lang == lang && (r.Service == svc || (r.Service == "" && path.Base(r.Exe) == svc)) {
			out = append(out, r)
		}
	}
	return out
}
