package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// explainKey marks config keys that name something the module reads or connects to.
var explainKey = regexp.MustCompile(`(?i)(url|endpoint|addr|address|host|hosts|brokers|targets|path|dir|file|socket|dsn|server|servers|port)s?$`)

// explain is `wt-agent explain [-remote FILE]`: the modules that would start after the remote
// overlay (a served config body, as YAML or JSON, when given), what each reads or connects to,
// and whether its secret references resolve. Values of references are never printed, nor their
// paths (they can be sensitive too); DSNs and URLs lose their user info and query.
func explain(ctx context.Context, cfgPath, remotePath string, w io.Writer) error {
	local, err := LoadLocal(cfgPath)
	if err != nil {
		return err
	}
	var rc *RemoteConfig
	if remotePath != "" {
		b, err := os.ReadFile(remotePath)
		if err != nil {
			return err
		}
		if rc, err = remoteFromYAML(b); err != nil {
			return fmt.Errorf("remote config: %w", err)
		}
	}
	reg := NewRegistry(local)
	var warns []string
	plan := Merge(reg, local.Modules, rc, func(m string) { warns = append(warns, m) })
	fmt.Fprintf(w, "exports to: %s (OTLP/HTTP)\nfleet: %s\n", redactURL(local.Endpoint), redactURL(local.FleetEndpoint))
	names := make([]string, 0, len(plan))
	for n := range plan {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cfg := plan[n]
		state := "starts"
		if _, ok := reg[n]; !ok {
			state = "unknown module: not started"
		} else if off(cfg) {
			state = "disabled"
		}
		fmt.Fprintf(w, "\nmodule %s: %s\n", n, state)
		for _, t := range explainTargets(cfg) {
			fmt.Fprintf(w, "  %s\n", t)
		}
		if HasSecretRefs(cfg) {
			rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := defaultResolver.resolve(rctx, cfg)
			cancel()
			providers := map[string]bool{}
			for _, m := range secretRefRe.FindAllSubmatch(cfg, -1) {
				providers[string(m[1])] = true
			}
			ps := make([]string, 0, len(providers))
			for p := range providers {
				ps = append(ps, p)
			}
			sort.Strings(ps)
			if err != nil {
				fmt.Fprintf(w, "  secret references (%s): NOT resolved: %v\n", strings.Join(ps, ", "), err)
			} else {
				fmt.Fprintf(w, "  secret references (%s): resolved (values redacted)\n", strings.Join(ps, ", "))
			}
		}
	}
	for _, m := range warns {
		fmt.Fprintf(w, "\nremote config refused: %s\n", m)
	}
	return nil
}

func off(cfg json.RawMessage) bool {
	var c struct {
		Enabled *bool `json:"enabled"`
	}
	return json.Unmarshal(cfg, &c) == nil && c.Enabled != nil && !*c.Enabled
}

// explainTargets walks a module config and lists `key.path = value` for keys that name an
// endpoint, address or local path. Secret references print as their provider only.
func explainTargets(cfg json.RawMessage) []string {
	var v any
	if json.Unmarshal(cfg, &v) != nil {
		return nil
	}
	var out []string
	var walk func(prefix string, v any, keyed bool)
	walk = func(prefix string, v any, keyed bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				walk(strings.TrimPrefix(prefix+"."+k, "."), c, explainKey.MatchString(k))
			}
		case []any:
			for i, c := range x {
				walk(fmt.Sprintf("%s[%d]", prefix, i), c, keyed)
			}
		case string:
			if keyed && x != "" {
				out = append(out, prefix+" = "+redactValue(x))
			}
		case float64:
			if keyed {
				out = append(out, fmt.Sprintf("%s = %v", prefix, x))
			}
		}
	}
	walk("", v, false)
	sort.Strings(out)
	return out
}

var (
	userInfo = regexp.MustCompile(`://[^/@\s]*@`)
	kvSecret = regexp.MustCompile(`(?i)(password|pwd|secret|token)=\S+`) // key=value DSNs
)

func redactValue(s string) string {
	s = secretRefRe.ReplaceAllString(s, "$${$1:<redacted>}")
	s = userInfo.ReplaceAllString(s, "://<redacted>@")
	s = kvSecret.ReplaceAllString(s, "$1=<redacted>")
	if i := strings.IndexByte(s, '?'); i >= 0 && strings.Contains(s, "://") {
		s = s[:i] + "?<redacted>"
	}
	return s
}

func redactURL(s string) string {
	if s == "" {
		return "(not set)"
	}
	return redactValue(s)
}
