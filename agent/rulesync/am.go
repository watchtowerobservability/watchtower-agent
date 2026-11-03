package rulesync

// AlertmanagerConfig sync (CFT-A09, Alloy mimir.alerts.kubernetes parity). Off unless
// `alertmanager_configs: true`: every AlertmanagerConfig (monitoring.coreos.com/v1alpha1) is
// merged into one Alertmanager config the way the Prometheus Operator does it (each CR's route
// becomes a child of the root with a `namespace` matcher, names are prefixed `<ns>/<cr>/`) and
// sent to POST /v1/projects/{prj}/routing:import-alertmanager?apply=true&replace=true whenever it
// changes. That import owns the project's whole routing tree, and its receivers start disabled
// without secrets (the CRDs reference Kubernetes secrets, which never leave the cluster): enter
// the secrets in Watchtower and enable them after a change.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type amList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	} `json:"items"`
}

// snake turns operator camelCase keys into Alertmanager keys: groupBy -> group_by, apiURL -> api_url.
func snake(s string) string {
	var b strings.Builder
	r := []rune(s)
	for i, c := range r {
		if unicode.IsUpper(c) {
			if i > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1])) {
				b.WriteByte('_')
			}
			c = unicode.ToLower(c)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// matcher turns {name, value, matchType|regex} into an Alertmanager matcher string.
func matcher(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		s, ok := v.(string)
		return s, ok
	}
	name, _ := m["name"].(string)
	val, _ := m["value"].(string)
	op, _ := m["matchType"].(string)
	if op == "" {
		op = "="
		if re, _ := m["regex"].(bool); re {
			op = "=~"
		}
	}
	if name == "" {
		return "", false
	}
	q, _ := json.Marshal(val)
	return name + op + string(q), true
}

var matcherKeys = map[string]string{"matchers": "matchers", "sourceMatch": "source_matchers", "targetMatch": "target_matchers"}

// isSecretRef reports a Kubernetes SecretKeySelector ({name, key}), which is dropped.
func isSecretRef(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) > 3 {
		return false
	}
	_, n := m["name"]
	_, k := m["key"]
	return n && k
}

// convert rewrites keys recursively; receiver/time-interval names get the CR prefix.
func convert(v any, prefix string) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			if to, ok := matcherKeys[k]; ok {
				var ms []string
				for _, m := range asList(val) {
					if s, ok := matcher(m); ok {
						ms = append(ms, s)
					}
				}
				out[to] = ms
				continue
			}
			if isSecretRef(val) {
				continue
			}
			switch k {
			case "receiver":
				if s, ok := val.(string); ok && s != "" {
					val = prefix + s
				}
			case "muteTimeIntervals", "activeTimeIntervals":
				var ns []string
				for _, n := range asList(val) {
					if s, ok := n.(string); ok {
						ns = append(ns, prefix+s)
					}
				}
				val = ns
			}
			out[snake(k)] = convert(val, prefix)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, convert(e, prefix))
		}
		return out
	}
	return v
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// MergeAlertmanager builds one Alertmanager config (as JSON, which is YAML) from the CR list.
func MergeAlertmanager(raw []byte) ([]byte, error) {
	var l amList
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, errors.New("malformed AlertmanagerConfig list")
	}
	receivers := []any{map[string]any{"name": "wt-null"}}
	var routes, inhibit, intervals []any
	for _, it := range l.Items {
		ns, prefix := it.Metadata.Namespace, it.Metadata.Namespace+"/"+it.Metadata.Name+"/"
		nsm := "namespace=" + fmt.Sprintf("%q", ns)
		spec, _ := convert(it.Spec, prefix).(map[string]any)
		for _, r := range asList(spec["receivers"]) {
			if m, ok := r.(map[string]any); ok {
				if n, _ := m["name"].(string); n != "" {
					m["name"] = prefix + n
					receivers = append(receivers, m)
				}
			}
		}
		if rt, ok := spec["route"].(map[string]any); ok {
			ms, _ := rt["matchers"].([]string)
			rt["matchers"] = append([]string{nsm}, ms...)
			rt["continue"] = true // every namespace's route sees every alert, as in the operator
			routes = append(routes, rt)
		}
		for _, r := range asList(spec["inhibit_rules"]) {
			if m, ok := r.(map[string]any); ok {
				for _, k := range []string{"source_matchers", "target_matchers"} {
					ms, _ := m[k].([]string)
					m[k] = append([]string{nsm}, ms...)
				}
				inhibit = append(inhibit, m)
			}
		}
		for _, t := range asList(spec["time_intervals"]) {
			if m, ok := t.(map[string]any); ok {
				if n, _ := m["name"].(string); n != "" {
					m["name"] = prefix + n
					intervals = append(intervals, m)
				}
			}
		}
	}
	cfg := map[string]any{"route": map[string]any{"receiver": "wt-null", "routes": routes}, "receivers": receivers}
	if len(inhibit) > 0 {
		cfg["inhibit_rules"] = inhibit
	}
	if len(intervals) > 0 {
		cfg["time_intervals"] = intervals
	}
	return json.Marshal(cfg)
}
