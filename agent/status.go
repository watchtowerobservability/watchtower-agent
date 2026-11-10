package main

// The local status page: `status_listen: 127.0.0.1:2850` serves the agent's version, redacted
// endpoints, module health and export counters as HTML (/) and JSON (/status.json), and
// `wt-agent status` prints the JSON of a running agent. Loopback only, read only, no secrets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"runtime"
	"sort"
	"time"
)

// checkLoopbackAddr accepts an empty address or host:port with a loopback IP or "localhost".
func checkLoopbackAddr(addr string) error {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("must be a loopback address (127.0.0.1:PORT)")
	}
	return nil
}

type moduleStatus struct {
	Name      string `json:"name"`
	Healthy   bool   `json:"healthy"`
	Status    string `json:"status"`
	Restarts  int    `json:"restarts"`
	LastError string `json:"last_error,omitempty"`
	Since     string `json:"since,omitempty"`
}

type agentStatus struct {
	Version  string             `json:"version"`
	AgentID  string             `json:"agent_id"`
	OS       string             `json:"os"`
	Arch     string             `json:"arch"`
	Endpoint string             `json:"endpoint"`
	Fleet    string             `json:"fleet_endpoint"`
	Proxy    bool               `json:"proxy"`
	Modules  []moduleStatus     `json:"modules"`
	Export   map[string]float64 `json:"export"`
}

func snapshot(health map[string]ModuleHealth, stats map[string]float64, agentID string, local *LocalConfig) agentStatus {
	st := agentStatus{Version: Version, AgentID: agentID, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Endpoint: redactURL(local.Endpoint), Fleet: redactURL(local.FleetEndpoint), Proxy: local.Proxy != "", Export: stats}
	for n, h := range health {
		m := moduleStatus{Name: n, Healthy: h.Healthy, Status: h.Status, Restarts: h.Restarts, LastError: redactValue(h.LastError)}
		if !h.Since.IsZero() {
			m.Since = h.Since.UTC().Format(time.RFC3339)
		}
		st.Modules = append(st.Modules, m)
	}
	sort.Slice(st.Modules, func(i, j int) bool { return st.Modules[i].Name < st.Modules[j].Name })
	return st
}

var statusPage = template.Must(template.New("status").Parse(`<!doctype html><meta charset=utf-8><title>wt-agent status</title>
<h1>wt-agent {{.Version}}</h1>
<p>agent {{.AgentID}} on {{.OS}}/{{.Arch}}; exports to {{.Endpoint}}; fleet {{.Fleet}}{{if .Proxy}}; via proxy{{end}}</p>
<table border=1 cellpadding=4><tr><th>module<th>status<th>restarts<th>last error
{{range .Modules}}<tr><td>{{.Name}}<td>{{if .Healthy}}ok{{else}}{{.Status}}{{end}}<td>{{.Restarts}}<td>{{.LastError}}
{{end}}</table>
<h2>export</h2><ul>{{range $k, $v := .Export}}<li>{{$k}} = {{$v}}{{end}}</ul>`))

// statusHandler serves the snapshot of the running supervisor and exporter.
func statusHandler(sup *Supervisor, out *OTLP, agentID string, local *LocalConfig) http.Handler {
	return statusHandlerFor(func() agentStatus { return snapshot(sup.Health(), out.SelfStats(), agentID, local) })
}

func statusHandlerFor(cur func() agentStatus) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cur())
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = statusPage.Execute(w, cur())
	})
	return mux
}

// serveStatus listens on addr (already validated as loopback) until ctx ends.
func serveStatus(ctx context.Context, addr string, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// statusCommand prints the status of the agent that serves status_listen from cfgPath.
func statusCommand(cfgPath string, w io.Writer) error {
	local, err := LoadLocal(cfgPath)
	if err != nil {
		return err
	}
	if local.StatusListen == "" {
		return errors.New("status_listen is not set in the config")
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Get("http://" + local.StatusListen + "/status.json")
	if err != nil {
		return fmt.Errorf("agent not reachable: %w", err)
	}
	defer resp.Body.Close()
	var st agentStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return err
	}
	fmt.Fprintf(w, "wt-agent %s (%s) %s/%s\nexports to: %s\n", st.Version, st.AgentID, st.OS, st.Arch, st.Endpoint)
	for _, m := range st.Modules {
		fmt.Fprintf(w, "  %-20s %-10s restarts=%d %s\n", m.Name, m.Status, m.Restarts, m.LastError)
	}
	return nil
}
