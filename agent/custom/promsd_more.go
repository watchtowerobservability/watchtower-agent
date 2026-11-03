package custom

// More service discovery (CFT-A02): file, consulagent, docker, dockerswarm, nomad, eureka, kuma,
// marathon and puppetdb. Each is one list call against the system's own API; tokens can be secret
// references (`${vault:...}`, see agent/secretref.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// doJSON sends one request and decodes a JSON answer into out.
func doJSON(ctx context.Context, hc *http.Client, method, u string, hdr map[string]string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("sd: bad url %s", redact(u))
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("sd %s: request failed", redact(u)) // url.Error would carry query secrets
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, sdMaxBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sd %s: status %d", redact(u), resp.StatusCode)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("sd %s: %w", redact(u), err)
	}
	return nil
}

func bearer(tok string) map[string]string {
	if tok == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + tok}
}

func (c SDConfig) fileSD() ([]TargetSpec, error) {
	var out []TargetSpec
	for _, f := range c.Files {
		got, err := readTargetsFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// consulAgentSD lists the services registered with the local Consul agent (no catalog access).
func (c SDConfig) consulAgentSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["X-Consul-Token"] = c.Token
	}
	var m map[string]struct {
		Service, Address string
		Port             int
		Tags             []string
	}
	if err := doJSON(ctx, hc, http.MethodGet, strings.TrimSuffix(c.URL, "/")+"/v1/agent/services", hdr, nil, &m); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, s := range m {
		if (len(c.Services) > 0 && !contains(c.Services, s.Service)) || s.Port <= 0 {
			continue
		}
		host := s.Address
		if host == "" {
			host = "127.0.0.1"
		}
		out = append(out, TargetSpec{URL: c.scrapeURL(host, s.Port), Labels: map[string]string{
			"consul_service": s.Service, "consul_tags": "," + strings.Join(s.Tags, ",") + ","}})
	}
	return out, nil
}

// dockerClient talks to the engine: unix socket (default /var/run/docker.sock) or an http(s) URL.
func (c SDConfig) dockerClient(hc *http.Client) (*http.Client, string) {
	host := c.Host
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	if sock, ok := strings.CutPrefix(host, "unix://"); ok {
		var d net.Dialer
		return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return d.DialContext(ctx, "unix", sock) },
		}}, "http://docker"
	}
	return hc, strings.TrimSuffix(host, "/")
}

func (c SDConfig) dockerSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	dc, base := c.dockerClient(hc)
	var cs []struct {
		ID              string `json:"Id"`
		Names           []string
		Labels          map[string]string
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
		Ports []struct {
			PrivatePort int
			Type        string
		}
	}
	if err := doJSON(ctx, dc, http.MethodGet, base+"/containers/json", nil, nil, &cs); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, ct := range cs {
		name := ""
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}
		ports := map[int]bool{}
		for _, p := range ct.Ports {
			if p.Type == "tcp" && p.PrivatePort > 0 {
				ports[p.PrivatePort] = true
			}
		}
		if len(ports) == 0 && c.Port > 0 {
			ports[c.Port] = true
		}
		for netName, n := range ct.NetworkSettings.Networks {
			if n.IPAddress == "" {
				continue
			}
			for p := range ports {
				l := map[string]string{"__meta_docker_container_id": ct.ID, "__meta_docker_container_name": name,
					"__meta_docker_network_name": netName, "container": name}
				for k, v := range ct.Labels {
					l["__meta_docker_container_label_"+metaName(k)] = v
				}
				out = append(out, TargetSpec{URL: c.scrapeURL(n.IPAddress, p), Labels: l})
			}
		}
	}
	return out, nil
}

// dockerSwarmSD: role "nodes" (each node's address and Port, default 9100) or "tasks" (each
// running task's overlay addresses and Port).
func (c SDConfig) dockerSwarmSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	dc, base := c.dockerClient(hc)
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	if c.Role == "nodes" {
		var nodes []struct {
			ID          string
			Description struct{ Hostname string }
			Status      struct{ State, Addr string }
		}
		if err := doJSON(ctx, dc, http.MethodGet, base+"/nodes", nil, nil, &nodes); err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if n.Status.State == "ready" && n.Status.Addr != "" {
				out = append(out, TargetSpec{URL: c.scrapeURL(n.Status.Addr, port), Labels: map[string]string{
					"__meta_dockerswarm_node_id": n.ID, "node": n.Description.Hostname}})
			}
		}
		return out, nil
	}
	var tasks []struct {
		ID, ServiceID, NodeID string
		Status                struct{ State string }
		NetworksAttachments   []struct{ Addresses []string }
	}
	if err := doJSON(ctx, dc, http.MethodGet, base+"/tasks", nil, nil, &tasks); err != nil {
		return nil, err
	}
	for _, t := range tasks {
		if t.Status.State != "running" {
			continue
		}
		for _, na := range t.NetworksAttachments {
			for _, a := range na.Addresses {
				ip, _, _ := strings.Cut(a, "/")
				out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: map[string]string{
					"__meta_dockerswarm_task_id": t.ID, "__meta_dockerswarm_service_id": t.ServiceID, "__meta_dockerswarm_node_id": t.NodeID}})
			}
		}
	}
	return out, nil
}

func (c SDConfig) nomadSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	base := strings.TrimSuffix(c.URL, "/")
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["X-Nomad-Token"] = c.Token
	}
	ns := "?namespace=*"
	var groups []struct {
		Namespace string
		Services  []struct{ ServiceName string }
	}
	if err := doJSON(ctx, hc, http.MethodGet, base+"/v1/services"+ns, hdr, nil, &groups); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, g := range groups {
		for _, s := range g.Services {
			if len(c.Services) > 0 && !contains(c.Services, s.ServiceName) {
				continue
			}
			var regs []struct {
				Address, ServiceName, NodeID, Datacenter, Namespace, JobID string
				Port                                                       int
				Tags                                                       []string
			}
			u := base + "/v1/service/" + url.PathEscape(s.ServiceName) + "?namespace=" + url.QueryEscape(g.Namespace)
			if err := doJSON(ctx, hc, http.MethodGet, u, hdr, nil, &regs); err != nil {
				return nil, err
			}
			for _, r := range regs {
				if r.Address != "" && r.Port > 0 {
					out = append(out, TargetSpec{URL: c.scrapeURL(r.Address, r.Port), Labels: map[string]string{
						"nomad_service": r.ServiceName, "nomad_namespace": r.Namespace, "nomad_dc": r.Datacenter, "nomad_job": r.JobID,
						"nomad_node_id": r.NodeID, "nomad_tags": "," + strings.Join(r.Tags, ",") + ","}})
				}
			}
		}
	}
	return out, nil
}

func (c SDConfig) eurekaSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	var doc struct {
		Applications struct {
			Application []struct {
				Name     string `json:"name"`
				Instance []struct {
					HostName string `json:"hostName"`
					IPAddr   string `json:"ipAddr"`
					Status   string `json:"status"`
					Port     struct {
						N int `json:"$"`
					} `json:"port"`
					Metadata map[string]string `json:"metadata"`
				} `json:"instance"`
			} `json:"application"`
		} `json:"applications"`
	}
	if err := doJSON(ctx, hc, http.MethodGet, strings.TrimSuffix(c.URL, "/")+"/apps", nil, nil, &doc); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, app := range doc.Applications.Application {
		for _, in := range app.Instance {
			host := in.IPAddr
			if host == "" {
				host = in.HostName
			}
			if in.Status != "UP" || host == "" || in.Port.N <= 0 {
				continue
			}
			l := map[string]string{"eureka_app": app.Name, "eureka_hostname": in.HostName}
			for k, v := range in.Metadata {
				l["__meta_eureka_app_instance_metadata_"+metaName(k)] = v
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(host, in.Port.N), Labels: l})
		}
	}
	return out, nil
}

// kumaSD reads Kuma's monitoring assignment discovery service (MADS v1, REST/JSON form).
func (c SDConfig) kumaSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	req, _ := json.Marshal(map[string]any{"node": map[string]string{"id": "watchtower-agent"},
		"type_url": "type.googleapis.com/kuma.observability.v1.MonitoringAssignment"})
	var resp struct {
		Resources []struct {
			Mesh    string `json:"mesh"`
			Service string `json:"service"`
			Targets []struct {
				Name        string            `json:"name"`
				Scheme      string            `json:"scheme"`
				Address     string            `json:"address"`
				MetricsPath string            `json:"metrics_path"`
				Labels      map[string]string `json:"labels"`
			} `json:"targets"`
		} `json:"resources"`
	}
	if err := doJSON(ctx, hc, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/v3/discovery:monitoringassignments", nil, req, &resp); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, r := range resp.Resources {
		for _, t := range r.Targets {
			scheme, path := t.Scheme, t.MetricsPath
			if scheme == "" {
				scheme = "http"
			}
			if path == "" {
				path = "/metrics"
			}
			l := map[string]string{"kuma_mesh": r.Mesh, "kuma_service": r.Service, "kuma_dataplane": t.Name}
			for k, v := range t.Labels {
				l[k] = v
			}
			out = append(out, TargetSpec{URL: scheme + "://" + t.Address + path, Labels: l})
		}
	}
	return out, nil
}

func (c SDConfig) marathonSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	var doc struct {
		Apps []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
			Tasks  []struct {
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
				State string `json:"state"`
			} `json:"tasks"`
		} `json:"apps"`
	}
	if err := doJSON(ctx, hc, http.MethodGet, strings.TrimSuffix(c.URL, "/")+"/v2/apps/?embed=apps.tasks", bearer(c.Token), nil, &doc); err != nil {
		return nil, err
	}
	var out []TargetSpec
	for _, a := range doc.Apps {
		for _, t := range a.Tasks {
			if t.State != "" && t.State != "TASK_RUNNING" {
				continue
			}
			for i, p := range t.Ports {
				l := map[string]string{"marathon_app": a.ID, "marathon_port_index": strconv.Itoa(i)}
				for k, v := range a.Labels {
					l["__meta_marathon_app_label_"+metaName(k)] = v
				}
				out = append(out, TargetSpec{URL: c.scrapeURL(t.Host, p), Labels: l})
			}
		}
	}
	return out, nil
}

// puppetdbSD runs a PQL query (Query, e.g. `resources { type = "Class" and title = "Prometheus::Node_exporter" }`)
// and scrapes each certname on Port.
func (c SDConfig) puppetdbSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	body, _ := json.Marshal(map[string]string{"query": c.Query})
	var res []struct {
		Certname    string `json:"certname"`
		Environment string `json:"environment"`
	}
	if err := doJSON(ctx, hc, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/pdb/query/v4", bearer(c.Token), body, &res); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []TargetSpec
	for _, r := range res {
		if r.Certname == "" || seen[r.Certname] {
			continue
		}
		seen[r.Certname] = true
		out = append(out, TargetSpec{URL: c.scrapeURL(r.Certname, c.Port), Labels: map[string]string{
			"puppetdb_certname": r.Certname, "puppetdb_environment": r.Environment}})
	}
	return out, nil
}
