package custom

// More discovery sources (CFT-A02): kubelet, Scaleway.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func init() {
	sdHTTPTypes["kubelet"] = SDConfig.kubeletSD
	sdHTTPTypes["scaleway"] = SDConfig.scalewaySD
}

const saTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // a path

// kubeletSD lists the pods of this node from the kubelet's /pods (URL, default https://$NODE_IP:10250),
// which needs no API server access; one target per named `metrics` port, or Port on each pod IP.
func (c SDConfig) kubeletSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	base := c.URL
	if base == "" {
		ip := os.Getenv("NODE_IP")
		if ip == "" {
			return nil, errors.New("sd kubelet: set url or NODE_IP")
		}
		base = "https://" + ip + ":10250"
	}
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = "Bearer " + c.Token
	} else if b, err := os.ReadFile(saTokenFile); err == nil {
		hdr["Authorization"] = "Bearer " + strings.TrimSpace(string(b))
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				NodeName   string `json:"nodeName"`
				Containers []struct {
					Name  string `json:"name"`
					Ports []struct {
						Name string `json:"name"`
						Port int    `json:"containerPort"`
					} `json:"ports"`
				} `json:"containers"`
			} `json:"spec"`
			Status struct {
				PodIP string `json:"podIP"`
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := doJSON(ctx, hc, http.MethodGet, strings.TrimSuffix(base, "/")+"/pods", hdr, nil, &doc); err != nil {
		return nil, fmt.Errorf("sd kubelet: %w", err)
	}
	var out []TargetSpec
	for _, p := range doc.Items {
		if p.Status.Phase != "Running" || p.Status.PodIP == "" {
			continue
		}
		l := map[string]string{"namespace": p.Metadata.Namespace, "pod": p.Metadata.Name, "node": p.Spec.NodeName}
		for k, v := range p.Metadata.Labels {
			l["__meta_kubernetes_pod_label_"+metaName(k)] = v
		}
		if c.Port > 0 {
			out = append(out, TargetSpec{URL: c.scrapeURL(p.Status.PodIP, c.Port), Labels: l})
			continue
		}
		for _, ct := range p.Spec.Containers {
			for _, port := range ct.Ports {
				if strings.Contains(port.Name, "metrics") {
					out = append(out, TargetSpec{URL: c.scrapeURL(p.Status.PodIP, port.Port), Labels: l})
				}
			}
		}
	}
	return out, nil
}

// scalewaySD lists instances of one zone (Zone, default fr-par-1; Token is the secret key; URL for
// tests); Port is the exporter port (default 9100). Only running servers.
func (c SDConfig) scalewaySD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	zone, base, port := c.Zone, c.URL, c.Port
	if zone == "" {
		zone = "fr-par-1"
	}
	if base == "" {
		base = "https://api.scaleway.com"
	}
	if port <= 0 {
		port = 9100
	}
	if c.Token == "" {
		return nil, errors.New("sd scaleway: token required")
	}
	var out []TargetSpec
	for page := 1; page <= sdMaxPages; page++ {
		var res struct {
			Servers []struct {
				Name      string   `json:"name"`
				State     string   `json:"state"`
				Tags      []string `json:"tags"`
				PrivateIP string   `json:"private_ip"`
				PublicIP  *struct {
					Address string `json:"address"`
				} `json:"public_ip"`
			} `json:"servers"`
		}
		u := fmt.Sprintf("%s/instance/v1/zones/%s/servers?per_page=100&page=%d", strings.TrimSuffix(base, "/"), zone, page)
		if err := doJSON(ctx, hc, http.MethodGet, u, map[string]string{"X-Auth-Token": c.Token}, nil, &res); err != nil {
			return nil, fmt.Errorf("sd scaleway: %w", err)
		}
		for _, s := range res.Servers {
			ip := s.PrivateIP
			if s.PublicIP != nil && (c.Public || ip == "") {
				ip = s.PublicIP.Address
			}
			if s.State == "running" && ip != "" {
				out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: map[string]string{"instance_name": s.Name, "zone": zone, "tags": strings.Join(s.Tags, ",")}})
			}
		}
		if len(res.Servers) < 100 {
			break
		}
	}
	return out, nil
}
