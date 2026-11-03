package net

// Availability zones on network edges (CFT-E12): cross-zone traffic costs money. The peer's zone
// comes from configured prefixes and, optionally, the Kubernetes nodes (podCIDRs, internal IPs).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// ZonePrefix says a network lies in a zone.
type ZonePrefix struct {
	CIDR string `json:"cidr"`
	Zone string `json:"zone"`
}

type zoneNet struct {
	p    netip.Prefix
	zone string
}

// Zones tags edges. A nil *Zones adds nothing.
type Zones struct {
	local string

	mu     sync.RWMutex
	static []zoneNet
	nets   []zoneNet // longest prefix first
}

func parseZones(in []ZonePrefix) []zoneNet {
	out := make([]zoneNet, 0, len(in))
	for _, z := range in {
		if p, err := netip.ParsePrefix(z.CIDR); err == nil && z.Zone != "" {
			out = append(out, zoneNet{p.Masked(), z.Zone})
		} else {
			slog.Warn("ebpf_net: bad zone prefix", "cidr", z.CIDR)
		}
	}
	return out
}

// NewZones builds the table.
func NewZones(local string, prefixes []ZonePrefix) *Zones {
	z := &Zones{local: local, static: parseZones(prefixes)}
	z.set(nil)
	return z
}

func (z *Zones) set(discovered []zoneNet) {
	nets := append(slices.Clone(z.static), discovered...)
	slices.SortStableFunc(nets, func(a, b zoneNet) int { return b.p.Bits() - a.p.Bits() })
	z.mu.Lock()
	z.nets = nets
	z.mu.Unlock()
}

func (z *Zones) lookup(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	z.mu.RLock()
	defer z.mu.RUnlock()
	for _, n := range z.nets {
		if n.p.Contains(a) {
			return n.zone
		}
	}
	return ""
}

// tag adds what is known. net.cross_zone only when both sides are known.
func (z *Zones) tag(attrs map[string]string, dstAddr string) {
	if z == nil {
		return
	}
	dst := z.lookup(dstAddr)
	if z.local != "" {
		attrs["src.zone"] = z.local
	}
	if dst != "" {
		attrs["dst.zone"] = dst
	}
	if z.local != "" && dst != "" {
		attrs["net.cross_zone"] = fmt.Sprint(z.local != dst)
	}
}

const (
	zoneLabel   = "topology.kubernetes.io/zone"
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount/"
	zoneRefresh = 10 * time.Minute
)

// nodeZones reads the node list document.
func nodeZones(body []byte) ([]zoneNet, error) {
	var doc struct {
		Items []struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				PodCIDRs []string `json:"podCIDRs"`
			} `json:"spec"`
			Status struct {
				Addresses []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("bad node list")
	}
	var out []ZonePrefix
	for _, n := range doc.Items {
		zone := n.Metadata.Labels[zoneLabel]
		if zone == "" {
			continue
		}
		for _, c := range n.Spec.PodCIDRs {
			out = append(out, ZonePrefix{c, zone})
		}
		for _, a := range n.Status.Addresses {
			if ip, err := netip.ParseAddr(a.Address); a.Type == "InternalIP" && err == nil {
				out = append(out, ZonePrefix{netip.PrefixFrom(ip, ip.BitLen()).String(), zone})
			}
		}
	}
	return parseZones(out), nil
}

// followK8s refreshes the node table until ctx ends. Failures keep the last table and only warn.
func (z *Zones) followK8s(ctx context.Context) {
	t := time.NewTicker(zoneRefresh)
	defer t.Stop()
	for {
		if nets, err := fetchNodeZones(ctx); err != nil {
			slog.Warn("ebpf_net: zones from Kubernetes unavailable", "error", err)
		} else {
			z.set(nets)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func fetchNodeZones(ctx context.Context) ([]zoneNet, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("not running in a cluster")
	}
	tok, err := os.ReadFile(saDir + "token")
	if err != nil {
		return nil, errors.New("no service account token")
	}
	ca, err := os.ReadFile(saDir + "ca.crt")
	if err != nil {
		return nil, errors.New("no cluster CA")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	// The API server is on a private address, so netguard's default client would refuse it.
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/api/v1/nodes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	resp, err := hc.Do(req)
	if err != nil {
		return nil, errors.New("node list request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node list: status %d (the agent's role needs list on nodes)", resp.StatusCode)
	}
	body, err := readCapped(resp)
	if err != nil {
		return nil, err
	}
	return nodeZones(body)
}

func readCapped(r *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 64<<20))
}
