package snmp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Columns walked for topology; only what is used, so the varbind cap is not spent on the rest.
const (
	oidLLDPLocChassis = "1.0.8802.1.1.2.1.3.2"
	oidLLDPLocName    = "1.0.8802.1.1.2.1.3.3"
	oidLLDPRem        = "1.0.8802.1.1.2.1.4.1.1" // lldpRemEntry: column.timeMark.localPort.index
	oidCDPCache       = "1.3.6.1.4.1.9.9.23.1.2.1.1"
	maxNeighbors      = 5_000 // varbinds per device and poll
)

var topologyOIDs = []string{
	oidLLDPLocChassis, oidLLDPLocName,
	oidLLDPRem + ".5", oidLLDPRem + ".7", oidLLDPRem + ".9", // chassis id, port id, system name
	oidCDPCache + ".4", oidCDPCache + ".6", oidCDPCache + ".7", // address, device id, port id
}

// Device is one end of an adjacency. ID is the stable key (LLDP chassis id, CDP device id, or the
// operator's target name for the polled device); Addr is the management address a neighbour
// announced, if any. The polled device's own address is never part of it.
type Device struct {
	ID, Name, Addr string
}

// Neighbor is one adjacency seen from the polled device.
type Neighbor struct {
	Kind       string // lldp or cdp
	LocalPort  string
	Remote     Device
	RemotePort string
}

func text(v any) string {
	switch b := v.(type) {
	case []byte:
		for _, c := range b {
			if c < 0x20 || c > 0x7e {
				parts := make([]string, len(b))
				for i, c := range b {
					parts[i] = fmt.Sprintf("%02x", c)
				}
				return strings.Join(parts, ":")
			}
		}
		return string(b)
	case string:
		return b
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func addrText(v any) string {
	if b, ok := v.([]byte); ok && (len(b) == 4 || len(b) == 16) {
		if a, ok := netip.AddrFromSlice(b); ok {
			return a.Unmap().String()
		}
	}
	return ""
}

// split returns the column and the index of an entry OID below prefix.
func split(name, prefix string) (col string, idx []string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimPrefix(name, "."), prefix+".")
	if !found {
		return "", nil, false
	}
	parts := strings.Split(rest, ".")
	return parts[0], parts[1:], len(parts) > 1
}

type row struct{ chassis, port, name, addr string }

func rowOf(m map[string]*row, idx []string) *row {
	k := strings.Join(idx, ".")
	if m[k] == nil {
		m[k] = &row{}
	}
	return m[k]
}

// ParseNeighbors reads LLDP-MIB lldpRemTable and CISCO-CDP-MIB cdpCacheTable rows. A remote is
// keyed by its chassis id (LLDP) or device id (CDP), else by its system name. Rows come out
// sorted so a poll is reproducible.
func ParseNeighbors(pdus []gosnmp.SnmpPDU) []Neighbor {
	lldp, cdp := map[string]*row{}, map[string]*row{}
	for _, p := range pdus {
		if col, idx, ok := split(p.Name, oidLLDPRem); ok && len(idx) == 3 {
			r := rowOf(lldp, idx)
			switch col {
			case "5":
				r.chassis = text(p.Value)
			case "7":
				r.port = text(p.Value)
			case "9":
				r.name = text(p.Value)
			}
		} else if col, idx, ok := split(p.Name, oidCDPCache); ok && len(idx) == 2 {
			r := rowOf(cdp, idx)
			switch col {
			case "4":
				r.addr = addrText(p.Value)
			case "6":
				r.name = text(p.Value)
			case "7":
				r.port = text(p.Value)
			}
		}
	}
	var out []Neighbor
	add := func(kind string, m map[string]*row, localPos int) {
		for k, r := range m {
			id := r.chassis
			if kind == "cdp" || id == "" {
				id = r.name
			}
			if id == "" {
				continue
			}
			out = append(out, Neighbor{kind, strings.Split(k, ".")[localPos],
				Device{ID: strings.ToLower(id), Name: cmpName(r.name, id), Addr: r.addr}, r.port})
		}
	}
	add("lldp", lldp, 1) // timeMark.localPort.index
	add("cdp", cdp, 0)   // ifIndex.deviceIndex
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Kind+a.LocalPort+a.Remote.ID+a.RemotePort < b.Kind+b.LocalPort+b.Remote.ID+b.RemotePort
	})
	return out
}

func cmpName(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

// pduText returns the value of the first PDU below prefix.
func pduText(pdus []gosnmp.SnmpPDU, prefix string) string {
	for _, p := range pdus {
		if strings.HasPrefix(strings.TrimPrefix(p.Name, "."), prefix+".") {
			return text(p.Value)
		}
	}
	return ""
}

// LocalDevice is the polled device: keyed by its LLDP chassis id, else by the operator's target
// name; named by its system name, else by the target name.
func LocalDevice(pdus []gosnmp.SnmpPDU, targetName string) Device {
	d := Device{ID: strings.ToLower(pduText(pdus, oidLLDPLocChassis)), Name: pduText(pdus, oidLLDPLocName)}
	if d.ID == "" {
		d.ID = strings.ToLower(targetName)
	}
	if d.Name == "" {
		d.Name = targetName
	}
	return d
}

// EmitNeighbors sends one `network.neighbor` log record per adjacency; the worker turns them into
// `entity_links` of kind lldp or cdp between `network_device` entities.
func EmitNeighbors(out sink.Sink, local Device, ns []Neighbor, at time.Time) {
	for _, n := range ns {
		out.Log("INFO", "neighbor", map[string]string{
			"event.name":       "network.neighbor",
			"link.kind":        n.Kind,
			"link.local":       local.Name,
			"link.local_id":    local.ID,
			"link.local_port":  n.LocalPort,
			"link.remote":      n.Remote.Name,
			"link.remote_id":   n.Remote.ID,
			"link.remote_addr": n.Remote.Addr,
			"link.remote_port": n.RemotePort,
		}, at)
	}
}

// PollNeighbors walks one device and emits its adjacencies. Whatever Walk read before an error
// is used (a device without CDP still gives its LLDP neighbours); only an empty walk is an error.
func PollNeighbors(ctx context.Context, t Target, out sink.Sink, at time.Time) error {
	pdus, err := Walk(ctx, t, topologyOIDs, maxNeighbors)
	if len(pdus) == 0 {
		return err
	}
	EmitNeighbors(out, LocalDevice(pdus, t.Name), ParseNeighbors(pdus), at)
	return nil
}

// RunTopology is the `topology` agent module: every interval, walk each configured device, each
// poll under its own deadline.
func RunTopology(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c struct {
		Enabled     *bool    `json:"enabled"`
		Interval    string   `json:"interval"`
		PollTimeout string   `json:"poll_timeout"`
		Targets     []Target `json:"targets"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	for _, tg := range c.Targets {
		if err := tg.Validate(); err != nil {
			return err
		}
	}
	every := max(host.Duration(c.Interval, 5*time.Minute, time.Minute), time.Minute)
	deadline := min(host.Duration(c.PollTimeout, 30*time.Second, time.Second), every)
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, tg := range c.Targets {
			pc, cancel := context.WithTimeout(ctx, deadline)
			_ = PollNeighbors(pc, tg, out, time.Now()) // an unreachable device is retried next round
			cancel()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
