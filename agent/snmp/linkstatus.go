package snmp

// Link status for the network map (INF-018): the topology walk also reads the local port's
// ifOperStatus, ifHighSpeed and 64-bit octet counters, so every network.neighbor record carries
// link.oper_status and, from the second poll on, link.utilization (the busier direction over
// the port speed). The LLDP local port number is mapped to an ifIndex through lldpLocPortId
// matching ifName; when the device does not name its ports that way the number is taken as the
// ifIndex, which is what most switches use.

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCIn        = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOut       = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	oidLLDPLocPortID = "1.0.8802.1.1.2.1.3.7.1.3"
)

var linkOIDs = []string{oidIfOperStatus, oidIfName, oidIfHCIn, oidIfHCOut, oidIfHighSpeed, oidLLDPLocPortID}

// PortState is what the map shows for one local port.
type PortState struct {
	Oper    string // up, down, testing, dormant, notPresent, lowerLayerDown, unknown
	Util    float64
	HasUtil bool
}

var operNames = map[string]string{"1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}

type portSample struct {
	in, out uint64
	at      time.Time
}

// LinkRates keeps the previous octet counters per device and port, to turn them into rates.
type LinkRates struct {
	mu   sync.Mutex
	prev map[string]portSample
}

type port struct {
	oper, name   string
	in, out, mbs uint64
	hasIn        bool
}

func pduUint(p gosnmp.SnmpPDU) uint64 {
	return gosnmp.ToBigInt(p.Value).Uint64()
}

// States reads the port columns of one walk and returns the state per ifIndex and per LLDP
// local port number (both as text keys).
func (lr *LinkRates) States(device string, pdus []gosnmp.SnmpPDU, at time.Time) map[string]PortState {
	ports := map[string]*port{}
	get := func(idx string) *port {
		if ports[idx] == nil {
			ports[idx] = &port{}
		}
		return ports[idx]
	}
	locPort := map[string]string{} // LLDP local port number -> port id text
	for _, p := range pdus {
		name := norm(p.Name)
		switch {
		case suffix(name, oidIfOperStatus) != "":
			get(suffix(name, oidIfOperStatus)).oper = operNames[strconv.FormatUint(pduUint(p), 10)]
		case suffix(name, oidIfName) != "":
			get(suffix(name, oidIfName)).name = text(p.Value)
		case suffix(name, oidIfHCIn) != "":
			pt := get(suffix(name, oidIfHCIn))
			pt.in, pt.hasIn = pduUint(p), true
		case suffix(name, oidIfHCOut) != "":
			get(suffix(name, oidIfHCOut)).out = pduUint(p)
		case suffix(name, oidIfHighSpeed) != "":
			get(suffix(name, oidIfHighSpeed)).mbs = pduUint(p)
		case suffix(name, oidLLDPLocPortID) != "":
			locPort[suffix(name, oidLLDPLocPortID)] = text(p.Value)
		}
	}
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if lr.prev == nil || len(lr.prev) > 100_000 {
		lr.prev = map[string]portSample{}
	}
	out := map[string]PortState{}
	byName := map[string]string{}
	for idx, pt := range ports {
		st := PortState{Oper: pt.oper}
		key := device + "|" + idx
		if pt.hasIn {
			if old, ok := lr.prev[key]; ok && pt.mbs > 0 && pt.in >= old.in && pt.out >= old.out {
				if secs := at.Sub(old.at).Seconds(); secs > 0 {
					bps := float64(max(pt.in-old.in, pt.out-old.out)) * 8 / secs
					st.Util, st.HasUtil = min(bps/(float64(pt.mbs)*1e6), 1), true
				}
			}
			lr.prev[key] = portSample{pt.in, pt.out, at}
		}
		if st.Oper != "" || st.HasUtil {
			out[idx] = st
		}
		if pt.name != "" {
			byName[strings.ToLower(pt.name)] = idx
		}
	}
	for num, id := range locPort {
		if idx, ok := byName[strings.ToLower(id)]; ok {
			if st, ok := out[idx]; ok {
				out["lldp:"+num] = st
			}
		}
	}
	return out
}

// stateOf finds the state of a neighbour's local port: LLDP through the local port table,
// else (and for CDP, whose index is the ifIndex) the number itself.
func stateOf(states map[string]PortState, n Neighbor) (PortState, bool) {
	if n.Kind == "lldp" {
		if st, ok := states["lldp:"+n.LocalPort]; ok {
			return st, true
		}
	}
	st, ok := states[n.LocalPort]
	return st, ok
}
