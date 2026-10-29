package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"slices"
)

const maxHostAddrs = 16

// hostAddrs returns the host's non-loopback unicast addresses and interface MACs as JSON string
// arrays (the semconv `host.ip` and `host.mac`). The resource map of the exporter holds strings,
// so the arrays travel as JSON text; the worker stores them as arrays.
// shortcut: link-local addresses are skipped, so a host with only fe80:: is not matched by flows.
func hostAddrs() (ips, macs string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	var ipl, macl []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if len(ifc.HardwareAddr) > 0 {
			macl = append(macl, ifc.HardwareAddr.String())
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			ipl = append(ipl, ip.String())
		}
	}
	return jsonList(ipl), jsonList(macl)
}

func jsonList(l []string) string {
	slices.Sort(l)
	l = slices.Compact(l)
	if len(l) == 0 {
		return ""
	}
	l = l[:min(len(l), maxHostAddrs)]
	b, _ := json.Marshal(l)
	return string(b)
}
