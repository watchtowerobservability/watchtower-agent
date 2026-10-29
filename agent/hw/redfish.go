// Package hw reads hardware health: Redfish (DMTF) BMCs, ipmitool sensor output and NUT UPS
// servers. Addresses, accounts and tool paths exist only in the agent's own file; none of them
// is exported, logged or put in an error.
package hw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxBody    = 4 << 20
	maxMembers = 64 // per collection; a rack-scale chassis list is cut here
)

// Redfish is one BMC.
type Redfish struct {
	Name               string `json:"name"` // shown as hw.bmc
	BaseURL            string `json:"base_url"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"` // BMCs often carry self-signed certificates
	Scope              Scope  `json:"scope"`                // what the BMC serves; stamped on every sample
}

type link struct {
	ID string `json:"@odata.id"`
}

type status struct {
	State  string `json:"State"`
	Health string `json:"Health"`
}

type collection struct {
	Members []link `json:"Members"`
}

type rfClient struct {
	cfg Redfish
	hc  *http.Client
	err error // first non-fatal error of this poll
}

func newRFClient(r Redfish) (*rfClient, error) {
	u, err := url.Parse(r.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("redfish base_url is not an http(s) URL")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: r.InsecureSkipVerify} //nolint:gosec // local opt-in for self-signed BMCs
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, errors.New("redfish ca_file cannot be read")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("redfish ca_file has no certificates")
		}
		tc.RootCAs = pool
	}
	hc := netguard.NewClientWith(netguard.FromEnv("agent"), netguard.Options{}, func(tr *http.Transport) {
		tr.TLSClientConfig = tc
		tr.DisableKeepAlives = true
	})
	hc.Timeout = 10 * time.Second
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // never forward the password
	return &rfClient{cfg: r, hc: hc}, nil
}

func (c *rfClient) scrub(err error) error {
	msg := err.Error()
	u, _ := url.Parse(c.cfg.BaseURL)
	for _, s := range []string{c.cfg.BaseURL, u.Host, c.cfg.Username, c.cfg.Password} {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "<redacted>")
		}
	}
	return errors.New(msg)
}

// get fetches path (a Redfish resource id) into v.
func (c *rfClient) get(ctx context.Context, path string, v any) error {
	if !strings.HasPrefix(path, "/redfish/v1") {
		return errors.New("redfish link leaves the service root")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.BaseURL, "/")+path, nil)
	if err != nil {
		return c.scrub(err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return c.scrub(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("redfish %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

// try is get that records the error and goes on, so one broken resource does not hide the rest.
func (c *rfClient) try(ctx context.Context, path string, v any) bool {
	if path == "" {
		return false
	}
	if err := c.get(ctx, path, v); err != nil {
		if c.err == nil {
			c.err = err
		}
		return false
	}
	return true
}

func (c *rfClient) members(ctx context.Context, path string) []link {
	var col collection
	if !c.try(ctx, path, &col) {
		return nil
	}
	return col.Members[:min(len(col.Members), maxMembers)]
}

func emitStatus(out sink.Sink, attrs map[string]string, typ string, s status, at time.Time) {
	if s.State == "Absent" {
		return
	}
	var state string
	switch s.Health {
	case "OK":
		state = "ok"
	case "Warning":
		state = "degraded"
	case "Critical":
		state = "failed"
	default:
		return
	}
	emitState(out, attrs, typ, state, at)
}

// emitState writes hw.status the OTel way: one series per state, 1 for the current state and 0
// for the others, so a change of state shows as one series falling and another rising.
func emitState(out sink.Sink, attrs map[string]string, typ, state string, at time.Time) {
	for _, s := range []string{"ok", "degraded", "failed"} {
		v := 0.0
		if s == state {
			v = 1
		}
		out.Gauge("hw.status", "1", v, sink.With(attrs, "hw.type", typ, "hw.state", s), at)
	}
}

func emitNum(out sink.Sink, name, unit string, v *float64, typ string, attrs map[string]string, at time.Time) {
	if v != nil {
		out.Gauge(name, unit, *v, sink.With(attrs, "hw.type", typ), at)
	}
}

func nameOf(parts ...string) string {
	for _, p := range parts {
		if p != "" {
			return p
		}
	}
	return "unknown"
}

// PollRedfish reads Systems, Chassis (thermal, power) and Storage of one BMC. It returns the
// first error after emitting everything it could read.
func PollRedfish(ctx context.Context, r Redfish, out sink.Sink, at time.Time) error {
	out = withScope(out, r.Scope)
	c, err := newRFClient(r)
	if err != nil {
		return err
	}
	base := map[string]string{"hw.bmc": r.Name}
	var root struct {
		Systems, Chassis link
	}
	if err := c.get(ctx, "/redfish/v1", &root); err != nil {
		out.Gauge("hw.bmc.up", "1", 0, base, at)
		return err
	}
	for _, l := range c.members(ctx, root.Systems.ID) {
		c.system(ctx, out, base, l.ID, at)
	}
	for _, l := range c.members(ctx, root.Chassis.ID) {
		c.chassis(ctx, out, base, l.ID, at)
	}
	out.Gauge("hw.bmc.up", "1", 1, base, at)
	return c.err
}

func (c *rfClient) system(ctx context.Context, out sink.Sink, base map[string]string, path string, at time.Time) {
	var s struct {
		ID, Name string
		Status   status
		Storage  link
	}
	if !c.try(ctx, path, &s) {
		return
	}
	emitStatus(out, sink.With(base, "hw.id", nameOf(s.ID), "hw.name", nameOf(s.Name, s.ID)), "enclosure", s.Status, at)
	for _, l := range c.members(ctx, s.Storage.ID) {
		c.storage(ctx, out, base, l.ID, at)
	}
}

// storage reads controllers, drives and volumes of one Storage resource (INF-013). Vendor array
// APIs are known gap G-23.
func (c *rfClient) storage(ctx context.Context, out sink.Sink, base map[string]string, path string, at time.Time) {
	var s struct {
		ID                 string
		StorageControllers []struct {
			MemberID, Name string
			Status         status
		}
		Drives  []link
		Volumes link
	}
	if !c.try(ctx, path, &s) {
		return
	}
	for _, sc := range s.StorageControllers {
		emitStatus(out, sink.With(base, "hw.id", nameOf(sc.MemberID, s.ID), "hw.name", nameOf(sc.Name, s.ID)), "disk_controller", sc.Status, at)
	}
	for _, l := range s.Drives[:min(len(s.Drives), maxMembers)] {
		var d struct {
			ID, Name, MediaType, Protocol string
			CapacityBytes                 *float64
			Status                        status
		}
		if !c.try(ctx, l.ID, &d) {
			continue
		}
		a := sink.With(base, "hw.id", nameOf(d.ID), "hw.name", nameOf(d.Name, d.ID), "hw.storage", s.ID, "hw.media", d.MediaType)
		emitStatus(out, a, "physical_disk", d.Status, at)
		emitNum(out, "hw.physical_disk.size", "By", d.CapacityBytes, "physical_disk", a, at)
	}
	for _, l := range c.members(ctx, s.Volumes.ID) {
		var v struct {
			ID, Name      string
			CapacityBytes *float64
			Status        status
		}
		if !c.try(ctx, l.ID, &v) {
			continue
		}
		a := sink.With(base, "hw.id", nameOf(v.ID), "hw.name", nameOf(v.Name, v.ID), "hw.storage", s.ID)
		emitStatus(out, a, "logical_disk", v.Status, at)
		emitNum(out, "hw.logical_disk.limit", "By", v.CapacityBytes, "logical_disk", a, at)
	}
}

func (c *rfClient) chassis(ctx context.Context, out sink.Sink, base map[string]string, path string, at time.Time) {
	var ch struct {
		ID, Name       string
		Status         status
		Thermal, Power link
	}
	if !c.try(ctx, path, &ch) {
		return
	}
	cb := sink.With(base, "hw.chassis", nameOf(ch.ID))
	emitStatus(out, sink.With(cb, "hw.id", nameOf(ch.ID), "hw.name", nameOf(ch.Name, ch.ID)), "enclosure", ch.Status, at)
	if ch.Thermal.ID != "" {
		var th struct {
			Temperatures []struct {
				MemberID, Name string
				ReadingCelsius *float64
				Status         status
			}
			Fans []struct {
				MemberID, Name, FanName, ReadingUnits string
				Reading                               *float64
				Status                                status
			}
		}
		if c.try(ctx, ch.Thermal.ID, &th) {
			for _, t := range th.Temperatures {
				a := sink.With(cb, "hw.id", nameOf(t.MemberID, t.Name), "hw.name", nameOf(t.Name))
				emitNum(out, "hw.temperature", "Cel", t.ReadingCelsius, "temperature", a, at)
				emitStatus(out, a, "temperature", t.Status, at)
			}
			for _, f := range th.Fans {
				a := sink.With(cb, "hw.id", nameOf(f.MemberID, f.Name, f.FanName), "hw.name", nameOf(f.Name, f.FanName))
				if f.Reading != nil && strings.EqualFold(f.ReadingUnits, "Percent") {
					r := *f.Reading / 100
					emitNum(out, "hw.fan.speed_ratio", "1", &r, "fan", a, at)
				} else {
					emitNum(out, "hw.fan.speed", "rpm", f.Reading, "fan", a, at)
				}
				emitStatus(out, a, "fan", f.Status, at)
			}
		}
	}
	if ch.Power.ID != "" {
		var pw struct {
			PowerControl []struct {
				MemberID, Name     string
				PowerConsumedWatts *float64
			}
			Voltages []struct {
				MemberID, Name string
				ReadingVolts   *float64
			}
			PowerSupplies []struct {
				MemberID, Name       string
				LastPowerOutputWatts *float64
				Status               status
			}
		}
		if c.try(ctx, ch.Power.ID, &pw) {
			for _, p := range pw.PowerControl {
				emitNum(out, "hw.power", "W", p.PowerConsumedWatts, "enclosure", sink.With(cb, "hw.id", nameOf(p.MemberID, p.Name), "hw.name", nameOf(p.Name), "hw.power.direction", "input"), at)
			}
			for _, v := range pw.Voltages {
				emitNum(out, "hw.voltage", "V", v.ReadingVolts, "voltage", sink.With(cb, "hw.id", nameOf(v.MemberID, v.Name), "hw.name", nameOf(v.Name)), at)
			}
			for _, p := range pw.PowerSupplies {
				a := sink.With(cb, "hw.id", nameOf(p.MemberID, p.Name), "hw.name", nameOf(p.Name), "hw.power.direction", "output")
				emitNum(out, "hw.power", "W", p.LastPowerOutputWatts, "power_supply", a, at)
				emitStatus(out, a, "power_supply", p.Status, at)
			}
		}
	}
}
