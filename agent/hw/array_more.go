package hw

// Dell PowerStore REST (/api/rest/...) and HPE 3PAR/Primera/Alletra 9000 WSAPI (/api/v1/...)
// collectors (INF-013). Same hw.* capacity and health set as ONTAP and Pure, same client: every
// request is pinned to the configured origin and redirects are never followed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const mibBytes = 1 << 20

// psLogin opens a PowerStore session: the login GET returns the DELL-EMC-TOKEN CSRF header that
// POSTs need, and the session cookie stays in a jar that only ever talks to the pinned origin.
func (c *arrayClient) psLogin(ctx context.Context) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return errors.New("hw array: cookie jar")
	}
	c.hc.Jar = jar
	h, err := c.do(ctx, http.MethodGet, "/api/rest/login_session", nil)
	if err != nil {
		return err
	}
	if tok := h.Get("DELL-EMC-TOKEN"); tok != "" {
		c.hdr["DELL-EMC-TOKEN"] = tok
	}
	return nil
}

// psItems walks a PowerStore collection with limit/offset paging.
func (c *arrayClient) psItems(ctx context.Context, path, sel string, each func(json.RawMessage)) error {
	for page := range maxArrayPages {
		p := fmt.Sprintf("/api/rest/%s?select=%s&limit=%d&offset=%d", path, sel, maxArrayRecords, page*maxArrayRecords)
		var items []json.RawMessage
		if _, err := c.do(ctx, http.MethodGet, p, &items); err != nil {
			return err
		}
		for _, it := range items {
			each(it)
		}
		if len(items) < maxArrayRecords {
			return nil
		}
	}
	return nil
}

func psState(s string) string {
	switch s {
	case "Healthy", "Ready":
		return "ok"
	case "", "Empty", "Uninitialized", "Initializing", "Destroying":
		return ""
	case "Life_Remaining_Low", "Degraded", "Disconnected":
		return "degraded"
	}
	return "failed" // Faulted, Failed, Offline, Unknown
}

func psHardwareType(t string) string {
	switch t {
	case "Drive":
		return "physical_disk"
	case "Power_Supply":
		return "power_supply"
	case "Fan":
		return "fan"
	case "Battery":
		return "battery"
	case "DIMM":
		return "memory"
	case "Node":
		return "disk_controller"
	case "IO_Module", "SFP":
		return "network"
	}
	return "enclosure"
}

func (c *arrayClient) powerstore(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	if err := c.psLogin(ctx); err != nil {
		return err
	}
	var appliances []struct{ ID, Name string }
	err := c.psItems(ctx, "appliance", "id,name", func(b json.RawMessage) {
		var r struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(b, &r) == nil && r.ID != "" {
			appliances = append(appliances, struct{ ID, Name string }{r.ID, r.Name})
		}
	})
	for _, ap := range appliances {
		var series []struct {
			PhysicalTotal *float64 `json:"physical_total"`
			PhysicalUsed  *float64 `json:"physical_used"`
			LogicalProv   *float64 `json:"logical_provisioned"`
			LogicalUsed   *float64 `json:"logical_used"`
			DataReduction *float64 `json:"data_reduction"`
		}
		body := map[string]string{"entity": "space_metrics_by_appliance", "entity_id": ap.ID, "interval": "Five_Mins"}
		if _, merr := c.doBody(ctx, http.MethodPost, "/api/rest/metrics/generate", body, &series); merr != nil {
			err = cmpErr(err, merr)
			continue
		}
		if len(series) == 0 {
			continue
		}
		last := series[len(series)-1] // samples come oldest first
		a := sink.With(base, "hw.id", ap.ID, "hw.name", nameOf(ap.Name, ap.ID), "hw.storage.kind", "appliance")
		emitNum(out, "hw.logical_disk.limit", "By", last.PhysicalTotal, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", last.PhysicalUsed, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.provisioned", "By", last.LogicalProv, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.logical_usage", "By", last.LogicalUsed, "logical_disk", a, at)
		emitNum(out, "hw.array.data_reduction", "1", last.DataReduction, "logical_disk", a, at)
	}
	verr := c.psItems(ctx, "volume", "id,name,size,state", func(b json.RawMessage) {
		var r struct {
			ID    string   `json:"id"`
			Name  string   `json:"name"`
			Size  *float64 `json:"size"`
			State string   `json:"state"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.ID, "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "volume")
		if s := psState(r.State); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Size, "logical_disk", a, at)
	})
	herr := c.psItems(ctx, "hardware", "id,name,type,lifecycle_state,serial_number", func(b json.RawMessage) {
		var r struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Type   string `json:"type"`
			State  string `json:"lifecycle_state"`
			Serial string `json:"serial_number"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		if s := psState(r.State); s != "" {
			a := sink.With(base, "hw.id", r.ID, "hw.name", nameOf(r.Name, r.ID), "hw.serial_number", r.Serial)
			emitState(out, a, psHardwareType(r.Type), s, at)
		}
	})
	return cmpErr(cmpErr(err, verr), herr)
}

// wsapiState maps the WSAPI state enum: 1 normal, 2 degraded, 3 failed.
func wsapiState(s int) string {
	switch s {
	case 1:
		return "ok"
	case 2:
		return "degraded"
	case 3:
		return "failed"
	}
	return ""
}

func mib(v *float64) *float64 {
	if v == nil {
		return nil
	}
	b := *v * mibBytes
	return &b
}

type wsapiUsage struct {
	TotalMiB *float64 `json:"totalMiB"`
	UsedMiB  *float64 `json:"usedMiB"`
}

func sumMiB(parts ...*float64) *float64 {
	var t float64
	seen := false
	for _, p := range parts {
		if p != nil {
			t += *p
			seen = true
		}
	}
	if !seen {
		return nil
	}
	return mib(&t)
}

// hpeLogin trades username/password for a WSAPI session key and returns the logout func.
func (c *arrayClient) hpeLogin(ctx context.Context) (func(), error) {
	var r struct {
		Key string `json:"key"`
	}
	body := map[string]string{"user": c.a.Username, "password": c.secret}
	if _, err := c.doBody(ctx, http.MethodPost, "/api/v1/credentials", body, &r); err != nil {
		return nil, err
	}
	if r.Key == "" {
		return nil, errors.New("hw array: hpe login returned no session key")
	}
	c.hdr["X-HP3PAR-WSAPI-SessionKey"] = r.Key
	return func() {
		// sessions are a scarce array resource, so close it even when the poll failed
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = c.do(lctx, http.MethodDelete, "/api/v1/credentials/"+url.PathEscape(r.Key), nil)
	}, nil
}

func (c *arrayClient) hpe(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	logout, err := c.hpeLogin(ctx)
	if err != nil {
		return err
	}
	defer logout()
	var sys struct {
		Name         string   `json:"name"`
		TotalMiB     *float64 `json:"totalCapacityMiB"`
		AllocatedMiB *float64 `json:"allocatedCapacityMiB"`
		FreeMiB      *float64 `json:"freeCapacityMiB"`
		FailedMiB    *float64 `json:"failedCapacityMiB"`
		ClusterNodes []int    `json:"clusterNodes"`
		OnlineNodes  []int    `json:"onlineNodes"`
	}
	if _, err = c.do(ctx, http.MethodGet, "/api/v1/system", &sys); err == nil {
		a := sink.With(base, "hw.id", sys.Name, "hw.name", nameOf(sys.Name), "hw.storage.kind", "array")
		emitNum(out, "hw.logical_disk.limit", "By", mib(sys.TotalMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", mib(sys.AllocatedMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.free", "By", mib(sys.FreeMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.failed", "By", mib(sys.FailedMiB), "logical_disk", a, at)
		for _, n := range sys.ClusterNodes {
			s := "failed"
			if slices.Contains(sys.OnlineNodes, n) {
				s = "ok"
			}
			id := fmt.Sprintf("node%d", n)
			emitState(out, sink.With(base, "hw.id", id, "hw.name", id), "disk_controller", s, at)
		}
	}
	var cpgs struct {
		Members []struct {
			Name  string     `json:"name"`
			State int        `json:"state"`
			Usr   wsapiUsage `json:"UsrUsage"`
			SA    wsapiUsage `json:"SAUsage"`
			SD    wsapiUsage `json:"SDUsage"`
		} `json:"members"`
	}
	_, cerr := c.do(ctx, http.MethodGet, "/api/v1/cpgs", &cpgs)
	for _, r := range cpgs.Members {
		a := sink.With(base, "hw.id", r.Name, "hw.name", r.Name, "hw.storage.kind", "cpg")
		if s := wsapiState(r.State); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", sumMiB(r.Usr.TotalMiB, r.SA.TotalMiB, r.SD.TotalMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", sumMiB(r.Usr.UsedMiB, r.SA.UsedMiB, r.SD.UsedMiB), "logical_disk", a, at)
	}
	var vols struct {
		Members []struct {
			Name      string     `json:"name"`
			State     int        `json:"state"`
			SizeMiB   *float64   `json:"sizeMiB"`
			TotalUsed *float64   `json:"totalUsedMiB"`
			UserSpace wsapiUsage `json:"userSpace"`
		} `json:"members"`
	}
	_, verr := c.do(ctx, http.MethodGet, "/api/v1/volumes", &vols)
	for i, r := range vols.Members {
		if i >= maxArrayRecords*maxArrayPages {
			break
		}
		a := sink.With(base, "hw.id", r.Name, "hw.name", r.Name, "hw.storage.kind", "volume")
		if s := wsapiState(r.State); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		used := r.TotalUsed
		if used == nil {
			used = r.UserSpace.UsedMiB // WSAPI before 1.6 has no totalUsedMiB
		}
		emitNum(out, "hw.logical_disk.limit", "By", mib(r.SizeMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", mib(used), "logical_disk", a, at)
	}
	return cmpErr(cmpErr(err, cerr), verr)
}
