package hw

// Dell Unity (Unisphere REST /api/types/...), HPE Nimble / Alletra 5000-6000 (REST v1 /v1/...)
// and IBM FlashSystem / Storwize (Spectrum Virtualize REST /rest/...) collectors (INF-013). Same
// hw.* capacity and health set and the same client as array.go: every request is pinned to the
// configured origin and redirects are never followed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// unityHealth maps the Unisphere health value: 5 OK, 7 OK_BUT, 10 degraded, 15 minor,
// 20 major, 25 critical, 30 non-recoverable, 0 unknown.
func unityHealth(v int) string {
	switch {
	case v == 0:
		return ""
	case v <= 7:
		return "ok"
	case v <= 15:
		return "degraded"
	}
	return "failed"
}

type unityHealthField struct {
	Value int `json:"value"`
}

// unityItems walks a Unisphere collection page by page.
func (c *arrayClient) unityItems(ctx context.Context, typ, fields string, each func(json.RawMessage)) error {
	for page := 1; page <= maxArrayPages; page++ {
		p := fmt.Sprintf("/api/types/%s/instances?fields=%s&per_page=%d&page=%d", typ, fields, maxArrayRecords, page)
		var res struct {
			Entries []struct {
				Content json.RawMessage `json:"content"`
			} `json:"entries"`
		}
		if _, err := c.do(ctx, http.MethodGet, p, &res); err != nil {
			return err
		}
		for _, e := range res.Entries {
			each(e.Content)
		}
		if len(res.Entries) < maxArrayRecords {
			return nil
		}
	}
	return nil
}

func (c *arrayClient) unity(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return errors.New("hw array: cookie jar")
	}
	c.hc.Jar = jar
	c.hdr["X-EMC-REST-CLIENT"] = "true"
	h, err := c.do(ctx, http.MethodGet, "/api/types/loginSessionInfo/instances", nil)
	if err != nil {
		return err
	}
	if tok := h.Get("EMC-CSRF-TOKEN"); tok != "" {
		c.hdr["EMC-CSRF-TOKEN"] = tok // POSTs (the logout) need it
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = c.doBody(lctx, http.MethodPost, "/api/types/loginSessionInfo/action/logout", map[string]any{}, nil)
	}()
	err = c.unityItems(ctx, "system", "id,name,model,health", func(b json.RawMessage) {
		var r struct {
			ID     string           `json:"id"`
			Name   string           `json:"name"`
			Model  string           `json:"model"`
			Health unityHealthField `json:"health"`
		}
		if json.Unmarshal(b, &r) == nil {
			if s := unityHealth(r.Health.Value); s != "" {
				emitState(out, sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.model", r.Model), "enclosure", s, at)
			}
		}
	})
	perr := c.unityItems(ctx, "pool", "id,name,sizeTotal,sizeUsed,sizeFree,sizeSubscribed,health", func(b json.RawMessage) {
		var r struct {
			ID         string           `json:"id"`
			Name       string           `json:"name"`
			Total      *float64         `json:"sizeTotal"`
			Used       *float64         `json:"sizeUsed"`
			Subscribed *float64         `json:"sizeSubscribed"`
			Health     unityHealthField `json:"health"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.ID, "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "pool")
		if s := unityHealth(r.Health.Value); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Total, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Used, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.provisioned", "By", r.Subscribed, "logical_disk", a, at)
	})
	lerr := c.unityItems(ctx, "lun", "id,name,sizeTotal,sizeAllocated,health", func(b json.RawMessage) {
		var r struct {
			ID        string           `json:"id"`
			Name      string           `json:"name"`
			Total     *float64         `json:"sizeTotal"`
			Allocated *float64         `json:"sizeAllocated"`
			Health    unityHealthField `json:"health"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", r.ID, "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "volume")
		if s := unityHealth(r.Health.Value); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Total, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Allocated, "logical_disk", a, at)
	})
	return cmpErr(cmpErr(err, perr), lerr)
}

// nimbleLogin opens a REST v1 session and returns the logout func.
func (c *arrayClient) nimbleLogin(ctx context.Context) (func(), error) {
	var r struct {
		Data struct {
			ID    string `json:"id"`
			Token string `json:"session_token"`
		} `json:"data"`
	}
	body := map[string]any{"data": map[string]string{"username": c.a.Username, "password": c.secret}}
	if _, err := c.doBody(ctx, http.MethodPost, "/v1/tokens", body, &r); err != nil {
		return nil, err
	}
	if r.Data.Token == "" {
		return nil, errors.New("hw array: nimble login returned no session token")
	}
	c.hdr["X-Auth-Token"] = r.Data.Token
	return func() {
		if r.Data.ID == "" {
			return
		}
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = c.do(lctx, http.MethodDelete, "/v1/tokens/"+url.PathEscape(r.Data.ID), nil)
	}, nil
}

// nimbleItems walks a /v1/<obj>/detail collection by row window.
func (c *arrayClient) nimbleItems(ctx context.Context, obj string, each func(json.RawMessage)) error {
	for page := range maxArrayPages {
		start := page * maxArrayRecords
		var res struct {
			TotalRows int               `json:"totalRows"`
			Data      []json.RawMessage `json:"data"`
		}
		p := fmt.Sprintf("/v1/%s/detail?startRow=%d&endRow=%d", obj, start, start+maxArrayRecords)
		if _, err := c.do(ctx, http.MethodGet, p, &res); err != nil {
			return err
		}
		for _, d := range res.Data {
			each(d)
		}
		if len(res.Data) < maxArrayRecords || start+len(res.Data) >= res.TotalRows {
			return nil
		}
	}
	return nil
}

func (c *arrayClient) nimble(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	logout, err := c.nimbleLogin(ctx)
	if err != nil {
		return err
	}
	defer logout()
	err = c.nimbleItems(ctx, "arrays", func(b json.RawMessage) {
		var r struct {
			ID     string   `json:"id"`
			Name   string   `json:"name"`
			Status string   `json:"status"`
			Usable *float64 `json:"usable_capacity_bytes"`
			Usage  *float64 `json:"usage"`
			Model  string   `json:"model"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "array", "hw.model", r.Model)
		switch r.Status {
		case "reachable":
			emitState(out, a, "enclosure", "ok", at)
		case "unreachable":
			emitState(out, a, "enclosure", "failed", at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", r.Usable, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Usage, "logical_disk", a, at)
	})
	perr := c.nimbleItems(ctx, "pools", func(b json.RawMessage) {
		var r struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Capacity *float64 `json:"capacity"`
			Usage    *float64 `json:"usage"`
			Free     *float64 `json:"free_space"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "pool")
		emitNum(out, "hw.logical_disk.limit", "By", r.Capacity, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Usage, "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.free", "By", r.Free, "logical_disk", a, at)
	})
	verr := c.nimbleItems(ctx, "volumes", func(b json.RawMessage) {
		var r struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Online  *bool    `json:"online"`
			SizeMiB *float64 `json:"size"` // MiB
			Used    *float64 `json:"vol_usage_compressed_bytes"`
		}
		if json.Unmarshal(b, &r) != nil {
			return
		}
		a := sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "volume")
		if r.Online != nil {
			s := "failed"
			if *r.Online {
				s = "ok"
			}
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", mib(r.SizeMiB), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", r.Used, "logical_disk", a, at)
	})
	return cmpErr(cmpErr(err, perr), verr)
}

// ibmBytes reads a Spectrum Virtualize size: plain bytes (the -bytes form) or "10.00TB" style.
func ibmBytes(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	mul := 1.0
	for i, u := range []string{"PB", "TB", "GB", "MB", "KB"} {
		if strings.HasSuffix(s, u) {
			mul = float64(int64(1) << (10 * (5 - i)))
			s = strings.TrimSuffix(s, u)
			break
		}
	}
	s = strings.TrimSuffix(s, "B")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	f *= mul
	return &f
}

func ibmState(s string) string {
	switch s {
	case "online":
		return "ok"
	case "degraded", "degraded_paths", "degraded_ports":
		return "degraded"
	case "":
		return ""
	}
	return "failed" // offline, excluded
}

// ibmLogin trades username/password (headers) for a token; the token ends on its own after
// an idle hour, there is no logout call.
func (c *arrayClient) ibmLogin(ctx context.Context) error {
	c.hdr = map[string]string{"X-Auth-Username": c.a.Username, "X-Auth-Password": c.secret}
	var r struct {
		Token string `json:"token"`
	}
	_, err := c.doBody(ctx, http.MethodPost, "/rest/auth", map[string]any{}, &r)
	c.hdr = map[string]string{}
	if err != nil {
		return err
	}
	if r.Token == "" {
		return errors.New("hw array: ibm login returned no token")
	}
	c.hdr["X-Auth-Token"] = r.Token
	return nil
}

func (c *arrayClient) ibm(ctx context.Context, out sink.Sink, base map[string]string, at time.Time) error {
	if err := c.ibmLogin(ctx); err != nil {
		return err
	}
	bytesOpt := map[string]any{"bytes": true}
	var sys struct {
		Name  string `json:"name"`
		Total string `json:"total_mdisk_capacity"`
		Used  string `json:"total_used_capacity"`
		Free  string `json:"total_free_space"`
	}
	_, err := c.doBody(ctx, http.MethodPost, "/rest/lssystem", map[string]any{}, &sys)
	if err == nil {
		a := sink.With(base, "hw.id", sys.Name, "hw.name", nameOf(sys.Name), "hw.storage.kind", "array")
		emitNum(out, "hw.logical_disk.limit", "By", ibmBytes(sys.Total), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", ibmBytes(sys.Used), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.free", "By", ibmBytes(sys.Free), "logical_disk", a, at)
	}
	var pools []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		Capacity string `json:"capacity"`
		Free     string `json:"free_capacity"`
		Used     string `json:"used_capacity"`
		Virtual  string `json:"virtual_capacity"`
	}
	_, perr := c.doBody(ctx, http.MethodPost, "/rest/lsmdiskgrp", bytesOpt, &pools)
	for _, r := range pools {
		a := sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "pool")
		if s := ibmState(r.Status); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", ibmBytes(r.Capacity), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.usage", "By", ibmBytes(r.Used), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.free", "By", ibmBytes(r.Free), "logical_disk", a, at)
		emitNum(out, "hw.logical_disk.provisioned", "By", ibmBytes(r.Virtual), "logical_disk", a, at)
	}
	var vdisks []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		Capacity string `json:"capacity"`
	}
	_, verr := c.doBody(ctx, http.MethodPost, "/rest/lsvdisk", bytesOpt, &vdisks)
	for i, r := range vdisks {
		if i >= maxArrayRecords*maxArrayPages {
			break
		}
		a := sink.With(base, "hw.id", nameOf(r.ID, r.Name), "hw.name", nameOf(r.Name, r.ID), "hw.storage.kind", "volume")
		if s := ibmState(r.Status); s != "" {
			emitState(out, a, "logical_disk", s, at)
		}
		emitNum(out, "hw.logical_disk.limit", "By", ibmBytes(r.Capacity), "logical_disk", a, at)
	}
	var encl []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Type   string `json:"type"`
		MTM    string `json:"product_MTM"`
		Serial string `json:"serial_number"`
	}
	_, eerr := c.doBody(ctx, http.MethodPost, "/rest/lsenclosure", map[string]any{}, &encl)
	for _, r := range encl {
		if s := ibmState(r.Status); s != "" {
			id := "enclosure" + r.ID
			emitState(out, sink.With(base, "hw.id", id, "hw.name", id, "hw.model", r.MTM, "hw.serial_number", r.Serial), "enclosure", s, at)
		}
	}
	return cmpErr(cmpErr(cmpErr(err, perr), verr), eerr)
}
