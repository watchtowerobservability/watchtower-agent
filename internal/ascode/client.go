package ascode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/watchtowerobservability/watchtower-agent/wtapi"
)

// ErrNotFound is a 404 from the API.
var ErrNotFound = errors.New("not found")

// Item is a live resource: its API path segment and its body.
type Item struct {
	Ref  string // id, or the name for ByName kinds
	Name string
	Body map[string]any
}

// Client talks to one project through the generated wtapi client's server URL, auth and transport.
type Client struct {
	API     *wtapi.Client
	Project string
	Org     string // set for org-scoped kinds (NewOrg)
	// ManagedBy goes with every request as X-WT-Managed-By: the API locks what it manages (A31).
	ManagedBy string

	ids map[string]string // "Kind/name" -> id, filled by Plan and Apply for by-name references (B4)
}

// Scope is the project id, or the org id for a client made by NewOrg.
func (c *Client) Scope() string {
	if c.Project == "" {
		return c.Org
	}
	return c.Project
}

// New builds a client; hc may be nil for http.DefaultClient.
func New(api, key, project string, hc *http.Client) (*Client, error) {
	if api == "" || key == "" || project == "" {
		return nil, errors.New("api url, key and project are required")
	}
	opts := []wtapi.ClientOption{wtapi.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+key)
		return nil
	})}
	if hc != nil {
		opts = append(opts, wtapi.WithHTTPClient(hc))
	}
	c, err := wtapi.NewClient(api, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{API: c, Project: project, ManagedBy: "wtctl"}, nil
}

// NewOrg builds a client for the org-scoped kinds (IP allowlists, SSO, secret stores).
func NewOrg(api, key, org string, hc *http.Client) (*Client, error) {
	if org == "" {
		return nil, errors.New("org id is required")
	}
	c, err := New(api, key, "-", hc)
	if err != nil {
		return nil, err
	}
	c.Project, c.Org = "", org
	return c, nil
}

func (c *Client) do(ctx context.Context, method, rel string, body, out any) error {
	return c.Do(ctx, method, rel, nil, body, out)
}

// Do sends one request below the project path with extra headers (If-Match, Content-Type); out may be nil.
func (c *Client) Do(ctx context.Context, method, rel string, hdr map[string]string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	if strings.Contains(rel, "{org}") {
		if c.Org == "" && c.Project != "" { // a project client finds its org once
			var pr struct {
				OrgID string `json:"org_id"`
			}
			if err := c.do(ctx, http.MethodGet, "/v1/projects/"+url.PathEscape(c.Project), nil, &pr); err != nil {
				return fmt.Errorf("find the org of project %s: %w", c.Project, err)
			}
			c.Org = pr.OrgID
		}
		if c.Org == "" {
			return errors.New("org-scoped resource needs an org id")
		}
		rel = strings.ReplaceAll(rel, "{org}", url.PathEscape(c.Org))
	}
	u := strings.TrimRight(c.API.Server, "/") + "/v1/projects/" + url.PathEscape(c.Project) + "/" + rel
	if strings.HasPrefix(rel, "/v1/") { // an absolute API path such as /v1/me
		u = strings.TrimRight(c.API.Server, "/") + rel
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err == nil && c.ManagedBy != "" {
		req.Header.Set("X-WT-Managed-By", c.ManagedBy)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, ed := range c.API.RequestEditors {
		if err := ed(ctx, req); err != nil {
			return err
		}
	}
	resp, err := c.API.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%s %s: %w", method, rel, ErrNotFound)
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("%s %s: %s: %s", method, rel, resp.Status, strings.TrimSpace(string(b)))
	case out != nil && len(b) > 0:
		return json.Unmarshal(b, out)
	}
	return nil
}

func (k *Kind) itemPath(ref string) string { return k.Path + "/" + url.PathEscape(ref) }

// List returns every live resource of the kind keyed by name. A Singleton yields one item named "".
func (c *Client) List(ctx context.Context, k *Kind) (map[string]Item, error) {
	if k.ops != nil {
		return k.ops.list(ctx, c)
	}
	out := map[string]Item{}
	if k.NoList {
		return out, nil
	}
	if k.Singleton {
		var dto map[string]any
		if err := c.do(ctx, http.MethodGet, k.Path, nil, &dto); err != nil {
			return nil, err
		}
		tree, ok := dto["tree"].(map[string]any)
		if !ok { // org documents (SSO) are flat
			tree = dto
		}
		out[""] = Item{Body: tree}
		return out, nil
	}
	cursor := ""
	for {
		var page struct {
			Data       []map[string]any `json:"data"`
			NextCursor *string          `json:"next_cursor"`
		}
		q := "?limit=200"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := c.do(ctx, http.MethodGet, k.Path+q, nil, &page); err != nil {
			return nil, err
		}
		for _, b := range page.Data {
			name, _ := b[k.NameKey()].(string)
			if f, ok := b[k.NameKey()].(float64); ok && k.IntKey {
				name = strconv.Itoa(int(f))
			}
			if b["revoked_at"] != nil {
				continue // a revoked health token is gone for our purposes
			}
			if name == "" {
				continue // no as-code identity (an inhibition rule made in the UI)
			}
			ref, _ := b["id"].(string)
			if k.ByName || ref == "" { // a time interval's name is its id
				ref = name
			}
			if k.Versioned && ref != "" {
				var full map[string]any
				if err := c.do(ctx, http.MethodGet, k.itemPath(ref), nil, &full); err != nil {
					return nil, err
				}
				b = full
			}
			out[name] = Item{Ref: ref, Name: name, Body: b}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out, nil
		}
		cursor = *page.NextCursor
	}
}

// Get fetches one resource by name; ErrNotFound when absent.
func (c *Client) Get(ctx context.Context, k *Kind, name string) (Item, error) {
	items, err := c.List(ctx, k)
	if err != nil {
		return Item{}, err
	}
	if k.Singleton {
		name = ""
	}
	it, ok := items[name]
	if !ok {
		return Item{}, fmt.Errorf("%s %q: %w", k.Name, name, ErrNotFound)
	}
	return it, nil
}

func withName(k *Kind, name string, spec map[string]any) map[string]any {
	body := make(map[string]any, len(spec)+1)
	for f, v := range spec {
		body[f] = v
	}
	// A ByName path already carries the name, and its body schema may not allow the field; a rule group's body does.
	if !k.Singleton && !k.NoBodyName && (!k.ByName || k.NoList) {
		body[k.NameKey()] = name
		if n, err := strconv.Atoi(name); k.IntKey && err == nil {
			body[k.NameKey()] = n
		}
	}
	return body
}

// Create sends a new resource and returns the API's answer (it may carry a secret shown once).
func (c *Client) Create(ctx context.Context, k *Kind, name string, spec map[string]any) (map[string]any, error) {
	if k.ops != nil {
		return k.ops.create(ctx, c, name, spec)
	}
	body := withName(k, name, spec)
	var out map[string]any
	var err error
	if k.ByName || k.Singleton {
		path := k.Path
		if k.ByName {
			path = k.itemPath(name)
		}
		err = c.do(ctx, http.MethodPut, path, body, &out)
	} else {
		err = c.do(ctx, http.MethodPost, k.Path, body, &out)
	}
	return out, err
}

// Update replaces the resource at it.
func (c *Client) Update(ctx context.Context, k *Kind, it Item, name string, spec map[string]any) (map[string]any, error) {
	if k.ops != nil {
		return k.ops.update(ctx, c, it, name, spec)
	}
	var out map[string]any
	body := withName(k, name, spec)
	var err error
	switch {
	case k.Singleton:
		err = c.do(ctx, http.MethodPut, k.Path, body, &out)
	default:
		var hdr map[string]string
		if v, ok := it.Body["version"].(float64); k.Versioned && ok {
			hdr = map[string]string{"If-Match": strconv.Itoa(int(v))}
		}
		for _, f := range k.UpdateOmit {
			delete(body, f)
		}
		err = c.Do(ctx, k.updateMethod(), k.itemPath(it.Ref), hdr, body, &out)
	}
	return out, err
}

// Delete removes the resource.
func (c *Client) Delete(ctx context.Context, k *Kind, it Item) error {
	if k.ops != nil {
		return k.ops.remove(ctx, c, it)
	}
	if k.ResetOnDelete != nil {
		return c.do(ctx, http.MethodPut, k.itemPath(it.Ref), k.ResetOnDelete, nil)
	}
	return c.do(ctx, http.MethodDelete, k.itemPath(it.Ref), nil, nil)
}
