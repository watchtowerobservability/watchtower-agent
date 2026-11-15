package ascode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
)

// shapingRuleOps maps `kind: ShapingRule` onto the project's shaping rules. The API gives a rule
// no name, so the manifest name is derived from what identifies it: "<signal>/<kind>" for a rule
// without a match, else "<signal>/<kind>/<first 8 hex of sha256(match)>". A create or update whose
// metadata.name differs from that says which name to use. The spec is the API body:
// {signal, kind, match?, params?, mode?}. Updates change params and mode only (the rest is the name).
// Rules the API generated from suggestions (source other than "manual") are not managed as code.
type shapingRuleOps struct{}

// shapingName is the manifest name of a rule.
func shapingName(signal, kind, match string) string {
	n := signal + "/" + kind
	if match == "" {
		return n
	}
	h := sha256.Sum256([]byte(match))
	return n + "/" + hex.EncodeToString(h[:4])
}

func specString(spec map[string]any, f string) string {
	s, _ := spec[f].(string)
	return s
}

func (shapingRuleOps) list(ctx context.Context, c *Client) (map[string]Item, error) {
	out := map[string]Item{}
	cursor := ""
	for {
		var page struct {
			Data       []map[string]any `json:"data"`
			NextCursor *string          `json:"next_cursor"`
		}
		q := "shaping-rules?limit=200"
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := c.do(ctx, http.MethodGet, q, nil, &page); err != nil {
			return nil, err
		}
		for _, b := range page.Data {
			if src, _ := b["source"].(string); src != "manual" {
				continue
			}
			name := shapingName(specString(b, "signal"), specString(b, "kind"), specString(b, "match"))
			id, _ := b["id"].(string)
			out[name] = Item{Ref: id, Name: name, Body: b}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out, nil
		}
		cursor = *page.NextCursor
	}
}

func checkShapingName(name string, spec map[string]any) error {
	want := shapingName(specString(spec, "signal"), specString(spec, "kind"), specString(spec, "match"))
	if name != want {
		return fmt.Errorf("ShapingRule %q: metadata.name must be %q (derived from signal, kind and match)", name, want)
	}
	return nil
}

func (shapingRuleOps) create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error) {
	if err := checkShapingName(name, spec); err != nil {
		return nil, err
	}
	var out map[string]any
	err := c.do(ctx, http.MethodPost, "shaping-rules", spec, &out)
	return out, err
}

func (shapingRuleOps) update(ctx context.Context, c *Client, it Item, name string, spec map[string]any) (map[string]any, error) {
	if err := checkShapingName(name, spec); err != nil {
		return nil, err
	}
	body := map[string]any{}
	for _, f := range []string{"params", "mode"} {
		if v, ok := spec[f]; ok {
			body[f] = v
		}
	}
	var out map[string]any
	err := c.do(ctx, http.MethodPatch, "shaping-rules/"+url.PathEscape(it.Ref), body, &out)
	return out, err
}

func (shapingRuleOps) remove(ctx context.Context, c *Client, it Item) error {
	return c.do(ctx, http.MethodDelete, "shaping-rules/"+url.PathEscape(it.Ref), nil, nil)
}
