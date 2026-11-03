package ascode

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// lokiRuleOps maps `kind: LokiRuleGroup` onto the Loki ruler API of the project. The manifest
// name is "<namespace>/<group>" and the spec is the ruler group without its name: {interval?,
// rules: [{alert|record, expr (LogQL), for?, labels?, annotations?}]}. JSON is valid YAML, so
// the group is sent as the JSON body of the YAML route.
type lokiRuleOps struct{}

func splitLokiName(name string) (ns, group string, err error) {
	ns, group, ok := strings.Cut(name, "/")
	if !ok || ns == "" || group == "" {
		return "", "", fmt.Errorf("LokiRuleGroup %q: name must be <namespace>/<group>", name)
	}
	return ns, group, nil
}

func (lokiRuleOps) list(ctx context.Context, c *Client) (map[string]Item, error) {
	var byNs map[string][]map[string]any
	if err := c.do(ctx, http.MethodGet, "loki/api/v1/rules", nil, &byNs); err != nil {
		return nil, err
	}
	out := map[string]Item{}
	for ns, groups := range byNs {
		for _, g := range groups {
			short, _ := g["name"].(string)
			body := make(map[string]any, len(g))
			for k, v := range g {
				if k != "name" {
					body[k] = v
				}
			}
			name := ns + "/" + short
			out[name] = Item{Ref: name, Name: name, Body: body}
		}
	}
	return out, nil
}

func (lokiRuleOps) create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error) {
	ns, group, err := splitLokiName(name)
	if err != nil {
		return nil, err
	}
	body := make(map[string]any, len(spec)+1)
	for k, v := range spec {
		body[k] = v
	}
	body["name"] = group
	return nil, c.do(ctx, http.MethodPost, "loki/api/v1/rules/"+url.PathEscape(ns), body, nil)
}

// update replaces the group: the ruler POST creates or replaces by name.
func (o lokiRuleOps) update(ctx context.Context, c *Client, _ Item, name string, spec map[string]any) (map[string]any, error) {
	return o.create(ctx, c, name, spec)
}

func (lokiRuleOps) remove(ctx context.Context, c *Client, it Item) error {
	ns, group, err := splitLokiName(it.Ref)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "loki/api/v1/rules/"+url.PathEscape(ns)+"/"+url.PathEscape(group), nil, nil)
}
