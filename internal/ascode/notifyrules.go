package ascode

import (
	"context"
	"net/http"
	"sort"
)

// notifyRuleOps maps `kind: NotificationRule` (name: audible or quiet) onto the caller's two rule sets
// below me/notification-rules. A set is replaced as a whole (PUT) and cannot be deleted: removing it
// empties it. The spec is {rules: [{delay_min, contact_method: <ContactMethod name>}]}; apply turns the
// contact method name into contact_method_id (Kind.Refs, array form) before it gets here.
type notifyRuleOps struct{}

func (notifyRuleOps) list(ctx context.Context, c *Client) (map[string]Item, error) {
	var sets map[string][]map[string]any
	if err := c.do(ctx, http.MethodGet, "me/notification-rules", nil, &sets); err != nil {
		return nil, err
	}
	out := map[string]Item{}
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if n != "audible" && n != "quiet" || len(sets[n]) == 0 {
			continue // the response also carries warnings; an empty set is "not declared"
		}
		rules := make([]any, len(sets[n]))
		for i, r := range sets[n] {
			rules[i] = map[string]any{"delay_min": r["delay_min"], "contact_method_id": r["contact_method_id"]}
		}
		out[n] = Item{Ref: n, Name: n, Body: map[string]any{"rules": rules}}
	}
	return out, nil
}

func (notifyRuleOps) create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPut, "me/notification-rules/"+name, map[string]any{"rules": spec["rules"]}, &out)
	return out, err
}

func (o notifyRuleOps) update(ctx context.Context, c *Client, _ Item, name string, spec map[string]any) (map[string]any, error) {
	return o.create(ctx, c, name, spec)
}

func (notifyRuleOps) remove(ctx context.Context, c *Client, it Item) error {
	return c.do(ctx, http.MethodPut, "me/notification-rules/"+it.Ref, map[string]any{"rules": []any{}}, nil)
}
