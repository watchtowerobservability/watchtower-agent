package ascode

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// teamMembersOps maps `kind: TeamMembers` onto PUT /v1/orgs/{org}/teams/{id}/members. The spec's
// `team` (a Team name) is turned into team_id by Kind.Refs before it gets here. The API has no GET,
// so nothing can be compared: the kind is NoList and every apply sends the full list.
type teamMembersOps struct{}

func (teamMembersOps) list(context.Context, *Client) (map[string]Item, error) {
	return map[string]Item{}, nil
}

func (teamMembersOps) create(ctx context.Context, c *Client, _ string, spec map[string]any) (map[string]any, error) {
	id, _ := spec["team_id"].(string)
	if id == "" {
		return nil, errors.New("spec.team must name a Team (declare it in the manifests or create it first)")
	}
	var out map[string]any
	err := c.do(ctx, http.MethodPut, "/v1/orgs/{org}/teams/"+url.PathEscape(id)+"/members", map[string]any{"user_ids": spec["user_ids"]}, &out)
	return out, err
}

func (o teamMembersOps) update(ctx context.Context, c *Client, _ Item, n string, spec map[string]any) (map[string]any, error) {
	return o.create(ctx, c, n, spec)
}

// remove forgets the kind: emptying a team is never a side effect of --prune.
func (teamMembersOps) remove(context.Context, *Client, Item) error { return nil }
