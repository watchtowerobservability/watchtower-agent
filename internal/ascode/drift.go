package ascode

import (
	"context"
	"fmt"
	"io"
)

// Drift ops reported for a manifest.
const (
	DriftCreate = "create" // in the file, missing live
	DriftUpdate = "update" // live differs from the file (a UI edit, or a pending push)
	DriftOrphan = "orphan" // live, of a kind in the file, but not in the file: reported, never deleted
)

// DriftItem is one difference between a manifest and the live project.
type DriftItem struct {
	Kind   string   `json:"kind"`
	Key    string   `json:"key"`
	Op     string   `json:"op"`
	Fields []string `json:"fields,omitempty"`
}

// PlanManifest plans m against the live project. Orphans are discovered with prune but turned
// into DriftOrphan items by Drifts; they are never part of what ApplyManifest writes.
func (c *Client) PlanManifest(ctx context.Context, m *Manifest) ([]Change, error) {
	return c.Plan(ctx, m.Docs, true)
}

// Drifts converts a plan into drift items (no-ops are not drift).
func Drifts(plan []Change) []DriftItem {
	var out []DriftItem
	for _, ch := range plan {
		it := DriftItem{Kind: ch.Kind, Key: ch.Name, Fields: ch.Fields}
		switch ch.Op {
		case OpCreate:
			it.Op = DriftCreate
		case OpUpdate:
			it.Op = DriftUpdate
		case OpDelete:
			it.Op, it.Fields = DriftOrphan, nil
		default:
			continue
		}
		out = append(out, it)
	}
	return out
}

// ApplyManifest writes the creates and updates of plan. Deletes are dropped (orphans are only
// reported) and a step of a kind the file does not name is refused.
func (c *Client) ApplyManifest(ctx context.Context, m *Manifest, plan []Change, secrets io.Writer) ([]Change, error) {
	kinds := m.Kinds()
	var steps []Change
	for _, ch := range plan {
		if ch.Op == OpDelete {
			continue
		}
		if !kinds[ch.Kind] {
			return nil, fmt.Errorf("%s/%s: kind is not in %s", ch.Kind, ch.Name, m.Path)
		}
		steps = append(steps, ch)
	}
	return c.Apply(ctx, steps, false, secrets)
}
