package ascode

import (
	"encoding/json"
	"fmt"
)

// Typed builders for dashboard specs (version 2), so dashboards as code in Go cannot misspell a
// field. The server still validates the result; Build only checks what it can know locally.

// Query is a panel or variable query: kind is promql, logs, traces or sql.
type Query struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Panel is one dashboard panel.
type Panel struct {
	ID      string         `json:"id"`
	Title   string         `json:"title"`
	Type    string         `json:"type"`
	Grid    Grid           `json:"grid"`
	Query   Query          `json:"query"`
	Options map[string]any `json:"options,omitempty"`
}

// Grid is a position on the 24 column grid.
type Grid struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

// Variable is a dashboard variable. DependsOn names parent variables; Scope a panel id.
type Variable struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Label      string   `json:"label,omitempty"`
	Default    string   `json:"default,omitempty"`
	Options    []string `json:"options,omitempty"`
	Query      *Query   `json:"query,omitempty"`
	Multi      bool     `json:"multi,omitempty"`
	IncludeAll bool     `json:"include_all,omitempty"`
	DependsOn  []string `json:"depends_on,omitempty"`
	Scope      string   `json:"scope,omitempty"`
}

// DashboardSpec accumulates variables and panels.
type DashboardSpec struct {
	variables []Variable
	panels    []Panel
}

// NewDashboard starts an empty spec.
func NewDashboard() *DashboardSpec { return &DashboardSpec{} }

// Var adds a variable.
func (d *DashboardSpec) Var(v Variable) *DashboardSpec {
	d.variables = append(d.variables, v)
	return d
}

// Timeseries adds a PromQL line chart of the given size at the next free row.
func (d *DashboardSpec) Timeseries(id, title, promql string, w, h int) *DashboardSpec {
	return d.panel(id, title, "timeseries", Query{Kind: "promql", Text: promql}, w, h)
}

// Stat adds a single-value PromQL panel.
func (d *DashboardSpec) Stat(id, title, promql string, w, h int) *DashboardSpec {
	return d.panel(id, title, "stat", Query{Kind: "promql", Text: promql}, w, h)
}

// Logs adds a log search panel.
func (d *DashboardSpec) Logs(id, title, search string, w, h int) *DashboardSpec {
	return d.panel(id, title, "logs", Query{Kind: "logs", Text: search}, w, h)
}

func (d *DashboardSpec) panel(id, title, typ string, q Query, w, h int) *DashboardSpec {
	y := 0
	for _, p := range d.panels {
		y = max(y, p.Grid.Y+p.Grid.H)
	}
	d.panels = append(d.panels, Panel{ID: id, Title: title, Type: typ, Grid: Grid{W: w, H: h, Y: y}, Query: q})
	return d
}

// Build returns the spec as JSON. It refuses duplicate ids and names, unknown parents and
// widths over 24; everything else is the server's to judge.
func (d *DashboardSpec) Build() ([]byte, error) {
	names := map[string]bool{}
	for _, v := range d.variables {
		if names[v.Name] {
			return nil, fmt.Errorf("duplicate variable %q", v.Name)
		}
		names[v.Name] = true
	}
	for _, v := range d.variables {
		for _, p := range v.DependsOn {
			if !names[p] {
				return nil, fmt.Errorf("variable %q depends on unknown %q", v.Name, p)
			}
		}
	}
	ids := map[string]bool{}
	for _, p := range d.panels {
		if ids[p.ID] {
			return nil, fmt.Errorf("duplicate panel %q", p.ID)
		}
		ids[p.ID] = true
		if p.Grid.W < 1 || p.Grid.W > 24 {
			return nil, fmt.Errorf("panel %q: width must be 1 to 24", p.ID)
		}
	}
	vars := d.variables
	if vars == nil {
		vars = []Variable{}
	}
	return json.Marshal(map[string]any{"version": 2, "variables": vars, "panels": d.panels})
}
