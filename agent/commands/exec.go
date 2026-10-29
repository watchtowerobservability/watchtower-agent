package commands

import (
	"context"
	"encoding/json"
)

// Result is the answer the agent sends back for one fleet command.
type Result struct {
	ID       string `json:"id"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

// Envelope is a command as the fleet server delivers it: the usual Request plus a delivery id.
// Parse (and so the no-extra-fields rule) is applied to the Request part only.
type Envelope struct {
	ID      string          `json:"id"`
	Request json.RawMessage `json:"request"`
}

// Exec runs one delivered envelope against the allowlist. It never returns an error: a refusal
// or failure is the Result.
func Exec(ctx context.Context, allow []Command, raw []byte) Result {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil || e.ID == "" {
		return Result{Error: "malformed command envelope"}
	}
	req, err := Parse(e.Request)
	if err != nil {
		return Result{ID: e.ID, Error: err.Error()}
	}
	out, err := Run(ctx, allow, req)
	if err != nil {
		return Result{ID: e.ID, Error: err.Error(), ExitCode: out.ExitCode, Stdout: out.Stdout, Stderr: out.Stderr}
	}
	return Result{ID: e.ID, OK: out.ExitCode == 0, ExitCode: out.ExitCode, Stdout: out.Stdout, Stderr: out.Stderr}
}
