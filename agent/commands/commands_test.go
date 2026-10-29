package commands

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func allow() []Command {
	max := 10.0
	return []Command{{
		Name: "greet",
		Argv: []string{"echo", "hello", "{who}"},
		Args: Schema{
			Properties: map[string]Prop{
				"who": {Type: "string", MaxLength: 16},
				"n":   {Type: "integer", Maximum: &max},
			},
			Required: []string{"who"},
		},
	}}
}

func TestUnknownCommandRefused(t *testing.T) {
	if _, _, err := Build(allow(), Request{Name: "rm_all"}); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("err = %v", err)
	}
}

func TestArgsSchemaEnforced(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"missing required": {},
		"unknown arg":      {"who": "a", "extra": "x"},
		"wrong type":       {"who": 3.0},
		"option injection": {"who": "--version"},
		"too long":         {"who": strings.Repeat("a", 17)},
		"out of range":     {"who": "a", "n": 11.0},
		"non integer":      {"who": "a", "n": 1.5},
	} {
		if _, _, err := Build(allow(), Request{Name: "greet", Args: args}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	argv, _, err := Build(allow(), Request{Name: "greet", Args: map[string]any{"who": "bob", "n": 3.0}})
	if err != nil || strings.Join(argv, " ") != "echo hello bob" {
		t.Fatalf("argv = %v, %v", argv, err)
	}
}

func TestNoScriptTextAccepted(t *testing.T) {
	for _, body := range []string{
		`{"name":"greet","args":{"who":"a"},"script":"rm -rf /"}`,
		`{"name":"greet","argv":["sh","-c","id"]}`,
		`{"name":"greet","shell":true}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	if _, err := Parse([]byte(`{"name":"greet","args":{"who":"a"}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistValidation(t *testing.T) {
	bad := [][]Command{
		{{Name: "Bad Name", Argv: []string{"x"}}},
		{{Name: "a", Argv: nil}},
		{{Name: "a", Argv: []string{"{prog}"}}},
		{{Name: "a", Argv: []string{"x"}}, {Name: "a", Argv: []string{"x"}}},
		{{Name: "a", Argv: []string{"x"}, TimeoutS: 9999}},
	}
	for i, cs := range bad {
		if ValidateAllowlist(cs) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := ValidateAllowlist(allow()); err != nil {
		t.Fatal(err)
	}
}

func TestLiveProcessListBounded(t *testing.T) {
	var all []ProcessInfo
	for i := 1; i <= 1000; i++ {
		all = append(all, ProcessInfo{PID: int32(i), Name: "p", CPUSecs: float64(i), RSS: uint64(2000 - i)})
	}
	old := procSource
	procSource = func() ([]ProcessInfo, error) { return all, nil }
	defer func() { procSource = old }()
	opt := []Command{{Name: "process_list", Builtin: "process_list"}}
	if err := ValidateAllowlist(opt); err != nil {
		t.Fatal(err)
	}
	decode := func(o Output) (int, []ProcessInfo) {
		var v struct {
			Total     int           `json:"total"`
			Processes []ProcessInfo `json:"processes"`
		}
		if err := json.Unmarshal([]byte(o.Stdout), &v); err != nil {
			t.Fatal(err)
		}
		return v.Total, v.Processes
	}
	o, err := Run(context.Background(), opt, Request{Name: "process_list"})
	if err != nil {
		t.Fatal(err)
	}
	total, ps := decode(o)
	if total != 1000 || len(ps) != 50 || ps[0].PID != 1000 {
		t.Fatalf("default: total=%d len=%d first=%+v", total, len(ps), ps[0])
	}
	o, err = Run(context.Background(), opt, Request{Name: "process_list", Args: map[string]any{"limit": 200.0, "sort": "memory"}})
	if _, ps = decode(o); err != nil || len(ps) != 200 || ps[0].PID != 1 {
		t.Fatalf("memory sort: %v %d", err, len(ps))
	}
	for name, args := range map[string]map[string]any{
		"over cap":     {"limit": 5000.0},
		"bad sort":     {"sort": "cmdline"},
		"unknown arg":  {"pid": 1.0},
		"zero limit":   {"limit": 0.0},
		"string limit": {"limit": "10"},
	} {
		if _, err := Run(context.Background(), opt, Request{Name: "process_list", Args: args}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// not opted in: the name is not in the allowlist
	if _, err := Run(context.Background(), allow(), Request{Name: "process_list"}); err == nil {
		t.Error("process_list ran without an opt-in")
	}
}

func TestRunCapturesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses echo")
	}
	out, err := Run(context.Background(), allow(), Request{Name: "greet", Args: map[string]any{"who": "bob"}})
	if err != nil || out.ExitCode != 0 || strings.TrimSpace(out.Stdout) != "hello bob" {
		t.Fatalf("out = %+v, %v", out, err)
	}
}
