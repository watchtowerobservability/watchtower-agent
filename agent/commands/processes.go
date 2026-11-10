package commands

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/shirou/gopsutil/v4/process"
)

// BuiltinProcessList is a built-in command: a live, read-only process list. It runs
// nothing: it reads the process table in-process. The operator opts in by listing a command with
// `builtin: process_list` in the agent config; the server can then ask for it by name.
const BuiltinProcessList = "process_list"

const (
	defaultProcLimit = 50
	maxProcLimit     = 200
)

// ProcessInfo is one row of the live list. Command lines are never included: they often carry
// credentials.
type ProcessInfo struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	User    string  `json:"user"`
	CPUSecs float64 `json:"cpu_seconds"`
	RSS     uint64  `json:"rss_bytes"`
}

// procSource reads the process table; tests replace it.
var procSource = readProcesses

func readProcesses() ([]ProcessInfo, error) {
	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, len(ps))
	for _, p := range ps {
		i := ProcessInfo{PID: p.Pid}
		i.Name, _ = p.Name()
		i.User, _ = p.Username()
		if t, err := p.Times(); err == nil {
			i.CPUSecs = t.User + t.System
		}
		if m, err := p.MemoryInfo(); err == nil && m != nil {
			i.RSS = m.RSS
		}
		out = append(out, i)
	}
	return out, nil
}

// ProcessListSchema is the argument schema of the built-in.
func ProcessListSchema() Schema {
	lo, hi := 1.0, float64(maxProcLimit)
	return Schema{Properties: map[string]Prop{
		"limit": {Type: "integer", Minimum: &lo, Maximum: &hi},
		"sort":  {Type: "string", Enum: []string{"cpu", "memory", "pid"}},
	}}
}

// TopProcesses returns at most limit rows (default 50, never more than 200), largest first by
// sortBy (cpu, memory; pid sorts ascending). Ties break by pid so the result is stable.
func TopProcesses(in []ProcessInfo, limit int, sortBy string) []ProcessInfo {
	if limit <= 0 {
		limit = defaultProcLimit
	}
	limit = min(limit, maxProcLimit)
	s := append([]ProcessInfo(nil), in...)
	sort.Slice(s, func(i, j int) bool {
		a, b := s[i], s[j]
		switch sortBy {
		case "memory":
			if a.RSS != b.RSS {
				return a.RSS > b.RSS
			}
		case "pid":
			return a.PID < b.PID
		default:
			if a.CPUSecs != b.CPUSecs {
				return a.CPUSecs > b.CPUSecs
			}
		}
		return a.PID < b.PID
	})
	return s[:min(len(s), limit)]
}

func isBuiltin(allow []Command, name, builtin string) bool {
	if name != builtin {
		return false
	}
	for _, c := range allow {
		if c.Name == name && c.Builtin == builtin {
			return true
		}
	}
	return false
}

// runProcessList validates the arguments and returns the list as JSON on stdout.
func runProcessList(args map[string]any) (Output, error) {
	if err := Validate(ProcessListSchema(), args); err != nil {
		return Output{}, err
	}
	limit := defaultProcLimit
	if f, ok := args["limit"].(float64); ok {
		limit = int(f)
	} else if i, ok := args["limit"].(int); ok {
		limit = i
	}
	sortBy, _ := args["sort"].(string)
	all, err := procSource()
	if err != nil {
		return Output{}, fmt.Errorf("process list: %w", err)
	}
	b, err := json.Marshal(map[string]any{"total": len(all), "processes": TopProcesses(all, limit, sortBy)})
	if err != nil {
		return Output{}, err
	}
	return Output{Stdout: string(b)}, nil
}
