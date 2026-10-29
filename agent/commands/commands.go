// Package commands is the agent's allowlist of remotely triggerable commands (P5-R1, ALT-008).
//
// The operator declares each command in the agent's own config (`commands:`), with a fixed argv
// and a typed argument schema. The server can only name a command and give argument values; it
// never sends script text, and a request carrying any other field is refused. Nothing runs
// through a shell: argv elements are substituted and passed to exec directly.
package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeoutS = 30
	maxTimeoutS     = 300
	maxOutput       = 64 << 10
	defaultMaxLen   = 256
)

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Prop is one argument: type string, integer, number or boolean.
type Prop struct {
	Type      string   `yaml:"type" json:"type"`
	Enum      []string `yaml:"enum" json:"enum"`
	MaxLength int      `yaml:"max_length" json:"max_length"`
	Minimum   *float64 `yaml:"minimum" json:"minimum"`
	Maximum   *float64 `yaml:"maximum" json:"maximum"`
}

// Schema lists the arguments a command takes. Unknown arguments are always refused.
type Schema struct {
	Properties map[string]Prop `yaml:"properties" json:"properties"`
	Required   []string        `yaml:"required" json:"required"`
}

// Command is one allowlisted command. Argv elements may contain `{arg}` placeholders.
type Command struct {
	Name     string   `yaml:"name"`
	Argv     []string `yaml:"argv"`
	Args     Schema   `yaml:"args"`
	TimeoutS int      `yaml:"timeout_s"`
	// Builtin names an in-process command (only "process_list"); Argv is then not used.
	Builtin string `yaml:"builtin"`
}

// Request is what the server may send: a name and argument values, nothing else.
type Request struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// Parse decodes a request and refuses unknown fields (so no `script`, `argv` or `shell`).
func Parse(b []byte) (Request, error) {
	var r Request
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return Request{}, errors.New("command request: only name and args are accepted")
	}
	return r, nil
}

// ValidateAllowlist checks the operator's config.
func ValidateAllowlist(cs []Command) error {
	seen := map[string]bool{}
	for _, c := range cs {
		switch {
		case !nameRe.MatchString(c.Name):
			return fmt.Errorf("commands: name %q must match %s", c.Name, nameRe)
		case seen[c.Name]:
			return fmt.Errorf("commands: duplicate %q", c.Name)
		case c.Builtin != "" && (c.Builtin != BuiltinProcessList || c.Name != BuiltinProcessList):
			return fmt.Errorf("commands.%s: builtin must be %q and the command named the same", c.Name, BuiltinProcessList)
		case c.Builtin != "":
			// no argv to check
		case len(c.Argv) == 0 || c.Argv[0] == "" || strings.Contains(c.Argv[0], "{"):
			return fmt.Errorf("commands.%s: argv[0] must be a fixed program", c.Name)
		case c.TimeoutS < 0 || c.TimeoutS > maxTimeoutS:
			return fmt.Errorf("commands.%s: timeout_s must be 0 to %d", c.Name, maxTimeoutS)
		}
		seen[c.Name] = true
	}
	return nil
}

// Validate checks args against s: no unknown names, every required one present, types, enums,
// bounds. A string may not start with `-` unless the enum lists it (no option injection).
func Validate(s Schema, args map[string]any) error {
	for k, v := range args {
		p, ok := s.Properties[k]
		if !ok {
			return fmt.Errorf("argument %q is not declared", k)
		}
		if err := checkValue(k, p, v); err != nil {
			return err
		}
	}
	for _, k := range s.Required {
		if _, ok := args[k]; !ok {
			return fmt.Errorf("argument %q is required", k)
		}
	}
	return nil
}

func checkValue(k string, p Prop, v any) error {
	switch p.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("argument %q must be a string", k)
		}
		max := p.MaxLength
		if max <= 0 {
			max = defaultMaxLen
		}
		inEnum := slices.Contains(p.Enum, s)
		switch {
		case len(p.Enum) > 0 && !inEnum:
			return fmt.Errorf("argument %q is not one of the allowed values", k)
		case len(s) > max || strings.ContainsRune(s, 0):
			return fmt.Errorf("argument %q is too long or has a NUL byte", k)
		case strings.HasPrefix(s, "-") && !inEnum:
			return fmt.Errorf("argument %q may not start with '-'", k)
		}
	case "integer", "number":
		f, ok := v.(float64)
		if !ok {
			if i, isInt := v.(int); isInt {
				f, ok = float64(i), true
			}
		}
		if !ok || (p.Type == "integer" && f != float64(int64(f))) {
			return fmt.Errorf("argument %q must be a %s", k, p.Type)
		}
		if (p.Minimum != nil && f < *p.Minimum) || (p.Maximum != nil && f > *p.Maximum) {
			return fmt.Errorf("argument %q is out of range", k)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("argument %q must be a boolean", k)
		}
	default:
		return fmt.Errorf("argument %q has an unsupported type %q", k, p.Type)
	}
	return nil
}

// Build returns the argv for r, or why it is refused. A command that is not in allow is refused
// before its arguments are looked at.
func Build(allow []Command, r Request) ([]string, time.Duration, error) {
	i := slices.IndexFunc(allow, func(c Command) bool { return c.Name == r.Name })
	if i < 0 {
		return nil, 0, fmt.Errorf("command %q is not in this agent's allowlist", r.Name)
	}
	c := allow[i]
	if c.Builtin != "" {
		return nil, 0, fmt.Errorf("command %q is built in and has no argv", r.Name)
	}
	if err := Validate(c.Args, r.Args); err != nil {
		return nil, 0, err
	}
	argv := make([]string, len(c.Argv))
	for j, e := range c.Argv {
		for k, v := range r.Args {
			e = strings.ReplaceAll(e, "{"+k+"}", render(v))
		}
		argv[j] = e
	}
	t := c.TimeoutS
	if t == 0 {
		t = defaultTimeoutS
	}
	return argv, time.Duration(t) * time.Second, nil
}

func render(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// Output is what a run produced (truncated to 64 KiB each).
type Output struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type capped struct{ b bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.b.Len(); room > 0 {
		c.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Run executes a request against the allowlist: no shell, a timeout, capped output.
func Run(ctx context.Context, allow []Command, r Request) (Output, error) {
	if isBuiltinProcessList(allow, r.Name) {
		return runProcessList(r.Args)
	}
	argv, timeout, err := Build(allow, r)
	if err != nil {
		return Output{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var so, se capped
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv[0] is fixed by the operator's config
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	out := Output{Stdout: so.b.String(), Stderr: se.b.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		out.ExitCode = ee.ExitCode()
	default:
		return out, fmt.Errorf("command %q did not run: %w", r.Name, err)
	}
	return out, nil
}
