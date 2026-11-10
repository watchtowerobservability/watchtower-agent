// Package autoinst is the host side of single-step auto-instrumentation (APM-011), for machines
// outside Kubernetes. It is opt-in from the agent's own config file (remote config can only
// toggle it) and names every target explicitly:
//
//   - Linux: rules match executables by glob. The agent renders /etc/watchtower/autoinst.conf
//     and adds the preload shim (infra/autoinst/preload, built by .illuminati/autoinst.yml) to
//     /etc/ld.so.preload. In every new process the shim reads the file and, for a matching
//     executable only, sets the loader variables (JAVA_TOOL_OPTIONS, NODE_OPTIONS, ...) that
//     the process has not set itself. Running processes pick it up on their next start.
//   - Windows: IIS application pools named in iis_pools get the .NET profiler variables of the
//     OpenTelemetry .NET auto-instrumentation in applicationHost.config and are recycled.
package autoinst

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Rule selects Linux executables: Exe is a glob (`*`, `?`) on the full path when it contains a
// slash, otherwise on the base name.
type Rule struct {
	Exe     string `json:"exe"`
	Lang    string `json:"lang"`    // java, nodejs, python, dotnet, ruby
	Service string `json:"service"` // OTEL_SERVICE_NAME; default the executable's base name
	// Unit is the systemd unit a remote upgrade may restart for this rule (only with AllowRestart).
	Unit string `json:"unit"`
}

// Pool is one IIS application pool to instrument.
type Pool struct {
	Name    string `json:"name"`
	Service string `json:"service"` // default the pool name
}

// Config is the `autoinst` module config.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
	// Endpoint is the local agent's OTLP/HTTP receiver (default http://127.0.0.1:4318).
	Endpoint string `json:"endpoint"`
	// AgentsDir holds the language agents: java/javaagent.jar, nodejs/, python/, dotnet/, ruby/
	// (default /opt/watchtower/autoinst). The preload shim is AgentsDir/libwtpreload.so.
	AgentsDir string `json:"agents_dir"`
	Rules     []Rule `json:"rules"`
	IISPools  []Pool `json:"iis_pools"`
	// DotnetHome is the OpenTelemetry .NET auto-instrumentation install on Windows.
	DotnetHome string `json:"dotnet_home"`
	// Versions pins a language to AgentsDir/versions/<version>/<lang>; a remote SDK upgrade sets
	// it (kept in StateFile). Without an entry the language runs from AgentsDir/<lang>.
	Versions map[string]string `json:"versions"`
	// AllowRestart lets a remote upgrade that asks for it restart the Unit of the matching rules.
	// Off by default: only the machine's owner opts in.
	AllowRestart bool `json:"allow_restart"`
	// StateFile holds the versions a remote upgrade applied (default /var/lib/watchtower/autoinst-versions.json).
	StateFile string `json:"state_file"`
}

const (
	defaultEndpoint   = "http://127.0.0.1:4318"
	defaultAgentsDir  = "/opt/watchtower/autoinst"
	defaultDotnetHome = `C:\Program Files\OpenTelemetry .NET AutoInstrumentation`
	profilerCLSID     = "{918728DD-259F-4A6A-AC2B-B85E1B658318}"
	maxRules          = 200
)

var langs = []string{"java", "nodejs", "python", "dotnet", "ruby"}

func (c Config) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return defaultEndpoint
}

func (c Config) agentsDir() string {
	if c.AgentsDir != "" {
		return c.AgentsDir
	}
	return defaultAgentsDir
}

// dirFor is where the agent of one language lives: the pinned version when there is one.
func (c Config) dirFor(lang string) string {
	if v := c.Versions[lang]; v != "" {
		return c.agentsDir() + "/versions/" + v
	}
	return c.agentsDir()
}

func (c Config) dotnetHome() string {
	if c.DotnetHome != "" {
		return c.DotnetHome
	}
	return defaultDotnetHome
}

// clean refuses characters that would break the rendered file or appcmd's argument syntax.
func clean(field, v string) error {
	if strings.ContainsAny(v, "\t\r\n'\"[]") {
		return fmt.Errorf("%s %q has a tab, newline, quote or bracket", field, v)
	}
	return nil
}

// Validate checks every rule and pool.
func (c Config) Validate() error {
	if len(c.Rules)+len(c.IISPools) > maxRules {
		return fmt.Errorf("at most %d rules and pools", maxRules)
	}
	for _, s := range []string{c.Endpoint, c.AgentsDir, c.DotnetHome, c.StateFile} {
		if err := clean("path", s); err != nil {
			return err
		}
	}
	for l, v := range c.Versions {
		if !slices.Contains(langs, l) || !versionRe.MatchString(v) {
			return fmt.Errorf("versions: %q: %q is not a language and a plain version", l, v)
		}
	}
	for _, r := range c.Rules {
		if r.Exe == "" || !slices.Contains(langs, r.Lang) {
			return fmt.Errorf("rule %q: exe is required and lang is one of %v", r.Exe, langs)
		}
		if _, err := path.Match(r.Exe, ""); err != nil {
			return fmt.Errorf("rule %q: %w", r.Exe, err)
		}
		if err := errors.Join(clean("exe", r.Exe), clean("service", r.Service)); err != nil {
			return err
		}
		if r.Unit != "" && !unitRe.MatchString(r.Unit) {
			return fmt.Errorf("rule %q: unit %q is not a systemd unit name", r.Exe, r.Unit)
		}
	}
	for _, p := range c.IISPools {
		if p.Name == "" {
			return errors.New("an IIS pool needs a name")
		}
		if err := errors.Join(clean("pool", p.Name), clean("service", p.Service)); err != nil {
			return err
		}
	}
	return nil
}

// LinuxEnv is the loader environment for one language with agents under dir.
func LinuxEnv(lang, dir string) [][2]string {
	switch lang {
	case "java":
		return [][2]string{{"JAVA_TOOL_OPTIONS", "-javaagent:" + dir + "/java/javaagent.jar"}}
	case "nodejs":
		return [][2]string{{"NODE_OPTIONS", "--require " + dir + "/nodejs/autoinstrumentation.js"}}
	case "python":
		return [][2]string{
			{"PYTHONPATH", dir + "/python/opentelemetry/instrumentation/auto_instrumentation:" + dir + "/python"},
			{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"},
		}
	case "dotnet":
		d := dir + "/dotnet"
		return [][2]string{
			{"CORECLR_ENABLE_PROFILING", "1"},
			{"CORECLR_PROFILER", profilerCLSID},
			{"CORECLR_PROFILER_PATH", d + "/linux-x64/OpenTelemetry.AutoInstrumentation.Native.so"},
			{"DOTNET_ADDITIONAL_DEPS", d + "/AdditionalDeps"},
			{"DOTNET_SHARED_STORE", d + "/store"},
			{"DOTNET_STARTUP_HOOKS", d + "/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll"},
			{"OTEL_DOTNET_AUTO_HOME", d},
		}
	case "ruby":
		return [][2]string{{"RUBYOPT", "-r" + dir + "/ruby/autoinstrument"}}
	}
	return nil
}

// RenderConf is the shim's file: one `glob<TAB>KEY=VALUE` line per variable, rules in order (the
// first rule that sets a variable for an executable wins, as the shim never overwrites).
func RenderConf(c Config) string {
	var b strings.Builder
	b.WriteString("# Written by wt-agent (module autoinst); edits are overwritten.\n")
	for _, r := range c.Rules {
		svc := r.Service
		if svc == "" {
			svc = "$EXE" // the shim substitutes the executable's base name
		}
		env := append(LinuxEnv(r.Lang, c.dirFor(r.Lang)),
			[2]string{"OTEL_SERVICE_NAME", svc}, [2]string{"OTEL_EXPORTER_OTLP_ENDPOINT", c.endpoint()})
		for _, kv := range env {
			fmt.Fprintf(&b, "%s\t%s=%s\n", r.Exe, kv[0], kv[1])
		}
	}
	return b.String()
}

// IISEnv is the .NET Framework and .NET (Core) profiler environment for one pool.
func IISEnv(c Config, p Pool) [][2]string {
	h := c.dotnetHome()
	svc := p.Service
	if svc == "" {
		svc = p.Name
	}
	x86 := h + `\win-x86\OpenTelemetry.AutoInstrumentation.Native.dll`
	x64 := h + `\win-x64\OpenTelemetry.AutoInstrumentation.Native.dll`
	return [][2]string{
		{"COR_ENABLE_PROFILING", "1"}, {"COR_PROFILER", profilerCLSID},
		{"COR_PROFILER_PATH_32", x86}, {"COR_PROFILER_PATH_64", x64},
		{"CORECLR_ENABLE_PROFILING", "1"}, {"CORECLR_PROFILER", profilerCLSID},
		{"CORECLR_PROFILER_PATH_32", x86}, {"CORECLR_PROFILER_PATH_64", x64},
		{"DOTNET_ADDITIONAL_DEPS", h + `\AdditionalDeps`},
		{"DOTNET_SHARED_STORE", h + `\store`},
		{"DOTNET_STARTUP_HOOKS", h + `\net\OpenTelemetry.AutoInstrumentation.StartupHook.dll`},
		{"OTEL_DOTNET_AUTO_HOME", h},
		{"OTEL_SERVICE_NAME", svc},
		{"OTEL_EXPORTER_OTLP_ENDPOINT", c.endpoint()},
	}
}
