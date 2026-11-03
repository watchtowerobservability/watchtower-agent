// Package inventory is the agent module `inventory` (INF-033, Checkmk HW/SW inventory): once a
// day it reports the installed packages (dpkg, rpm, apk, Windows uninstall keys), the kernel,
// the OS and the BIOS/DMI identity as log records (event.name host.package and host.system), so
// the host page lists them and two hosts can be compared through the logs search API.
package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	ghost "github.com/shirou/gopsutil/v4/host"
)

// MaxPackages caps one report.
const MaxPackages = 5000

// Package is one installed package.
type Package struct{ Name, Version, Manager string }

// Logger is the part of the agent exporter the module uses.
type Logger interface {
	Log(severity, body string, attrs map[string]string, at time.Time)
}

// Config of the module; remote config may only toggle it.
type Config struct {
	Interval string `json:"interval"` // default 24h, at least 1h
}

// Run reports at start and then on the interval until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, agentVersion string, out Logger) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	every := 24 * time.Hour
	if d, err := time.ParseDuration(c.Interval); err == nil && d >= time.Hour {
		every = d
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		Report(out, System(agentVersion), Packages(ctx), time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Report writes one host.system record and one host.package record per package.
func Report(out Logger, sys map[string]string, pkgs []Package, at time.Time) {
	a := map[string]string{"event.name": "host.system"}
	for k, v := range sys {
		a[k] = v
	}
	out.Log("INFO", "host inventory: "+sys["os.description"], a, at)
	for _, p := range pkgs[:min(len(pkgs), MaxPackages)] {
		out.Log("INFO", "package "+p.Name+" "+p.Version, map[string]string{"event.name": "host.package",
			"package.name": p.Name, "package.version": p.Version, "package.manager": p.Manager}, at)
	}
}

// System is the kernel, OS and hardware identity.
func System(agentVersion string) map[string]string {
	s := map[string]string{"os.type": runtime.GOOS, "host.arch": runtime.GOARCH, "wt_agent.version": agentVersion}
	if k, err := ghost.KernelVersion(); err == nil {
		s["os.kernel"] = k
	}
	if p, fam, ver, err := ghost.PlatformInformation(); err == nil {
		s["os.name"], s["os.family"], s["os.version"] = p, fam, ver
		s["os.description"] = strings.TrimSpace(p + " " + ver)
	}
	if runtime.GOOS == "linux" {
		for _, f := range []string{"bios_vendor", "bios_version", "bios_date", "sys_vendor", "product_name"} {
			if b, err := os.ReadFile("/sys/class/dmi/id/" + f); err == nil {
				s["dmi."+f] = strings.TrimSpace(string(b))
			}
		}
	}
	for k, v := range s {
		if v == "" {
			delete(s, k)
		}
	}
	return s
}

// Packages lists what the platform's package managers know, sorted by name.
func Packages(ctx context.Context) []Package {
	var out []Package
	if f, err := os.Open("/var/lib/dpkg/status"); err == nil {
		out = append(out, ParseDpkg(f)...)
		f.Close()
	}
	if f, err := os.Open("/lib/apk/db/installed"); err == nil {
		out = append(out, ParseApk(f)...)
		f.Close()
	}
	if runtime.GOOS == "linux" {
		for _, rpm := range []string{"/usr/bin/rpm", "/bin/rpm"} {
			if _, err := os.Stat(rpm); err != nil {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			b, err := exec.CommandContext(cctx, rpm, "-qa", "--queryformat", `%{NAME}\t%{VERSION}-%{RELEASE}\n`).Output() // #nosec G204 -- fixed path and args
			cancel()
			if err == nil {
				out = append(out, ParseRpm(string(b))...)
			}
			break
		}
	}
	out = append(out, platformPackages()...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ParseDpkg reads /var/lib/dpkg/status: stanzas of `Key: value`, kept when Status ends in installed.
func ParseDpkg(r io.Reader) []Package {
	var out []Package
	var name, ver, status string
	flush := func() {
		if name != "" && strings.HasSuffix(status, " installed") {
			out = append(out, Package{Name: name, Version: ver, Manager: "dpkg"})
		}
		name, ver, status = "", "", ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok || strings.HasPrefix(line, " ") {
			continue
		}
		switch k {
		case "Package":
			name = v
		case "Version":
			ver = v
		case "Status":
			status = v
		}
	}
	flush()
	return out
}

// ParseApk reads Alpine's installed database (P: name, V: version, blank line between packages).
func ParseApk(r io.Reader) []Package {
	var out []Package
	var p Package
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if p.Name != "" {
				p.Manager = "apk"
				out = append(out, p)
			}
			p = Package{}
		case strings.HasPrefix(line, "P:"):
			p.Name = line[2:]
		case strings.HasPrefix(line, "V:"):
			p.Version = line[2:]
		}
	}
	if p.Name != "" {
		p.Manager = "apk"
		out = append(out, p)
	}
	return out
}

// ParseRpm reads `name\tversion-release` lines.
func ParseRpm(s string) []Package {
	var out []Package
	for _, line := range strings.Split(s, "\n") {
		if n, v, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok && n != "" {
			out = append(out, Package{Name: n, Version: v, Manager: "rpm"})
		}
	}
	return out
}
