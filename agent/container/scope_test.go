package container

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestSelfContainerID(t *testing.T) {
	id := strings.Repeat("ab", 32)
	for name, c := range map[string]struct{ cg, mi string }{
		"v2 systemd":  {"0::/system.slice/docker-" + id + ".scope\n", ""},
		"v2 parent":   {"0::/wt-app.slice/docker-" + id + ".scope\n", ""},
		"v1 cgroupfs": {"12:cpu,cpuacct:/docker/" + id + "\n11:memory:/docker/" + id + "\n", ""},
		"v2 cgroupfs": {"0::/docker/" + id + "\n", ""},
		"k8s":         {"0::/kubepods/burstable/pod1/cri-containerd-" + id + ".scope\n", ""},
		"cgroupns":    {"0::/\n", "1 2 0:3 /var/lib/docker/containers/" + id + "/hostname /etc/hostname rw - ext4 x\n"},
	} {
		if got := SelfContainerID(c.cg, c.mi); got != id {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := SelfContainerID("0::/\n", ""); got != "" {
		t.Errorf("no id expected, got %q", got)
	}
}

func TestSelfProject(t *testing.T) {
	id := strings.Repeat("c", 64)
	get := func(want string, labels map[string]string, resID string) func(string, any) error {
		return func(path string, v any) error {
			if path != "/containers/"+want+"/json" {
				return errors.New("inspected " + path)
			}
			r := v.(*struct {
				ID     string `json:"Id"`
				Config struct {
					Labels map[string]string `json:"Labels"`
				} `json:"Config"`
			})
			r.ID, r.Config.Labels = resID, labels
			return nil
		}
	}
	lab := map[string]string{ComposeProjectLabel: "myapp"}
	if p, err := SelfProject(get(id, lab, id), "0::/docker/"+id, "", "h"); err != nil || p != "myapp" {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := SelfProject(get(id, nil, id), "0::/docker/"+id, "", "h"); err == nil {
		t.Fatal("no label must fail, never widen")
	}
	// hostname fallback must resolve to our own id, not another container with that name
	if _, err := SelfProject(get("web", lab, strings.Repeat("d", 64)), "0::/", "", "web"); err == nil {
		t.Fatal("hostname that is another container's name must fail")
	}
	if p, err := SelfProject(get("abc123abc123", lab, "abc123abc123"+strings.Repeat("0", 52)), "0::/", "", "abc123abc123"); err != nil || p != "myapp" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestWantsSelf(t *testing.T) {
	t.Setenv("WT_AGENT_SCOPE", "")
	if ok, err := WantsSelf(""); ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := WantsSelf("self"); !ok {
		t.Fatal("self")
	}
	if _, err := WantsSelf("all"); err == nil {
		t.Fatal("unknown scope must error")
	}
	t.Setenv("WT_AGENT_SCOPE", "self")
	if ok, _ := WantsSelf(""); !ok {
		t.Fatal("env")
	}
}

func TestCgroupFilterParentLayouts(t *testing.T) {
	id := strings.Repeat("1", 64)
	cases := []struct {
		f    CgroupFilter
		path string
		want bool
	}{
		{CgroupFilter{Parent: "wt-app.slice"}, "/wt.slice/wt-app.slice/docker-" + id + ".scope", true},
		{CgroupFilter{Parent: "wt-app.slice"}, "/wt-app.slice/docker-" + id + ".scope", true},
		{CgroupFilter{Parent: "wt-app.slice"}, "/system.slice/docker-" + id + ".scope", false},
		{CgroupFilter{Parent: "wt-app.slice"}, "/wt-app.slice.evil/docker-" + id + ".scope", false},
		{CgroupFilter{Parent: "/wt-app"}, "/wt-app/" + id, true},
		{CgroupFilter{Parent: "/wt-app"}, "/docker/" + id, false},
		{CgroupFilter{}, "/docker/" + id, true},
		{CgroupFilter{Include: []string{"/system.slice/*"}}, "/system.slice/docker-x.scope", true},
		{CgroupFilter{Include: []string{"/system.slice/*"}}, "/other/docker-x.scope", false},
		{CgroupFilter{Exclude: []string{"/system.slice/*"}}, "/system.slice/docker-x.scope", false},
		{CgroupFilter{IDs: map[string]bool{"other": true}}, "/x/y", false},
		{CgroupFilter{Labels: LabelSet{"wt.team": {"a"}}}, "/x/y", false},
	}
	for i, c := range cases {
		if got := c.f.Match(c.path, id, "api-1", nil); got != c.want {
			t.Errorf("case %d: %+v on %s = %v", i, c.f, c.path, got)
		}
	}
	f := CgroupFilter{Include: []string{"api-*"}}
	if !f.Match("/x/y", "id", "api-1", nil) {
		t.Error("name glob")
	}
	if !(&CgroupFilter{Labels: LabelSet{"wt.team": {"a"}}}).Match("/x", "id", "n", map[string]string{"wt.team": "a"}) {
		t.Error("label match")
	}
}

func TestParseHealth(t *testing.T) {
	ok := func(l map[string]string) HealthTarget {
		t.Helper()
		h, has, err := ParseHealth("proj-api-1", "api", l)
		if !has || err != nil {
			t.Fatalf("%v %v %v", l, has, err)
		}
		return h
	}
	if h := ok(map[string]string{"wt.health": "http://:3000/healthz"}); h.URL != "http://proj-api-1:3000/healthz" || h.Interval != 30*time.Second {
		t.Fatalf("%+v", h)
	}
	if h := ok(map[string]string{"wt.health": "tcp://api:5432", "wt.health.interval": "1s", "wt.health.timeout": "2s"}); h.URL != "tcp://api:5432" || h.Interval != 5*time.Second || h.Timeout != 2*time.Second {
		t.Fatalf("%+v", h)
	}
	if h := ok(map[string]string{"wt.health": "postgres://:5432"}); h.URL != "postgres://proj-api-1:5432" {
		t.Fatalf("%+v", h)
	}
	if h := ok(map[string]string{"wt.health": "redis://"}); h.URL != "redis://proj-api-1:6379" {
		t.Fatalf("%+v", h)
	}
	for _, bad := range []string{"http://169.254.169.254/", "http://other:80/", "ftp://:21", "tcp://:", "http://u:p@:80/"} {
		if _, _, err := ParseHealth("proj-api-1", "api", map[string]string{"wt.health": bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, has, _ := ParseHealth("n", "", nil); has {
		t.Error("no label, no probe")
	}
	if _, err := ParseHealthTarget("x", "http://:80", "", "", "", ""); err == nil {
		t.Error("static target needs a host")
	}
}

func TestStatusOKAndRedis(t *testing.T) {
	if !statusOK("", 302) || statusOK("", 500) || !statusOK("2xx", 204) || statusOK("2xx", 301) || !statusOK("503", 503) {
		t.Fatal("statusOK")
	}
	if !redisUp("+PONG\r\n") || !redisUp("-NOAUTH Authen") || redisUp("-ERR") || redisUp("") {
		t.Fatal("redisUp")
	}
}

// writeScope makes one container cgroup with the files ScanCgroups needs.
func writeScope(t *testing.T, root, parent, id, oom string) string {
	t.Helper()
	d := filepath.Join(root, parent, "docker-"+id+".scope")
	writeCG(t, d, map[string]string{"cpu.stat": "usage_usec 1\n", "memory.current": "5\n", "memory.max": "max\n", "memory.events": "oom_kill " + oom + "\n"})
	return d
}

func TestCgroupLifecycleNamesAndRestarts(t *testing.T) {
	root := t.TempDir()
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	rec := &sink.Recorder{}
	p := &Poller{Filter: &CgroupFilter{Parent: "wt-app.slice"}}
	scan := func() { p.CollectCgroups(root, map[string]bool{}, rec); p.Prune(map[string]bool{}) }
	dir := writeScope(t, root, "wt-app.slice", a, "0")
	writeScope(t, root, "other.slice", b, "0") // outside the parent: never reported
	scan()                                     // baseline: no events
	for _, s := range rec.Snapshot() {
		if s.Name == "" && s.Attrs["container.event"] != "" {
			t.Fatalf("event on first scan: %+v", s)
		}
	}
	// a log record teaches the name; the series then carries it and the restart counts by name
	Learn(a, Learned{Name: "proj-api-1", Service: "api", Labels: map[string]string{"wt.team": "x"}})
	scan()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	scan() // die
	writeScope(t, root, "wt-app.slice", a, "2")
	scan() // start again: restart
	var starts, dies, ooms int
	var restarts float64
	for _, s := range rec.Snapshot() {
		switch {
		case s.Body == "container start":
			starts++
		case s.Body == "container die":
			dies++
		case s.Body == "container oom":
			ooms++
		case s.Name == "container.restarts" && s.Attrs["container.name"] == "proj-api-1":
			restarts = s.Value
		}
	}
	if starts != 1 || dies != 1 || restarts != 1 || ooms != 0 {
		t.Fatalf("starts=%d dies=%d restarts=%v ooms=%d: %+v", starts, dies, restarts, ooms, rec.Snapshot())
	}
	// an OOM kill on the running container is an event and a counter
	writeScope(t, root, "wt-app.slice", a, "3")
	scan()
	for _, s := range rec.Snapshot() {
		if s.Body == "container oom" {
			ooms++
		}
	}
	if ooms != 1 {
		t.Fatalf("oom events: %d", ooms)
	}
}

func TestLearnedLabelFilter(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("e", 64)
	writeScope(t, root, "x", id, "0")
	rec := &sink.Recorder{}
	p := &Poller{Filter: &CgroupFilter{Labels: LabelSet{"wt.team": {"a"}}}}
	p.CollectCgroups(root, map[string]bool{}, rec)
	if len(rec.Snapshot()) != 0 {
		t.Fatal("a container nothing is learned about must be skipped under a label filter")
	}
	Learn(id, Learned{Name: "n", Labels: map[string]string{"wt.team": "a"}})
	p.CollectCgroups(root, map[string]bool{}, rec)
	if len(rec.Snapshot()) == 0 {
		t.Fatal("matching labels must be reported")
	}
}
