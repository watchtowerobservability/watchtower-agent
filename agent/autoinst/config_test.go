package autoinst

import (
	"strings"
	"testing"
)

func TestValidateAndRender(t *testing.T) {
	c := Config{Enabled: true, AgentsDir: "/opt/wt", Rules: []Rule{
		{Exe: "/usr/bin/java", Lang: "java", Service: "billing"},
		{Exe: "node*", Lang: "nodejs"},
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	conf := RenderConf(c)
	for _, want := range []string{
		"/usr/bin/java\tJAVA_TOOL_OPTIONS=-javaagent:/opt/wt/java/javaagent.jar\n",
		"/usr/bin/java\tOTEL_SERVICE_NAME=billing\n",
		"node*\tNODE_OPTIONS=--require /opt/wt/nodejs/autoinstrumentation.js\n",
		"node*\tOTEL_SERVICE_NAME=$EXE\n",
		"node*\tOTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318\n",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in\n%s", want, conf)
		}
	}
	for _, bad := range []Config{
		{Rules: []Rule{{Exe: "java", Lang: "cobol"}}},
		{Rules: []Rule{{Exe: "", Lang: "java"}}},
		{Rules: []Rule{{Exe: "ja\tva", Lang: "java"}}},
		{IISPools: []Pool{{Name: "a'] /-[name='b"}}},
		{IISPools: []Pool{{}}},
	} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestIISEnvAndArgs(t *testing.T) {
	c := Config{DotnetHome: `D:\otel`}
	env := IISEnv(c, Pool{Name: "Shop"})
	got := map[string]string{}
	for _, kv := range env {
		got[kv[0]] = kv[1]
	}
	if got["COR_PROFILER_PATH_64"] != `D:\otel\win-x64\OpenTelemetry.AutoInstrumentation.Native.dll` ||
		got["CORECLR_PROFILER"] != profilerCLSID || got["OTEL_SERVICE_NAME"] != "Shop" {
		t.Fatalf("env %v", got)
	}
	a := IISArgs("Shop", "COR_ENABLE_PROFILING", "1")
	if a[3] != "/+[name='Shop'].environmentVariables.[name='COR_ENABLE_PROFILING',value='1']" {
		t.Fatalf("args %v", a)
	}
}
