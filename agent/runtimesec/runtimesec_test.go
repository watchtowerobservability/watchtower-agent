package runtimesec

import (
	"testing"
	"time"
)

type fakeSink struct {
	sev, body string
	attrs     map[string]string
}

func (f *fakeSink) Log(severity, body string, attrs map[string]string, _ time.Time) {
	f.sev, f.body, f.attrs = severity, body, attrs
}

func TestDefaultPolicyIsValidAndCoversTheThreeKinds(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	kinds := map[string]bool{}
	for _, r := range p.Rules {
		kinds[r.Kind] = true
	}
	for _, want := range []string{"exec", "file", "network"} {
		if !kinds[want] {
			t.Errorf("default policy misses kind %q", want)
		}
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	cases := []Policy{
		{Rules: []Rule{{Kind: "exec", Severity: "high", Action: "alert"}}},                                                                  // no id
		{Rules: []Rule{{ID: "a", Kind: "nope", Severity: "high", Action: "alert"}}},                                                         // bad kind
		{Rules: []Rule{{ID: "a", Kind: "exec", Severity: "loud", Action: "alert"}}},                                                         // bad severity
		{Rules: []Rule{{ID: "a", Kind: "exec", Severity: "high", Action: "stop"}}},                                                          // bad action
		{Rules: []Rule{{ID: "a", Kind: "exec", Severity: "high", Action: "block"}}},                                                         // block needs paths
		{Rules: []Rule{{ID: "a", Kind: "network", Severity: "high", Action: "block", Match: map[string]any{"paths": []string{"/x"}}}}},      // network cannot block
		{Rules: []Rule{{ID: "a", Kind: "file", Severity: "high", Action: "block", Match: map[string]any{"paths": []string{"etc/passwd"}}}}}, // relative path
	}
	for i, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestEmitterShapesSignalIntoLog(t *testing.T) {
	s := &fakeSink{}
	e := NewEmitter(s, "node-1")
	e.Signal(Rule{ID: "shell_in_container", Kind: "exec", Severity: "high"}, "pod/web", map[string]string{"comm": "bash"})
	if s.sev != "high" {
		t.Errorf("severity = %q", s.sev)
	}
	if s.attrs["security.source"] != "runtime_security" || s.attrs["security.rule"] != "shell_in_container" {
		t.Errorf("attrs = %v", s.attrs)
	}
	if s.attrs["security.detail.comm"] != "bash" {
		t.Errorf("detail not carried: %v", s.attrs)
	}
}
