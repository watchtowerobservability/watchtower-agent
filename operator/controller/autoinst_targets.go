package controller

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// AutoInstTargetsEnv holds namespace and workload targets (APM-011), as JSON
// `[{"namespace": "shop", "selector": {"app": "checkout"}, "languages": ["java"]}]`: every pod in
// the namespace whose labels contain the selector gets those languages without an annotation.
// A target needs a namespace or a selector. A pod annotation `watchtower.dev/inject-<lang>:
// "false"` still opts that pod out.
const AutoInstTargetsEnv = "WT_AUTOINST_TARGETS"

// GoTargetExe names the binary the Go eBPF instrumentation attaches to (required for "go").
const GoTargetExe = "watchtower.dev/otel-go-target-exe"

// Pinned to open-telemetry/opentelemetry-operator versions.txt (operator 0.162.0).
const goImage = "ghcr.io/open-telemetry/opentelemetry-go-instrumentation/autoinstrumentation-go:v0.23.0-alpha"

const goSidecar = "wt-otel-go"

type autoTarget struct {
	Namespace string            `json:"namespace"`
	Selector  map[string]string `json:"selector"`
	Languages []string          `json:"languages"`
}

// autoTargets parses the targets; a malformed value targets nothing.
func autoTargets() []autoTarget {
	var ts []autoTarget
	if raw := os.Getenv(AutoInstTargetsEnv); raw != "" && json.Unmarshal([]byte(raw), &ts) != nil {
		return nil
	}
	return ts
}

func (t autoTarget) matches(pod *corev1.Pod) bool {
	if t.Namespace == "" && len(t.Selector) == 0 {
		return false
	}
	if t.Namespace != "" && t.Namespace != pod.Namespace {
		return false
	}
	for k, v := range t.Selector {
		if pod.Labels[k] != v {
			return false
		}
	}
	return true
}

// wantLang: the pod's annotation decides when set, otherwise any matching target.
func wantLang(pod *corev1.Pod, lang string) bool {
	switch strings.ToLower(pod.Annotations[AutoInstPrefix+lang]) {
	case "true":
		return true
	case "false":
		return false
	}
	for _, t := range autoTargets() {
		if slices.Contains(t.Languages, lang) && t.matches(pod) {
			return true
		}
	}
	return false
}

// goSidecarPatch adds the Go eBPF instrumentation as a privileged sidecar sharing the pod's
// process namespace, attached to the binary named by GoTargetExe. Without that annotation
// nothing is added (the agent cannot guess which process to attach to).
func goSidecarPatch(pod *corev1.Pod, port int) []v1.PatchOp {
	exe := pod.Annotations[GoTargetExe]
	if exe == "" || !wantLang(pod, "go") {
		return nil
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == goSidecar {
			return nil
		}
	}
	img := goImage
	if v := os.Getenv("WT_AUTOINST_IMAGE_GO"); v != "" {
		img = v
	}
	root, priv := int64(0), true
	c := corev1.Container{Name: goSidecar, Image: img,
		Env: []corev1.EnvVar{
			{Name: nodeIPEnv, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"}}},
			{Name: "OTEL_GO_AUTO_TARGET_EXE", Value: exe},
			{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: "http://$(" + nodeIPEnv + "):" + strconv.Itoa(port)},
		},
		SecurityContext: &corev1.SecurityContext{RunAsUser: &root, Privileged: &priv},
	}
	return []v1.PatchOp{
		{Op: "add", Path: "/spec/shareProcessNamespace", Value: true},
		{Op: "add", Path: "/spec/containers/-", Value: c},
	}
}
