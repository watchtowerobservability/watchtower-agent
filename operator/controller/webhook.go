package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

const nodeIPEnv = "WT_NODE_IP"

// maxReview bounds an AdmissionReview body.
const maxReview = 1 << 20

// Mutate serves the injection webhook (`POST /mutate`): every container of an opted-in pod gets
// WT_NODE_IP (downward API, the node the pod lands on) and OTEL_EXPORTER_OTLP_ENDPOINT pointing
// at the agent on that node. The pod's node is unknown at CREATE, so the endpoint refers to
// $(WT_NODE_IP) and Kubernetes expands it at start. Any decode problem allows the pod unchanged:
// the chart sets failurePolicy Ignore and an outage must never block scheduling.
func Mutate(port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in admissionv1.AdmissionReview
		if json.NewDecoder(io.LimitReader(r.Body, maxReview)).Decode(&in) != nil || in.Request == nil {
			http.Error(w, "bad admission review", http.StatusBadRequest)
			return
		}
		resp := &admissionv1.AdmissionResponse{UID: in.Request.UID, Allowed: true}
		var pod corev1.Pod
		if in.Request.Kind.Kind == "Pod" && json.Unmarshal(in.Request.Object.Raw, &pod) == nil {
			if pod.Namespace == "" { // unset at CREATE; targets match on the request's namespace
				pod.Namespace = in.Request.Namespace
			}
			resp.Warnings = unconfigured(&pod)
			if ops := podPatch(&pod, port); len(ops) > 0 {
				if b, err := json.Marshal(ops); err == nil {
					pt := admissionv1.PatchTypeJSONPatch
					resp.Patch, resp.PatchType = b, &pt
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(admissionv1.AdmissionReview{
			TypeMeta: in.TypeMeta, Response: resp,
		})
	})
}

// podPatch is the JSON patch for pod, nil when it opted out or has nothing to add: the agent
// endpoint first, then any per-language auto-instrumentation the pod asked for, and the status
// annotation for any it asked for whose image is not configured.
func podPatch(pod *corev1.Pod, port int) []v1.PatchOp {
	ops := endpointPatch(pod, port)
	ops = append(ops, autoInstPatch(pod, ops)...)
	ops = append(ops, webServerPatch(pod, ops)...)
	ops = append(ops, statusPatch(pod, unconfigured(pod))...)
	return append(ops, goSidecarPatch(pod, port)...)
}

// endpointPatch adds WT_NODE_IP and OTEL_EXPORTER_OTLP_ENDPOINT to every container.
func endpointPatch(pod *corev1.Pod, port int) []v1.PatchOp {
	names := make([][]string, len(pod.Spec.Containers))
	for i, c := range pod.Spec.Containers {
		for _, e := range c.Env {
			names[i] = append(names[i], e.Name)
		}
	}
	// Probe first: InjectPatch decides opt-out and which containers need the variable.
	probe := v1.InjectPatch(pod.Annotations, names, "$("+nodeIPEnv+")", port)
	if len(probe) == 0 {
		return nil
	}
	var ops []v1.PatchOp
	for i, c := range pod.Spec.Containers {
		if hasEnv(c.Env, nodeIPEnv) {
			continue
		}
		entry := corev1.EnvVar{Name: nodeIPEnv, ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"}}}
		base := "/spec/containers/" + strconv.Itoa(i) + "/env"
		if len(c.Env) == 0 {
			ops = append(ops, v1.PatchOp{Op: "add", Path: base, Value: []corev1.EnvVar{entry}})
		} else {
			ops = append(ops, v1.PatchOp{Op: "add", Path: base + "/-", Value: entry})
		}
		names[i] = append(names[i], nodeIPEnv) // the endpoint is then appended after it
	}
	return append(ops, v1.InjectPatch(pod.Annotations, names, "$("+nodeIPEnv+")", port)...)
}

func hasEnv(env []corev1.EnvVar, name string) bool {
	for _, e := range env {
		if e.Name == name {
			return true
		}
	}
	return false
}
