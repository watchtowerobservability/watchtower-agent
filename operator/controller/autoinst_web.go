package controller

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// Web servers (APM-011): `watchtower.dev/inject-httpd` (Apache 2.4) or `inject-nginx` adds the
// OpenTelemetry webserver module. Four parts, none needing a shell in the app image:
//  1. an init container from the module image copies the module and its SDK libraries to webDir;
//  2. an init container from the Watchtower image (WebLoaderImageEnv) copies the static
//     wt-webloader helper (go/cmd/wt-webloader) to webDir;
//  3. a loader init container from the app's own image (so it sees the image's config and, for
//     nginx, its version) runs that helper: it copies the config dir to a staging volume, writes
//     the generated module config (webModuleConf) there and loads it: `Include` for httpd,
//     `load_module` plus an `include` in the http block for nginx;
//  4. the app container mounts the staged config over its config dir and gets LD_LIBRARY_PATH.
//
// An nginx version the module image has no build for leaves the config unchanged (the loader
// prints why), so a pod never fails to start because of instrumentation. Without
// WebLoaderImageEnv nothing is injected and the pod's status annotation says so.
// shortcut: config files the app mounts inside the config dir (ConfigMap subPath) shadow the
// staged copy, so put the module include there yourself; add a merge when that is common.

// WebConfDir overrides the web server's config dir (default /usr/local/apache2/conf for the
// official httpd image, /etc/nginx for nginx).
const WebConfDir = "watchtower.dev/otel-webserver-conf-dir"

// WebLoaderImageEnv names the image that carries wt-webloader on its PATH: the Watchtower image
// (the chart sets it to the operator's own image).
const WebLoaderImageEnv = "WT_WEBLOADER_IMAGE"

const (
	webVolume     = "wt-otel-web"
	webDir        = "/otel-web"
	webConfVolume = "wt-otel-web-conf"
	webStage      = "/wt-otel-conf"
	// The module exports OTLP over gRPC to the node agent's gRPC receiver.
	webAgentGRPC = 4317
	// Pinned to open-telemetry/opentelemetry-operator versions.txt (operator 0.162.0); the image
	// carries both the Apache and the nginx module builds under /opt/opentelemetry.
	webImage = "ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-apache-httpd:1.0.4"
)

type webServer struct{ confDir, confFile string }

var webServers = map[string]webServer{
	"httpd": {"/usr/local/apache2/conf", "httpd.conf"},
	"nginx": {"/etc/nginx", "nginx.conf"},
}

// webSDKLibs are the module's SDK libraries Apache loads with LoadFile before the module.
var webSDKLibs = []string{"common", "resources", "trace", "otlp_recordable",
	"exporter_ostream_span", "exporter_otlp_grpc"}

// webModuleConf is the module configuration for kind with placeholders the loader fills in at
// pod start: __WT_NODE_IP__ (the agent's node) and __WT_POD__ (the service instance id).
func webModuleConf(kind, service, namespace string) string {
	var b strings.Builder
	prefix, end := "Nginx", ";"
	if kind == "httpd" {
		prefix, end = "Apache", ""
		for _, l := range webSDKLibs {
			fmt.Fprintf(&b, "LoadFile %s/sdk_lib/lib/libopentelemetry_%s.so\n", webDir, l)
		}
		fmt.Fprintf(&b, "LoadModule otel_apache_module %s/WebServerModule/Apache/libmod_apache_otel.so\n", webDir)
	}
	for _, kv := range [][2]string{
		{"Enabled", "ON"},
		{"OtelSpanExporter", "otlp"},
		{"OtelExporterEndpoint", "http://__WT_NODE_IP__:" + strconv.Itoa(webAgentGRPC)},
		{"ServiceName", service},
		{"ServiceNamespace", namespace},
		{"ServiceInstanceId", "__WT_POD__"},
		{"ResolveBackends", "ON"},
		{"TraceAsError", "ON"},
	} {
		fmt.Fprintf(&b, "%sModule%s %s%s\n", prefix, kv[0], kv[1], end)
	}
	return b.String()
}

// webKind is the web server the pod opted into ("" for none); httpd wins when both are asked.
func webKind(pod *corev1.Pod) string {
	for _, k := range []string{"httpd", "nginx"} {
		if wantLang(pod, k) {
			return k
		}
	}
	return ""
}

func webService(pod *corev1.Pod, c corev1.Container) string {
	for _, l := range []string{"app.kubernetes.io/name", "app"} {
		if v := pod.Labels[l]; v != "" {
			return v
		}
	}
	return c.Name
}

// webServerPatch instruments the pod's first container. prior are the ops already in the patch.
func webServerPatch(pod *corev1.Pod, prior []v1.PatchOp) []v1.PatchOp {
	kind := webKind(pod)
	loader := os.Getenv(WebLoaderImageEnv)
	if kind == "" || loader == "" || len(pod.Spec.Containers) == 0 {
		return nil
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == webVolume {
			return nil // already injected
		}
	}
	ws := webServers[kind]
	if d := pod.Annotations[WebConfDir]; d != "" {
		ws.confDir = strings.TrimRight(d, "/")
	}
	img := webImage
	if v := os.Getenv("WT_AUTOINST_IMAGE_" + strings.ToUpper(kind)); v != "" {
		img = v
	}
	app := pod.Spec.Containers[0]
	agentMount := corev1.VolumeMount{Name: webVolume, MountPath: webDir}
	stageMount := corev1.VolumeMount{Name: webConfVolume, MountPath: webStage}
	empty := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	vols := len(pod.Spec.Volumes) > 0 || created(prior, "/spec/volumes")
	inits := len(pod.Spec.InitContainers) > 0 || created(prior, "/spec/initContainers")
	ops := []v1.PatchOp{
		addTo("/spec/volumes", !vols, corev1.Volume{Name: webVolume, VolumeSource: empty}),
		addTo("/spec/volumes", false, corev1.Volume{Name: webConfVolume, VolumeSource: empty}),
		addTo("/spec/initContainers", !inits, corev1.Container{
			Name: "wt-otel-web-module", Image: img, VolumeMounts: []corev1.VolumeMount{agentMount},
			Command: []string{"sh", "-c", "cp -r /opt/opentelemetry/. " + webDir},
		}),
		addTo("/spec/initContainers", false, corev1.Container{
			Name: "wt-otel-web-helper", Image: loader, VolumeMounts: []corev1.VolumeMount{agentMount},
			Command: []string{"wt-webloader", "install", webDir + "/wt-webloader"},
		}),
		addTo("/spec/initContainers", false, corev1.Container{
			Name: "wt-otel-web-loader", Image: app.Image,
			Command:      []string{webDir + "/wt-webloader"},
			VolumeMounts: []corev1.VolumeMount{agentMount, stageMount},
			Env: []corev1.EnvVar{
				{Name: "WT_WEB_KIND", Value: kind}, {Name: "WT_STAGE_DIR", Value: webStage}, {Name: "WT_WEB_DIR", Value: webDir},
				{Name: "WT_CONF_DIR", Value: ws.confDir}, {Name: "WT_CONF_FILE", Value: ws.confFile},
				{Name: "WT_OTEL_MODULE_CONF", Value: webModuleConf(kind, webService(pod, app), pod.Namespace)},
				{Name: nodeIPEnv, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"}}},
				{Name: "WT_POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
			},
		}),
	}
	mounts := len(app.VolumeMounts) > 0 || created(prior, "/spec/containers/0/volumeMounts")
	ops = append(ops,
		addTo("/spec/containers/0/volumeMounts", !mounts, agentMount),
		addTo("/spec/containers/0/volumeMounts", false, corev1.VolumeMount{Name: webConfVolume, MountPath: ws.confDir}))
	if !hasEnv(app.Env, "LD_LIBRARY_PATH") {
		envArr := len(app.Env) > 0 || created(prior, "/spec/containers/0/env")
		ops = append(ops, addTo("/spec/containers/0/env", !envArr,
			corev1.EnvVar{Name: "LD_LIBRARY_PATH", Value: webDir + "/sdk_lib/lib"}))
	}
	return ops
}
