package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAutoInstAddsAgentPerLanguage(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"},
		{Name: "side", Env: []corev1.EnvVar{{Name: "JAVA_TOOL_OPTIONS", Value: "-Xmx1g"}}}}}}
	pod.Annotations = map[string]string{AutoInstPrefix + "java": "true"}
	t.Setenv("WT_AUTOINST_IMAGE_JAVA", "reg/java-agent:1")
	out := review(t, pod)
	p := string(out.Response.Patch)
	for _, want := range []string{`"/spec/volumes"`, `"/spec/initContainers"`, "reg/java-agent:1",
		`"/spec/containers/0/volumeMounts"`, "-javaagent:/otel-auto/javaagent.jar", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in %s", want, p)
		}
	}
	// The sidecar keeps its own JAVA_TOOL_OPTIONS: only one container gets the loader.
	if strings.Count(p, "-javaagent:") != 1 {
		t.Fatalf("app setting overwritten: %s", p)
	}
	// The env array of container 0 is created once, by the endpoint patch.
	if strings.Count(p, `"path":"/spec/containers/0/env"`) != 1 {
		t.Fatalf("env array created twice: %s", p)
	}
	pod.Annotations = nil
	if p := string(review(t, pod).Response.Patch); strings.Contains(p, "initContainers") {
		t.Fatalf("not opted in but injected: %s", p)
	}
}

func TestAutoInstTargetsAndOptOut(t *testing.T) {
	t.Setenv(AutoInstTargetsEnv, `[{"namespace":"shop","selector":{"app":"checkout"},"languages":["python"]},
		{"languages":["java"]}]`)
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	pod.Namespace, pod.Labels = "shop", map[string]string{"app": "checkout", "tier": "web"}
	p := string(review(t, pod).Response.Patch)
	if !strings.Contains(p, "wt-otel-auto-python") || strings.Contains(p, "javaagent") {
		t.Fatalf("target not applied (or an unscoped target matched): %s", p)
	}
	pod.Annotations = map[string]string{AutoInstPrefix + "python": "false"}
	if p := string(review(t, pod).Response.Patch); strings.Contains(p, "initContainers") {
		t.Fatalf("opt-out ignored: %s", p)
	}
	pod.Annotations, pod.Namespace = nil, "other"
	if p := string(review(t, pod).Response.Patch); strings.Contains(p, "initContainers") {
		t.Fatalf("other namespace injected: %s", p)
	}
}

func TestAutoInstPhpAndRubyNeedConfiguredImages(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	pod.Annotations = map[string]string{AutoInstPrefix + "php": "true", AutoInstPrefix + "ruby": "true"}
	out := review(t, pod)
	p := string(out.Response.Patch)
	// No default image: no init container that could never pull, a status on the pod instead.
	if strings.Contains(p, "initContainers") || strings.Contains(p, "PHP_INI_SCAN_DIR") {
		t.Fatalf("injected without an image: %s", p)
	}
	for _, want := range []string{`"path":"/metadata/annotations/watchtower.dev~1autoinst-status"`,
		"php: image not configured (set WT_AUTOINST_IMAGE_PHP on the operator); ruby: image not configured"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in %s", want, p)
		}
	}
	if len(out.Response.Warnings) != 2 {
		t.Fatalf("warnings: %v", out.Response.Warnings)
	}
	t.Setenv("WT_AUTOINST_IMAGE_PHP", "reg/php-otel:1")
	t.Setenv("WT_AUTOINST_IMAGE_RUBY", "reg/ruby-otel:1")
	p = string(review(t, pod).Response.Patch)
	for _, want := range []string{"reg/php-otel:1", "reg/ruby-otel:1", "PHP_INI_SCAN_DIR", "-r/otel-auto/ruby/autoinstrument"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in %s", want, p)
		}
	}
	if strings.Contains(p, AutoInstStatus) {
		t.Fatalf("status set although configured: %s", p)
	}
	// A pod without annotations (opted in by a target) gets the annotations map created.
	t.Setenv("WT_AUTOINST_IMAGE_PHP", "")
	t.Setenv(AutoInstTargetsEnv, `[{"selector":{"app":"shop"},"languages":["php"]}]`)
	pod.Annotations, pod.Labels = nil, map[string]string{"app": "shop"}
	if p := string(review(t, pod).Response.Patch); !strings.Contains(p, `"path":"/metadata/annotations","value":{"watchtower.dev/autoinst-status"`) {
		t.Fatalf("annotations map not created: %s", p)
	}
}

func TestAutoInstGoSidecar(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	pod.Annotations = map[string]string{AutoInstPrefix + "go": "true"}
	if p := string(review(t, pod).Response.Patch); strings.Contains(p, goSidecar) {
		t.Fatalf("go sidecar without a target exe: %s", p)
	}
	pod.Annotations[GoTargetExe] = "/app/server"
	p := string(review(t, pod).Response.Patch)
	for _, want := range []string{`"/spec/shareProcessNamespace"`, goSidecar, "OTEL_GO_AUTO_TARGET_EXE",
		"/app/server", "$(WT_NODE_IP):4318", `"privileged":true`} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in %s", want, p)
		}
	}
}

func TestAutoInstWebServers(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "nginx:1.25.3"}}}}
	pod.Namespace, pod.Labels = "shop", map[string]string{"app": "storefront"}
	pod.Annotations = map[string]string{AutoInstPrefix + "nginx": "true"}
	if p := string(review(t, pod).Response.Patch); strings.Contains(p, "wt-otel-web") || !strings.Contains(p, "nginx: helper image not configured") {
		t.Fatalf("injected without the helper image, or no status: %s", p)
	}
	t.Setenv(WebLoaderImageEnv, "reg/watchtower:1")
	p := string(review(t, pod).Response.Patch)
	// No shell anywhere in the app image: the loader is the static helper the helper container installed.
	for _, want := range []string{"wt-otel-web-module", "wt-otel-web-helper", `"image":"reg/watchtower:1"`,
		`"command":["wt-webloader","install","/otel-web/wt-webloader"]`, "wt-otel-web-loader", `"image":"nginx:1.25.3"`,
		`"command":["/otel-web/wt-webloader"]`, `"name":"WT_WEB_KIND","value":"nginx"`,
		`"mountPath":"/etc/nginx"`, "LD_LIBRARY_PATH", "NginxModuleServiceName storefront;",
		"NginxModuleOtelExporterEndpoint http://__WT_NODE_IP__:4317;", "metadata.name"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in %s", want, p)
		}
	}
	if strings.Count(p, `"path":"/spec/containers/0/env"`) != 1 || strings.Count(p, `"path":"/spec/volumes"`) != 1 {
		t.Fatalf("an array created twice: %s", p)
	}
	conf := webModuleConf("httpd", "shop", "ns")
	for _, want := range []string{"LoadModule otel_apache_module /otel-web/WebServerModule/Apache/libmod_apache_otel.so\n",
		"LoadFile /otel-web/sdk_lib/lib/libopentelemetry_exporter_otlp_grpc.so\n", "ApacheModuleServiceName shop\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in %s", want, conf)
		}
	}
	pod.Annotations = map[string]string{AutoInstPrefix + "httpd": "true", WebConfDir: "/etc/httpd/conf/"}
	p = string(review(t, pod).Response.Patch)
	if !strings.Contains(p, `"mountPath":"/etc/httpd/conf"`) || !strings.Contains(p, `"name":"WT_WEB_KIND","value":"httpd"`) {
		t.Fatalf("httpd conf dir override: %s", p)
	}
}
