package controller

import (
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// AutoInstPrefix + a language ("java", "nodejs", "python", "dotnet", "php", "ruby", "go") set to
// "true" on a pod (or a namespace/workload target, see AutoInstTargetsEnv) asks
// the webhook to add the official OpenTelemetry auto-instrumentation agent for that language: an
// init container copies it into a shared emptyDir and the app containers get the env that loads
// it. The image per language is WT_AUTOINST_IMAGE_<LANG>, defaulting to the upstream OTel image.
// PHP and Ruby have no default: a pod asking for one without its image set starts uninstrumented
// and gets AutoInstStatus, never an init container that cannot pull. "httpd" and "nginx" add the
// OTel webserver module (autoinst_web.go).
const AutoInstPrefix = "watchtower.dev/inject-"

// AutoInstStatus is the pod annotation (and admission warning) naming each auto-instrumentation
// the pod asked for but did not get because its image is not configured on the operator.
const AutoInstStatus = "watchtower.dev/autoinst-status"

const (
	autoVolume = "wt-otel-auto"
	autoDir    = "/otel-auto"
)

type autoLang struct {
	image string
	copy  string
	env   [][2]string
}

// Tags pinned to open-telemetry/opentelemetry-operator versions.txt (operator 0.162.0); glibc
// builds only (the images also carry musl variants under other paths).
var autoLangs = map[string]autoLang{
	"java": {"ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.32.0",
		"cp /javaagent.jar " + autoDir + "/javaagent.jar",
		[][2]string{{"JAVA_TOOL_OPTIONS", "-javaagent:" + autoDir + "/javaagent.jar"}}},
	"nodejs": {"ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-nodejs:0.82.0-1",
		"cp -r /autoinstrumentation/. " + autoDir,
		[][2]string{{"NODE_OPTIONS", "--require " + autoDir + "/autoinstrumentation.js"}}},
	"python": {"ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-python:0.66b1",
		"cp -r /autoinstrumentation/. " + autoDir,
		[][2]string{
			{"PYTHONPATH", autoDir + "/opentelemetry/instrumentation/auto_instrumentation:" + autoDir},
			{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"},
			{"OTEL_TRACES_EXPORTER", "otlp"}, {"OTEL_METRICS_EXPORTER", "otlp"}, {"OTEL_LOGS_EXPORTER", "otlp"},
		}},
	"dotnet": {"ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-dotnet:1.17.0",
		"cp -r /autoinstrumentation/. " + autoDir,
		[][2]string{
			{"CORECLR_ENABLE_PROFILING", "1"},
			{"CORECLR_PROFILER", "{918728DD-259F-4A6A-AC2B-B85E1B658318}"},
			{"CORECLR_PROFILER_PATH", autoDir + "/linux/OpenTelemetry.AutoInstrumentation.Native.so"},
			{"DOTNET_ADDITIONAL_DEPS", autoDir + "/AdditionalDeps"},
			{"DOTNET_SHARED_STORE", autoDir + "/store"},
			{"DOTNET_STARTUP_HOOKS", autoDir + "/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll"},
			{"OTEL_DOTNET_AUTO_HOME", autoDir},
		}},
	// PHP and Ruby have no upstream operator image; ours are built from infra/autoinst by
	// .illuminati/autoinst.yml (infra/docker/autoinst-{php,ruby}.Dockerfile). PHP: the extension and
	// php/conf.d/otel.ini that loads it with the Composer autoloader; Ruby: the gems and
	// ruby/autoinstrument.rb. No default image: set WT_AUTOINST_IMAGE_PHP / _RUBY (chart value
	// operator.autoinstImages) to where the integrator pushed them.
	"php": {"", "cp -r /autoinstrumentation/. " + autoDir,
		[][2]string{{"PHP_INI_SCAN_DIR", ":" + autoDir + "/php/conf.d"}, {"OTEL_PHP_AUTOLOAD_ENABLED", "true"}}},
	"ruby": {"", "cp -r /autoinstrumentation/. " + autoDir,
		[][2]string{{"RUBYOPT", "-r" + autoDir + "/ruby/autoinstrument"}}},
}

// autoLanguages lists the languages pod opted into (annotation or target, see wantLang) that
// have an image, in a fixed order.
func autoLanguages(pod *corev1.Pod) []string {
	var out []string
	for _, l := range []string{"java", "nodejs", "python", "dotnet", "php", "ruby"} {
		if wantLang(pod, l) && autoImage(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// unconfigured names each instrumentation pod asked for whose image is not configured.
func unconfigured(pod *corev1.Pod) []string {
	var out []string
	for _, l := range []string{"java", "nodejs", "python", "dotnet", "php", "ruby"} {
		if wantLang(pod, l) && autoImage(l) == "" {
			out = append(out, l+": image not configured (set WT_AUTOINST_IMAGE_"+strings.ToUpper(l)+" on the operator)")
		}
	}
	if k := webKind(pod); k != "" && os.Getenv(WebLoaderImageEnv) == "" {
		out = append(out, k+": helper image not configured (set "+WebLoaderImageEnv+" on the operator)")
	}
	return out
}

// statusPatch records msgs (from unconfigured) on the pod as AutoInstStatus.
func statusPatch(pod *corev1.Pod, msgs []string) []v1.PatchOp {
	if len(msgs) == 0 {
		return nil
	}
	val := strings.Join(msgs, "; ")
	if pod.Annotations == nil {
		return []v1.PatchOp{{Op: "add", Path: "/metadata/annotations", Value: map[string]string{AutoInstStatus: val}}}
	}
	// JSON pointer: "/" in the key is written "~1"
	return []v1.PatchOp{{Op: "add", Path: "/metadata/annotations/" + strings.ReplaceAll(AutoInstStatus, "/", "~1"), Value: val}}
}

func autoImage(lang string) string {
	base := autoLangs[lang].image
	if v := os.Getenv("WT_AUTOINST_IMAGE_" + strings.ToUpper(lang)); v != "" {
		base = v
	}
	// a remote SDK upgrade (sdkupgrade.go) moves the tag of the configured image
	if v := autoVersion(lang); v != "" && base != "" {
		return withTag(base, v)
	}
	return base
}

// autoInstPatch adds the agent volume, one init container per language and the loader env to
// every container. prior are the ops already in the patch (they may have created env arrays).
// A variable the container already sets is left alone, so an app's own settings win.
func autoInstPatch(pod *corev1.Pod, prior []v1.PatchOp) []v1.PatchOp {
	langs := autoLanguages(pod)
	if len(langs) == 0 {
		return nil
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == autoVolume {
			return nil // already injected (a re-admitted pod)
		}
	}
	vol := corev1.Volume{Name: autoVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	ops := []v1.PatchOp{addTo("/spec/volumes", len(pod.Spec.Volumes) == 0, vol)}
	mount := corev1.VolumeMount{Name: autoVolume, MountPath: autoDir}
	inits := len(pod.Spec.InitContainers)
	for _, l := range langs {
		ops = append(ops, addTo("/spec/initContainers", inits == 0, initContainer(l, mount)))
		inits++
	}
	for i, c := range pod.Spec.Containers {
		base := "/spec/containers/" + strconv.Itoa(i)
		ops = append(ops, addTo(base+"/volumeMounts", len(c.VolumeMounts) == 0, mount))
		envArr := len(c.Env) > 0 || created(prior, base+"/env")
		for _, l := range langs {
			for _, kv := range autoLangs[l].env {
				if hasEnv(c.Env, kv[0]) {
					continue
				}
				ops = append(ops, addTo(base+"/env", !envArr, corev1.EnvVar{Name: kv[0], Value: kv[1]}))
				envArr = true
			}
		}
	}
	return ops
}

func initContainer(lang string, mount corev1.VolumeMount) corev1.Container {
	small := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")}
	return corev1.Container{
		Name: "wt-otel-auto-" + lang, Image: autoImage(lang),
		Command:      []string{"sh", "-c", autoLangs[lang].copy},
		VolumeMounts: []corev1.VolumeMount{mount},
		Resources:    corev1.ResourceRequirements{Requests: small, Limits: small},
	}
}

// addTo appends value to the array at path, creating the array when it does not exist yet.
func addTo(path string, create bool, value any) v1.PatchOp {
	if create {
		return v1.PatchOp{Op: "add", Path: path, Value: []any{value}}
	}
	return v1.PatchOp{Op: "add", Path: path + "/-", Value: value}
}

func created(ops []v1.PatchOp, path string) bool {
	for _, o := range ops {
		if o.Path == path {
			return true
		}
	}
	return false
}
