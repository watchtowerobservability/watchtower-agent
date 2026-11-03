package k8s

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExplainSaysWhyAPodIsNotScraped(t *testing.T) {
	pod := func(ann map[string]string, ip string, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n", Annotations: ann},
			Status: corev1.PodStatus{PodIP: ip, Phase: phase}}
	}
	on := map[string]string{AnnPrefix + "scrape": "true", AnnPrefix + "port": "9102"}
	cases := []struct {
		p    *corev1.Pod
		want string
	}{
		{pod(nil, "10.0.0.1", corev1.PodRunning), "is not \"true\""},
		{pod(on, "", corev1.PodRunning), "no IP"},
		{pod(on, "10.0.0.1", corev1.PodPending), "Pending"},
		{pod(map[string]string{AnnPrefix + "scrape": "true", AnnPrefix + "port": "x"}, "10.0.0.1", corev1.PodRunning), "port"},
		{pod(map[string]string{AnnPrefix + "scrape": "true", AnnPrefix + "port": "1", AnnPrefix + "path": "metrics"}, "10.0.0.1", corev1.PodRunning), "path"},
	}
	for _, c := range cases {
		if _, why := Explain(c.p); !strings.Contains(why, c.want) {
			t.Errorf("why = %q, want it to mention %q", why, c.want)
		}
	}
	tg, why := Explain(pod(on, "10.0.0.1", corev1.PodRunning))
	if why != "" || tg.URL() != "http://10.0.0.1:9102/metrics" {
		t.Fatalf("target %+v why %q", tg, why)
	}
}
