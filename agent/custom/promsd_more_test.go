package custom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAPIBackedSDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/services":
			fmt.Fprint(w, `[{"Namespace":"default","Services":[{"ServiceName":"api"}]}]`)
		case "/v1/service/api":
			fmt.Fprint(w, `[{"Address":"10.0.0.5","Port":8080,"ServiceName":"api","Namespace":"default","JobID":"j"}]`)
		case "/apps":
			fmt.Fprint(w, `{"applications":{"application":[{"name":"PAY","instance":[{"hostName":"h","ipAddr":"10.0.0.6","status":"UP","port":{"$":9000}},{"ipAddr":"10.0.0.7","status":"DOWN","port":{"$":9000}}]}]}}`)
		case "/v3/discovery:monitoringassignments":
			fmt.Fprint(w, `{"resources":[{"mesh":"m","service":"web","targets":[{"name":"dp1","address":"10.0.0.8:5670","labels":{"zone":"a"}}]}]}`)
		case "/v2/droplets":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"droplets":[{"id":1,"name":"d1","status":"active","networks":{"v4":[{"ip_address":"1.2.3.4","type":"public"},{"ip_address":"10.1.0.1","type":"private"}]}}]}`)
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"c1","Names":["/redis"],"Labels":{"app":"cache"},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}},"Ports":[{"PrivatePort":9121,"Type":"tcp"}]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx, hc := context.Background(), srv.Client()
	cases := []struct {
		c    SDConfig
		url  string
		lbl  string
		want string
	}{
		{SDConfig{Type: "nomad", URL: srv.URL}, "http://10.0.0.5:8080/metrics", "nomad_service", "api"},
		{SDConfig{Type: "eureka", URL: srv.URL}, "http://10.0.0.6:9000/metrics", "eureka_app", "PAY"},
		{SDConfig{Type: "kuma", URL: srv.URL}, "http://10.0.0.8:5670/metrics", "zone", "a"},
		{SDConfig{Type: "digitalocean", Token: "tok", Endpoint: srv.URL}, "http://10.1.0.1:9100/metrics", "do_droplet_name", "d1"},
		{SDConfig{Type: "docker", Host: srv.URL}, "http://172.17.0.2:9121/metrics", "container", "redis"},
	}
	for _, tc := range cases {
		got, err := tc.c.discover(ctx, hc)
		if err != nil || len(got) != 1 || got[0].URL != tc.url || got[0].Labels[tc.lbl] != tc.want {
			t.Errorf("%s: %+v %v", tc.c.Type, got, err)
		}
	}
	if (SDConfig{Type: "digitalocean"}).validate() == nil || (SDConfig{Type: "kubernetes", Role: "x"}).validate() == nil {
		t.Fatal("bad configs must fail validation")
	}
}

func useFakeKube(t *testing.T, objs ...runtime.Object) kubernetes.Interface {
	t.Helper()
	cs := fake.NewSimpleClientset(objs...)
	old := kubeClient
	kubeClient = func() (kubernetes.Interface, error) { return cs, nil }
	t.Cleanup(func() { kubeClient = old })
	return cs
}

func TestKubernetesRolesAndServiceMonitor(t *testing.T) {
	node := "n1"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "metrics", Port: 9100}}}}
	ep := &corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}, Subsets: []corev1.EndpointSubset{{
		Addresses: []corev1.EndpointAddress{{IP: "10.2.0.1", NodeName: &node, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "web-1"}}},
		Ports:     []corev1.EndpointPort{{Name: "metrics", Port: 9100}, {Name: "http", Port: 80}}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "prod", Labels: map[string]string{"app": "web"}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: 9100}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.2.0.1"}}
	useFakeKube(t, svc, ep, pod)
	ctx := context.Background()
	got, err := SDConfig{Type: "kubernetes", Role: "endpoints"}.discover(ctx, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("endpoints: %+v %v", got, err)
	}
	got, err = SDConfig{Type: "kubernetes", Role: "pod", Selector: "app=web"}.discover(ctx, nil)
	if err != nil || len(got) != 1 || got[0].Labels["__meta_kubernetes_pod_label_app"] != "web" || got[0].Labels["pod"] != "web-1" {
		t.Fatalf("pods: %+v %v", got, err)
	}
	if _, l, _ := resolve(got[0]); l["__meta_kubernetes_pod_name"] != "" || l["pod"] != "web-1" {
		t.Fatalf("meta labels must not reach the series: %v", l)
	}
	old := kubeRaw
	t.Cleanup(func() { kubeRaw = old })
	kubeRaw = func(_ context.Context, _ kubernetes.Interface, path string) ([]byte, error) {
		if strings.Contains(path, "servicemonitors") {
			return []byte(`{"items":[{"metadata":{"name":"web","namespace":"prod"},"spec":{"selector":{"matchLabels":{"app":"web"}},
				"endpoints":[{"port":"metrics","interval":"15s","path":"/m","relabelings":[{"action":"Replace","targetLabel":"team","replacement":"core"}]}]}}]}`), nil
		}
		if strings.Contains(path, "probes") {
			return []byte(`{"items":[{"metadata":{"name":"site","namespace":"prod"},"spec":{"module":"http_2xx","prober":{"url":"bb:9115"},"targets":{"staticConfig":{"static":["https://x.test"]}}}}]}`), nil
		}
		return []byte(`{"items":[]}`), nil
	}
	got, err = SDConfig{Type: "prometheus_operator", Kinds: []string{"servicemonitor", "probe"}}.discover(ctx, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("operator: %+v %v", got, err)
	}
	sm := got[0]
	if sm.URL != "http://10.2.0.1:9100/m" || sm.Labels["job"] != "web" || sm.ScrapeInterval != "15s" || len(sm.RelabelConfigs) != 1 {
		t.Fatalf("servicemonitor target: %+v", sm)
	}
	if _, l, err := resolve(sm); err != nil || l["team"] != "core" {
		t.Fatalf("operator relabelings: %v %v", l, err)
	}
	if got[1].URL != "http://bb:9115/probe?module=http_2xx&target=https%3A%2F%2Fx.test" || got[1].Labels["instance"] != "https://x.test" {
		t.Fatalf("probe target: %+v", got[1])
	}
}

func TestClusterRendezvousMovesOnlyLeaversTargets(t *testing.T) {
	peers := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	before := map[string]string{}
	for i := range 300 {
		u := fmt.Sprintf("http://t%d:9100/metrics", i)
		before[u] = owner(u, peers)
	}
	moved := 0
	for u, o := range before {
		if n := owner(u, peers[:2]); n != o {
			moved++
			if o != "10.0.0.3" {
				t.Fatalf("%s moved from a peer that stayed", u)
			}
		}
	}
	if moved < 50 || moved > 150 {
		t.Fatalf("moved %d of 300, want about a third", moved)
	}
	cl := &cluster{self: "10.0.0.2"}
	if !cl.owns("http://x/metrics") {
		t.Fatal("no membership yet must scrape everything")
	}
	old := lookupPeers
	t.Cleanup(func() { lookupPeers = old })
	lookupPeers = func(context.Context, string) ([]string, error) { return peers, nil }
	if cl.refresh(context.Background(), ClusterConfig{PeersDNS: "agents.svc"}) != 3 {
		t.Fatal("refresh")
	}
	n := 0
	for u := range before {
		if cl.owns(u) {
			n++
		}
	}
	if n < 50 || n > 150 {
		t.Fatalf("self owns %d of 300", n)
	}
}
