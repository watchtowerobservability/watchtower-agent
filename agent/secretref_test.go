package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretRefsResolve(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pw")
	if err := os.WriteFile(f, []byte("p\"w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "vt" || r.URL.Path != "/v1/secret/data/db" {
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"user":"admin"}}}`))
	}))
	defer vault.Close()
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_TOKEN", "vt")
	t.Setenv("WT_TEST_TOKEN", "abc")
	cs := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "mon"}, Data: map[string][]byte{"k": []byte("kv")}})
	r := &secretResolver{http: vault.Client(), kube: func() (kubernetes.Interface, error) { return cs, nil }}
	raw := json.RawMessage(`{"a":"${env:WT_TEST_TOKEN}","b":"${file:` + f + `}","c":"${vault:secret/data/db#user}","d":"x-${k8s:mon/s#k}","e":"${1}"}`)
	got, err := r.resolve(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("%s: %v", got, err)
	}
	if m["a"] != "abc" || m["b"] != `p"w` || m["c"] != "admin" || m["d"] != "x-kv" || m["e"] != "${1}" {
		t.Fatalf("resolved %v", m)
	}
	if _, err := r.resolve(context.Background(), json.RawMessage(`{"a":"${env:WT_NOT_SET_X}"}`)); err == nil {
		t.Fatal("missing env must fail")
	}
}

func TestRemoteSecretRefsRefused(t *testing.T) {
	var warned []string
	p := Merge(NewRegistry(&LocalConfig{}), nil, &RemoteConfig{Modules: map[string]json.RawMessage{
		"prometheus": json.RawMessage(`{"targets":[{"url":"http://x/${file:/etc/shadow}"}]}`)}}, func(s string) { warned = append(warned, s) })
	if _, ok := p["prometheus"]; ok || len(warned) != 1 {
		t.Fatalf("remote secret refs must be refused: %v %v", p, warned)
	}
}
