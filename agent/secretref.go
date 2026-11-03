package main

// Secret and value references in module configs (CFT-A16, Alloy local.file / remote.vault /
// remote.kubernetes.secret parity). A JSON string in the agent's own config file may hold
// `${env:NAME}`, `${file:/path}`, `${vault:secret/data/app#field}`, `${k8s:namespace/name#key}`,
// `${k8s-cm:namespace/name#key}`, `${http:https://host/path#json-key}`, `${s3:bucket/key#json-key}`,
// `${aws-sm:secret-id#json-key}` or `${gcp-sm:projects/p/secrets/s/versions/latest}`. They are
// resolved when the module starts and re-checked every 5 minutes; a changed value restarts the
// module. Remote config can never carry references (Merge refuses them), so the fleet server
// cannot make the agent read a local file or secret. Values never appear in logs or errors.
// vault needs VAULT_ADDR and VAULT_TOKEN (or VAULT_TOKEN_FILE); k8s needs the in-cluster
// service account; aws-sm the AWS default credential chain and AWS_REGION; gcp-sm the GCE
// metadata server. Without them the reference fails and the module does not start.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// secretRefRe matches one reference; `${1}`-style relabel replacements have no provider prefix.
var secretRefRe = regexp.MustCompile(`\$\{(env|file|vault|k8s|k8s-cm|http|s3|aws-sm|gcp-sm):([^}]{1,512})\}`)

const secretRefresh = 5 * time.Minute

// HasSecretRefs reports whether a config holds references.
func HasSecretRefs(raw []byte) bool { return secretRefRe.Match(raw) }

type secretResolver struct {
	http *http.Client
	kube func() (kubernetes.Interface, error)
}

var defaultResolver = &secretResolver{
	http: netguard.Guarded("agent", 15*time.Second),
	kube: func() (kubernetes.Interface, error) {
		rc, err := rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("not in a cluster")
		}
		return kubernetes.NewForConfig(rc)
	},
}

// ResolveSecretRefs returns raw with every reference replaced by its JSON-escaped value.
func (r *secretResolver) resolve(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if !HasSecretRefs(raw) {
		return raw, nil
	}
	var firstErr error
	out := secretRefRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := secretRefRe.FindSubmatch(m)
		v, err := r.value(ctx, string(sub[1]), string(sub[2]))
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("secret reference %s:...: %w", sub[1], err) // the path may be sensitive too
			}
			return m
		}
		q, _ := json.Marshal(v)
		return q[1 : len(q)-1] // the reference sits inside a JSON string
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func splitKey(ref string) (string, string) {
	p, k, _ := strings.Cut(ref, "#")
	return p, k
}

func (r *secretResolver) value(ctx context.Context, provider, ref string) (string, error) {
	switch provider {
	case "env":
		v, ok := os.LookupEnv(ref)
		if !ok {
			return "", errors.New("not set")
		}
		return v, nil
	case "file":
		b, err := os.ReadFile(ref)
		if err != nil {
			return "", errors.New("unreadable")
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case "vault":
		return r.vault(ctx, ref)
	case "k8s":
		return r.k8s(ctx, ref)
	case "k8s-cm":
		return r.k8sConfigMap(ctx, ref)
	case "http":
		return r.httpRef(ctx, ref)
	case "s3":
		return r.s3Ref(ctx, ref)
	case "aws-sm":
		return r.awsSM(ctx, ref)
	case "gcp-sm":
		return r.gcpSM(ctx, ref)
	}
	return "", errors.New("unknown provider")
}

func (r *secretResolver) getJSON(ctx context.Context, method, u string, hdr map[string]string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad url")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return errors.New("unreachable")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if json.Unmarshal(b, out) != nil {
		return errors.New("malformed answer")
	}
	return nil
}

// vault reads KV v2 (`secret/data/app#field`) or v1 (`kv/app#field`).
func (r *secretResolver) vault(ctx context.Context, ref string) (string, error) {
	addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if f := os.Getenv("VAULT_TOKEN_FILE"); tok == "" && f != "" {
		b, _ := os.ReadFile(f)
		tok = strings.TrimSpace(string(b))
	}
	if addr == "" || tok == "" {
		return "", errors.New("VAULT_ADDR and VAULT_TOKEN not configured")
	}
	path, key := splitKey(ref)
	var doc struct {
		Data map[string]any `json:"data"`
	}
	if err := r.getJSON(ctx, http.MethodGet, strings.TrimSuffix(addr, "/")+"/v1/"+strings.TrimPrefix(path, "/"),
		map[string]string{"X-Vault-Token": tok}, nil, &doc); err != nil {
		return "", err
	}
	data := doc.Data
	if inner, ok := data["data"].(map[string]any); ok { // KV v2 nests the values
		data = inner
	}
	if s, ok := data[key].(string); ok {
		return s, nil
	}
	return "", errors.New("key not found")
}

func (r *secretResolver) k8s(ctx context.Context, ref string) (string, error) {
	path, key := splitKey(ref)
	ns, name, ok := strings.Cut(path, "/")
	if !ok || key == "" {
		return "", errors.New("want namespace/name#key")
	}
	cs, err := r.kube()
	if err != nil {
		return "", err
	}
	s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case k8serrors.IsForbidden(err):
		return "", errors.New("forbidden: grant the agent get on this secret by name (Helm rbac.secretRefs, or infra/kubernetes/agent/secret-refs.example.yaml)")
	case k8serrors.IsNotFound(err):
		return "", errors.New("secret not found")
	case err != nil:
		return "", errors.New("secret not readable")
	}
	v, ok := s.Data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return string(v), nil
}

// jsonKey picks one key of a JSON object secret, or the whole value when key is empty.
func jsonKey(v, key string) (string, error) {
	if key == "" {
		return v, nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(v), &m) != nil {
		return "", errors.New("value is not a JSON object")
	}
	s, ok := m[key].(string)
	if !ok {
		return "", errors.New("key not found")
	}
	return s, nil
}

func (r *secretResolver) awsSM(ctx context.Context, ref string) (string, error) {
	id, key := splitKey(ref)
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil || cfg.Region == "" {
		return "", errors.New("aws credentials or AWS_REGION unavailable")
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", errors.New("aws credentials unavailable")
	}
	body, _ := json.Marshal(map[string]string{"SecretId": id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://secretsmanager."+cfg.Region+".amazonaws.com/", bytes.NewReader(body))
	if err != nil {
		return "", errors.New("bad region")
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	sum := sha256.Sum256(body)
	if v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "secretsmanager", cfg.Region, time.Now()) != nil {
		return "", errors.New("sigv4 signing failed")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return "", errors.New("unreachable")
	}
	defer resp.Body.Close()
	var out struct {
		SecretString string `json:"SecretString"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &out) != nil {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return jsonKey(out.SecretString, key)
}

func (r *secretResolver) gcpSM(ctx context.Context, ref string) (string, error) {
	name, key := splitKey(ref)
	if !strings.HasPrefix(name, "projects/") {
		return "", errors.New("want projects/<p>/secrets/<s>/versions/<v>")
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := r.getJSON(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		map[string]string{"Metadata-Flavor": "Google"}, nil, &tok); err != nil {
		return "", errors.New("gce metadata token unavailable")
	}
	var out struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	u := "https://secretmanager.googleapis.com/v1/" + (&url.URL{Path: name}).EscapedPath() + ":access"
	if err := r.getJSON(ctx, http.MethodGet, u, map[string]string{"Authorization": "Bearer " + tok.AccessToken}, nil, &out); err != nil {
		return "", err
	}
	v, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return "", errors.New("malformed payload")
	}
	return jsonKey(string(v), key)
}

// withSecrets runs start with the resolved config and restarts it (returns) when a referenced
// value changes. Configs without references run start directly.
func withSecrets(ctx context.Context, cfg json.RawMessage, start func(context.Context, json.RawMessage) error) error {
	if !HasSecretRefs(cfg) {
		return start(ctx, cfg)
	}
	resolved, err := defaultResolver.resolve(ctx, cfg)
	if err != nil {
		return err
	}
	mctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(secretRefresh)
		defer t.Stop()
		for {
			select {
			case <-mctx.Done():
				return
			case <-t.C:
				if now, err := defaultResolver.resolve(mctx, cfg); err == nil && !bytes.Equal(now, resolved) {
					cancel() // the supervisor restarts the module with the new values
					return
				}
			}
		}
	}()
	err = start(mctx, resolved)
	if ctx.Err() == nil && mctx.Err() != nil {
		return errors.New("referenced secret changed")
	}
	return err
}
