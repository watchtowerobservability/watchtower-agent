package main

// Remote values for references (CFT-A16, Alloy remote.http, remote.s3 and remote.kubernetes.configmap).
// Only the agent's own config can hold references, so the fleet server cannot point the agent at a URL.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const maxRemoteRef = 1 << 20

func (r *secretResolver) k8sConfigMap(ctx context.Context, ref string) (string, error) {
	path, key := splitKey(ref)
	ns, name, ok := strings.Cut(path, "/")
	if !ok || key == "" {
		return "", errors.New("want namespace/name#key")
	}
	cs, err := r.kube()
	if err != nil {
		return "", err
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	switch {
	case k8serrors.IsForbidden(err):
		return "", errors.New("forbidden: grant the agent get on this configmap by name (Helm rbac.secretRefs)")
	case k8serrors.IsNotFound(err):
		return "", errors.New("configmap not found")
	case err != nil:
		return "", errors.New("configmap not readable")
	}
	v, ok := cm.Data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return v, nil
}

func (r *secretResolver) body(req *http.Request) (string, error) {
	resp, err := r.http.Do(req)
	if err != nil {
		return "", errors.New("unreachable") // url.Error would embed the URL
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteRef))
	if err != nil {
		return "", errors.New("read failed")
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func (r *secretResolver) httpRef(ctx context.Context, ref string) (string, error) {
	raw, key := splitKey(ref)
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("want an http(s) URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, http.NoBody)
	if err != nil {
		return "", errors.New("bad URL")
	}
	v, err := r.body(req)
	if err != nil {
		return "", err
	}
	return jsonKey(v, key)
}

func (r *secretResolver) s3Ref(ctx context.Context, ref string) (string, error) {
	path, key := splitKey(ref)
	bucket, obj, ok := strings.Cut(path, "/")
	if !ok || bucket == "" || obj == "" {
		return "", errors.New("want bucket/key")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil || cfg.Region == "" {
		return "", errors.New("aws credentials or AWS_REGION unavailable")
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", errors.New("aws credentials unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+bucket+".s3."+cfg.Region+".amazonaws.com/"+obj, http.NoBody)
	if err != nil {
		return "", errors.New("bad bucket or key")
	}
	sum := sha256.Sum256(nil)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	if v4.NewSigner().SignHTTP(ctx, creds, req, payload, "s3", cfg.Region, time.Now()) != nil {
		return "", errors.New("sigv4 signing failed")
	}
	v, err := r.body(req)
	if err != nil {
		return "", err
	}
	return jsonKey(v, key)
}
