package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Vector databases (LLM-004): each reads the product's Prometheus endpoint. Qdrant and Weaviate
// use unprefixed names, so their series are forwarded as qdrant_* and weaviate_*.

// Qdrant reads /metrics (port 6333); Token is the api-key when the instance has one.
func Qdrant(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "qdrant", path: "/metrics", header: "api-key", interval: 30 * time.Second, rename: "qdrant_",
		prefixes: []string{"qdrant_", "app_", "collections_", "rest_", "grpc_", "cluster_", "memory_"}}, raw, out)
}

// Weaviate reads the PROMETHEUS_MONITORING_ENABLED endpoint (port 2112).
func Weaviate(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "weaviate", path: "/metrics", interval: 30 * time.Second, rename: "weaviate_",
		prefixes: []string{"weaviate_", "batch_", "object_", "objects_", "vector_index_", "lsm_", "queries_", "requests_", "async_operations_", "index_queue_"}}, raw, out)
}

// Milvus reads a component's /metrics (port 9091): proxy search latency, entities, collections.
func Milvus(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "milvus", prefixes: []string{"milvus_"}, path: "/metrics", interval: 30 * time.Second}, raw, out)
}

// maxSDTargets caps the targets a Prometheus HTTP service-discovery answer may add.
const maxSDTargets = 50

// Pinecone reads the project's Prometheus HTTP service discovery (url ending in /discovery, Token
// the API key) and scrapes each listed HTTPS target with the same key; a plain url is scraped
// directly.
func Pinecone(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	sp := exporterSpec{name: "pinecone", prefixes: []string{"pinecone_"}, interval: 60 * time.Second}
	c := &ExporterConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if len(c.Prefixes) == 0 {
		c.Prefixes = sp.prefixes
	}
	return Loop(ctx, sp.name, c.Base, sp.interval, out, func(ctx context.Context, now time.Time) error {
		targets := []string{c.URL}
		if strings.HasSuffix(strings.TrimRight(c.URL, "/"), "/discovery") {
			var err error
			if targets, err = discover(ctx, sp, c); err != nil {
				return err
			}
		}
		var errs []error
		for _, t := range targets {
			errs = append(errs, scrapeOne(ctx, sp, c, t, out, now))
		}
		return errors.Join(errs...)
	})
}

// discover reads a Prometheus HTTP SD document: [{"targets": ["host:port"], "labels": {...}}].
func discover(ctx context.Context, sp exporterSpec, c *ExporterConfig) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	authorize(req, sp, c)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s discovery: HTTP %d", sp.name, resp.StatusCode)
	}
	var groups []struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&groups); err != nil {
		return nil, fmt.Errorf("%s discovery: %w", sp.name, err)
	}
	var out []string
	for _, g := range groups {
		for _, t := range g.Targets {
			path := g.Labels["__metrics_path__"]
			if path == "" {
				path = "/metrics"
			}
			u := &url.URL{Scheme: "https", Host: t, Path: path} // the API key only ever goes over TLS
			if out = append(out, u.String()); len(out) >= maxSDTargets {
				return out, nil
			}
		}
	}
	return out, nil
}
