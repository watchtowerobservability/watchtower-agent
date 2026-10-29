package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	minBackoff    = time.Second
	maxBackoff    = time.Minute
	maxRetryAfter = 5 * time.Minute
)

// Forwarder drains the queue to the gateway with the project's ingestion key. 429 and 5xx are
// retried (honoring Retry-After); other 4xx drop only that batch and are counted. 401 and 403
// are retried too: a rotated key must not lose data.
type Forwarder struct {
	Q        *Queue
	Upstream string // gateway OTLP/HTTP base, e.g. https://ingest.example.com:4318
	Key      string // project ingestion key (wti_...)
	HTTP     *http.Client
	// Sleep waits d or until ctx ends; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error

	Forwarded atomic.Int64
	Rejected  atomic.Int64

	fails int
}

type retryError struct {
	after time.Duration // 0 = use backoff
	err   error
}

func (e *retryError) Error() string { return e.err.Error() }
func (e *retryError) Unwrap() error { return e.err }

// Step drains once. It returns how long to wait before the next attempt (0 after a clean drain).
func (f *Forwarder) Step(ctx context.Context) (time.Duration, error) {
	err := f.Q.Drain(func(path string, body []byte) error {
		return f.send(ctx, path, body)
	})
	if err == nil {
		f.fails = 0
		return 0, nil
	}
	f.fails++
	if re, ok := err.(*retryError); ok && re.after > 0 { //nolint:errorlint // never wrapped
		return min(re.after, maxRetryAfter), err
	}
	d := min(minBackoff<<min(f.fails-1, 10), maxBackoff)
	return d - time.Duration(rand.Int64N(int64(d/5)+1)), err
}

// Run drains whenever batches arrive (poke) or every second until ctx ends.
func (f *Forwarder) Run(ctx context.Context, poke <-chan struct{}) {
	for ctx.Err() == nil {
		wait, err := f.Step(ctx)
		if err != nil {
			slog.Warn("relay forward failed", "error", err, "retry_in", wait)
			if f.sleep(ctx, wait) != nil {
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-poke:
		case <-time.After(time.Second):
		}
	}
}

func (f *Forwarder) sleep(ctx context.Context, d time.Duration) error {
	if f.Sleep != nil {
		return f.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (f *Forwarder) send(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Upstream+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+f.Key)
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return &retryError{err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch c := resp.StatusCode; {
	case c < 300:
		f.Forwarded.Add(1)
		return nil
	case c == http.StatusTooManyRequests || c >= 500 || c == http.StatusUnauthorized || c == http.StatusForbidden:
		return &retryError{after: parseRetryAfter(resp.Header.Get("Retry-After")), err: fmt.Errorf("%s: status %d", path, c)}
	}
	slog.Error("relay batch rejected by gateway, dropped", "path", path, "status", resp.StatusCode)
	f.Rejected.Add(1)
	return nil
}

// parseRetryAfter accepts delta-seconds or an HTTP date; anything else is 0 (use backoff).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}
