package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Fetch limits for FetchOptions' zero values.
const (
	DefaultMaxBytes = 1 << 20
	DefaultTimeout  = 10 * time.Second
)

// ErrTooLarge is returned when the body is over the cap.
var ErrTooLarge = errors.New("response is over the size cap")

// FetchOptions bound one fetch.
type FetchOptions struct {
	// ETag is sent as If-None-Match.
	ETag string
	// MaxBytes caps the body (default 1 MiB).
	MaxBytes int64
	// Timeout bounds the whole fetch (default 10 s).
	Timeout time.Duration
	// Dialer replaces the public-only guarded dialer (tests).
	Options Options
}

// Fetched is the result of Fetch.
type Fetched struct {
	// NotModified is true for a 304: there is no body to parse.
	NotModified bool
	Body        []byte
	ETag        string
}

// Fetch GETs an https URL through the guarded dialer: the address is checked at connect, for
// every connection, so private and metadata addresses are refused even behind a public name.
// Redirects and proxies are not followed. Used for external calendars and metric/symbol sources.
func Fetch(ctx context.Context, raw string, o FetchOptions) (Fetched, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return Fetched{}, fmt.Errorf("url must be https://host/... without credentials")
	}
	return fetch(ctx, u, o)
}

func fetch(ctx context.Context, u *url.URL, o FetchOptions) (Fetched, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{DialContext: New(o.Options).DialContext, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Fetched{}, err
	}
	if o.ETag != "" {
		req.Header.Set("If-None-Match", o.ETag)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // no URL: it may carry a token
		}
		return Fetched{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return Fetched{NotModified: true, ETag: o.ETag}, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return Fetched{}, fmt.Errorf("server answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, o.MaxBytes+1))
	if err != nil {
		return Fetched{}, err
	}
	if int64(len(b)) > o.MaxBytes {
		return Fetched{}, ErrTooLarge
	}
	return Fetched{Body: b, ETag: resp.Header.Get("ETag")}, nil
}
