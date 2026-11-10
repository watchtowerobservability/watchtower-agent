package relay

import (
	"compress/gzip"
	"compress/zlib"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/watchtowerobservability/watchtower-agent/internal/srcconv"
)

// maxSourceEntries caps log entries and spans per request, like the gateway receivers.
const maxSourceEntries = 100_000

// sourceBody reads a request body (gzip and zlib "deflate" undone) capped at maxBody.
func sourceBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxBody)
	switch strings.ToLower(r.Header.Get("Content-Encoding")) {
	case "gzip":
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return nil, false
		}
		body = io.LimitReader(gz, maxBody+1)
	case "zstd":
		zr, err := zstd.NewReader(body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxBody))
		if err != nil {
			http.Error(w, "bad zstd", http.StatusBadRequest)
			return nil, false
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxBody+1)
	case "deflate":
		zr, err := zlib.NewReader(body)
		if err != nil {
			http.Error(w, "bad deflate", http.StatusBadRequest)
			return nil, false
		}
		body = io.LimitReader(zr, maxBody+1)
	}
	raw, err := io.ReadAll(body)
	if err != nil || len(raw) > maxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return raw, true
}

func tokenOK(want, got string) bool {
	return want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// ingestFail answers a conversion or queue error: 413 too large, 400 malformed, 503 queue down.
func ingestFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, srcconv.ErrTooLarge) || errors.Is(err, ErrTooLarge):
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, srcconv.ErrDatadog) || errors.Is(err, srcconv.ErrHECFormat) || errors.As(err, &badRequest{}):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "queue unavailable", http.StatusServiceUnavailable)
	}
}

func writeJSONString(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

// datadogHandler serves the Datadog Agent intake: logs /api/v2/logs, series /api/v2/series and
// /api/v1/series (JSON or protobuf), traces /v0.3|v0.4|v0.5/traces (msgpack) and key validation.
func (r *Relay) datadogHandler(token string) http.Handler {
	mux := http.NewServeMux()
	auth := func(h func(http.ResponseWriter, *http.Request, []byte) error, respond string) http.HandlerFunc {
		return func(w http.ResponseWriter, hr *http.Request) {
			key := hr.Header.Get("DD-API-KEY")
			if key == "" {
				key = hr.URL.Query().Get("api_key")
			}
			if !tokenOK(token, key) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			raw, ok := sourceBody(w, hr)
			if !ok {
				return
			}
			if err := h(w, hr, raw); err != nil {
				ingestFail(w, err)
				return
			}
			code := http.StatusAccepted
			if strings.Contains(respond, "rate_by_service") {
				code = http.StatusOK
			}
			writeJSONString(w, code, respond)
		}
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /api/v1/validate", func(w http.ResponseWriter, hr *http.Request) {
		key := hr.Header.Get("DD-API-KEY")
		if key == "" {
			key = hr.URL.Query().Get("api_key")
		}
		if !tokenOK(token, key) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeJSONString(w, http.StatusOK, `{"valid":true}`)
	})
	mux.HandleFunc("POST /api/v2/logs", auth(func(_ http.ResponseWriter, _ *http.Request, b []byte) error {
		entries, err := srcconv.DDLogEntries(b)
		if err != nil {
			return err
		}
		if len(entries) > maxSourceEntries {
			return srcconv.ErrTooLarge
		}
		return r.Logs(srcconv.DDLogsRequest(entries, uint64(time.Now().UnixNano()))) //nolint:gosec // positive
	}, `{}`))
	series := auth(func(_ http.ResponseWriter, hr *http.Request, b []byte) error {
		var ss []srcconv.Series
		var err error
		if strings.Contains(hr.Header.Get("Content-Type"), "protobuf") {
			ss, err = srcconv.SeriesFromProto(b)
		} else {
			ss, err = srcconv.SeriesFromJSON(b)
		}
		if err != nil {
			if errors.Is(err, srcconv.ErrTooLarge) {
				return err
			}
			return srcconv.ErrDatadog
		}
		return r.Metrics(srcconv.SeriesRequest(ss))
	}, `{"errors":[]}`)
	mux.HandleFunc("POST /api/v2/series", series)
	mux.HandleFunc("POST /api/v1/series", series)
	traces := func(conv func(any, int) (*coltrace.ExportTraceServiceRequest, error)) http.HandlerFunc {
		return auth(func(_ http.ResponseWriter, hr *http.Request, b []byte) error {
			v, err := srcconv.MsgpackDecode(b)
			if err != nil {
				return srcconv.ErrDatadog
			}
			req, err := conv(v, maxSourceEntries)
			if err != nil {
				return err
			}
			return r.Traces(hr.Context(), req, false)
		}, `{"rate_by_service":{}}`)
	}
	mux.HandleFunc("POST /api/v0.2/traces", auth(func(_ http.ResponseWriter, hr *http.Request, b []byte) error {
		req, err := srcconv.DDTracesV02(b, maxSourceEntries)
		if err != nil {
			return err
		}
		return r.Traces(hr.Context(), req, false)
	}, `{}`))
	mux.HandleFunc("POST /api/v0.2/stats", auth(func(_ http.ResponseWriter, hr *http.Request, b []byte) error {
		ms, err := srcconv.DDStatsMetrics(b, strings.Contains(hr.Header.Get("Content-Type"), "msgpack"), maxSourceEntries)
		if err != nil {
			return err
		}
		return r.metricList(ms)
	}, `{}`))
	mux.HandleFunc("POST /api/beta/sketches", auth(func(_ http.ResponseWriter, _ *http.Request, b []byte) error {
		ms, err := srcconv.ParseSketches(b, maxSourceEntries)
		if err != nil {
			return err
		}
		return r.metricList(ms)
	}, `{}`))
	mux.HandleFunc("POST /api/v1/events", auth(func(_ http.ResponseWriter, _ *http.Request, b []byte) error {
		evs, err := srcconv.DecodeObjects(b, maxSourceEntries)
		if err != nil {
			return err
		}
		now := uint64(time.Now().UnixNano()) //nolint:gosec // positive
		recs := make([]*logspb.LogRecord, 0, len(evs))
		for _, e := range evs {
			recs = append(recs, srcconv.DDEventLog(e, now))
		}
		if len(recs) == 0 {
			return nil
		}
		return r.Logs(logsReq(recs))
	}, `{"status":"ok"}`))
	mux.HandleFunc("POST /v0.7/traces", auth(func(_ http.ResponseWriter, hr *http.Request, b []byte) error {
		v, err := srcconv.MsgpackDecode(b)
		top, isMap := v.(map[string]any)
		if err != nil || !isMap {
			return srcconv.ErrDatadog
		}
		req, err := srcconv.DDTracesV07(top, maxSourceEntries)
		if err != nil {
			return err
		}
		return r.Traces(hr.Context(), req, false)
	}, `{"rate_by_service":{}}`))
	for _, m := range []string{"POST", "PUT"} {
		mux.HandleFunc(m+" /v0.3/traces", traces(srcconv.DDTraces))
		mux.HandleFunc(m+" /v0.4/traces", traces(srcconv.DDTraces))
		mux.HandleFunc(m+" /v0.5/traces", traces(srcconv.DDTracesV05))
	}
	return mux
}

// hecChannelMax bounds the channels and the unacknowledged ids one channel remembers.
const (
	hecChannels   = 10_000
	hecPendingMax = 100_000
)

// hecAcks implements indexer acknowledgement. A request is acknowledged once its events are in
// the disk queue, which happens before the response is sent, so an issued id is already true:
// the ack endpoint reports each issued id once (like Splunk, which forgets an id once it is
// reported) and unknown ids as false.
type hecAcks struct {
	mu sync.Mutex
	ch map[string]*hecChan
}

type hecChan struct {
	next    uint64
	pending map[uint64]struct{}
}

func (a *hecAcks) issue(channel string) (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.ch[channel]
	if c == nil {
		if len(a.ch) >= hecChannels {
			return 0, false
		}
		c = &hecChan{pending: map[uint64]struct{}{}}
		a.ch[channel] = c
	}
	id := c.next
	c.next++
	c.pending[id] = struct{}{}
	if len(c.pending) > hecPendingMax {
		delete(c.pending, id-hecPendingMax) // the oldest id nobody asked about
	}
	return id, true
}

// query returns the state of ids on channel and forgets the acknowledged ones.
func (a *hecAcks) query(channel string, ids []uint64) map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]bool, len(ids))
	c := a.ch[channel]
	for _, id := range ids {
		ok := false
		if c != nil {
			_, ok = c.pending[id]
			delete(c.pending, id)
		}
		out[strconv.FormatUint(id, 10)] = ok
	}
	return out
}

func hecChannelOf(r *http.Request) string {
	if c := r.Header.Get("X-Splunk-Request-Channel"); c != "" {
		return c
	}
	return r.URL.Query().Get("channel")
}

// hecHandler serves Splunk HEC: /services/collector[/event] (JSON events, metric events become
// gauges), /services/collector/raw (one event per line; host, source, sourcetype, index in the
// query), /services/collector/ack (indexer acknowledgement) and /services/collector/health.
// A request on a channel (X-Splunk-Request-Channel or ?channel=) gets an `ackId`; /raw requires one.
func (r *Relay) hecHandler(token string) http.Handler {
	mux := http.NewServeMux()
	acks := &hecAcks{ch: map[string]*hecChan{}}
	ok := func(w http.ResponseWriter, hr *http.Request) bool {
		got := strings.TrimPrefix(strings.TrimPrefix(hr.Header.Get("Authorization"), "Splunk "), "Bearer ")
		if !tokenOK(token, got) {
			writeJSONString(w, http.StatusUnauthorized, `{"text":"Invalid token","code":4}`)
			return false
		}
		return true
	}
	// done answers success; with a channel the response carries the request's ackId.
	done := func(w http.ResponseWriter, channel string) {
		if channel != "" && len(channel) <= 128 {
			if id, good := acks.issue(channel); good {
				writeJSONString(w, http.StatusOK, `{"text":"Success","code":0,"ackId":`+strconv.FormatUint(id, 10)+`}`)
				return
			}
			writeJSONString(w, http.StatusServiceUnavailable, `{"text":"Server is busy","code":9}`)
			return
		}
		writeJSONString(w, http.StatusOK, `{"text":"Success","code":0}`)
	}
	event := func(w http.ResponseWriter, hr *http.Request) {
		if !ok(w, hr) {
			return
		}
		raw, good := sourceBody(w, hr)
		if !good {
			return
		}
		evs, err := srcconv.HECDecode(raw, maxSourceEntries)
		if err != nil {
			ingestFail(w, err)
			return
		}
		lreq, mreq := srcconv.HECRequests(evs, uint64(time.Now().UnixNano())) //nolint:gosec // positive
		if srcconv.HECLogCount(lreq) > 0 {
			if err := r.Logs(lreq); err != nil {
				ingestFail(w, err)
				return
			}
		}
		if mreq != nil {
			if err := r.Metrics(mreq); err != nil {
				ingestFail(w, err)
				return
			}
		}
		done(w, hecChannelOf(hr))
	}
	mux.HandleFunc("POST /services/collector", event)
	mux.HandleFunc("POST /services/collector/event", event)
	mux.HandleFunc("POST /services/collector/raw", func(w http.ResponseWriter, hr *http.Request) {
		if !ok(w, hr) {
			return
		}
		channel := hecChannelOf(hr)
		if channel == "" {
			writeJSONString(w, http.StatusBadRequest, `{"text":"Data channel is missing","code":10}`)
			return
		}
		raw, good := sourceBody(w, hr)
		if !good {
			return
		}
		q := hr.URL.Query()
		e := srcconv.HECEvt{Host: q.Get("host"), Source: q.Get("source"), Sourcetype: q.Get("sourcetype"), Index: q.Get("index")}
		req, err := srcconv.HECRawRequest(string(raw), e, uint64(time.Now().UnixNano()), maxSourceEntries) //nolint:gosec // positive
		if err == nil {
			err = r.Logs(req)
		}
		if err != nil {
			ingestFail(w, err)
			return
		}
		done(w, channel)
	})
	mux.HandleFunc("POST /services/collector/ack", func(w http.ResponseWriter, hr *http.Request) {
		if !ok(w, hr) {
			return
		}
		channel := hecChannelOf(hr)
		if channel == "" {
			writeJSONString(w, http.StatusBadRequest, `{"text":"Data channel is missing","code":10}`)
			return
		}
		raw, good := sourceBody(w, hr)
		if !good {
			return
		}
		var in struct {
			Acks []uint64 `json:"acks"`
		}
		if err := json.Unmarshal(raw, &in); err != nil || len(in.Acks) > 10_000 {
			writeJSONString(w, http.StatusBadRequest, `{"text":"Invalid data format","code":6}`)
			return
		}
		out, _ := json.Marshal(map[string]any{"acks": acks.query(channel, in.Acks)})
		writeJSONString(w, http.StatusOK, string(out))
	})
	health := func(w http.ResponseWriter, _ *http.Request) {
		writeJSONString(w, http.StatusOK, `{"text":"HEC is healthy","code":17}`)
	}
	mux.HandleFunc("GET /services/collector/health", health)
	mux.HandleFunc("GET /services/collector/health/1.0", health)
	return mux
}
