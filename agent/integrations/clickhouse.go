package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// clickhouseTopQueries groups the last interval of system.query_log by normalized query hash:
// the 50 heaviest statements by total duration, read-only over the HTTP interface.
const clickhouseTopQueries = `SELECT toString(normalized_query_hash) AS id,
 substring(replaceRegexpAll(any(query), '\\s+', ' '), 1, 120) AS q, count() AS calls,
 sum(query_duration_ms) AS ms, sum(read_rows) AS read_rows, sum(memory_usage) AS mem,
 countIf(exception_code != 0) AS errors
 FROM system.query_log WHERE type IN ('QueryFinish', 'ExceptionWhileProcessing')
 AND event_time > now() - INTERVAL 60 SECOND AND is_initial_query
 GROUP BY normalized_query_hash ORDER BY ms DESC LIMIT 50 FORMAT JSONEachRow`

// ClickHouse reads per-statement statistics from system.query_log every minute (the server's
// own Prometheus endpoint still covers server metrics through the prometheus module).
func ClickHouse(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "clickhouse", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		// No readonly=1 param: a read-only user (the recommended setup) rejects any settings change, even that one.
		b, err := getBody(ctx, *c, c.URL+"/?query="+url.QueryEscape(clickhouseTopQueries))
		if err != nil {
			return err
		}
		return EmitClickHouseQueries(out, b, now)
	})
}

// EmitClickHouseQueries turns JSONEachRow rows of clickhouseTopQueries into per-statement sums.
func EmitClickHouseQueries(out sink.Sink, body []byte, now time.Time) error {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		// ClickHouse quotes 64-bit integers in JSON by default, so read them as json.Number.
		var r struct {
			ID     string      `json:"id"`
			Q      string      `json:"q"`
			Calls  json.Number `json:"calls"`
			Ms     json.Number `json:"ms"`
			Rows   json.Number `json:"read_rows"`
			Mem    json.Number `json:"mem"`
			Errors json.Number `json:"errors"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("clickhouse: not a query_log row: %w", err)
		}
		a := map[string]string{"queryid": r.ID, "query": r.Q}
		out.Sum("clickhouse.statement.calls", "{calls}", jnum(r.Calls), a, now)
		out.Sum("clickhouse.statement.total_time", "ms", jnum(r.Ms), a, now)
		out.Sum("clickhouse.statement.read_rows", "{rows}", jnum(r.Rows), a, now)
		out.Sum("clickhouse.statement.memory", "By", jnum(r.Mem), a, now)
		out.Sum("clickhouse.statement.errors", "{errors}", jnum(r.Errors), a, now)
	}
	return sc.Err()
}

func jnum(n json.Number) float64 {
	f, _ := n.Float64()
	return f
}
