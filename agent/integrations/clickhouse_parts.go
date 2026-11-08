package integrations

// ClickHouse table health (track A2): active parts per table and the worst partition (the
// "too many parts" limit), running merges and mutations, unfinished mutations, replication
// queues and delay, and samples of the slowest queries (canonical normalization in the agent, literals removed).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

var clickhouseHealthQueries = map[string]string{
	"parts": `SELECT database, table, sum(c) AS parts, max(c) AS max_partition_parts, sum(r) AS rows, sum(b) AS bytes
 FROM (SELECT database, table, partition_id, count() AS c, sum(rows) AS r, sum(bytes_on_disk) AS b
 FROM system.parts WHERE active GROUP BY database, table, partition_id)
 GROUP BY database, table ORDER BY max_partition_parts DESC LIMIT 100 FORMAT JSONEachRow`,
	"merges": `SELECT database, table, count() AS merges, countIf(is_mutation) AS mutations, max(elapsed) AS longest_s,
 sum(total_size_bytes_compressed) AS bytes FROM system.merges GROUP BY database, table FORMAT JSONEachRow`,
	"mutations": `SELECT database, table, count() AS pending, countIf(latest_fail_reason != '') AS failing,
 dateDiff('second', min(create_time), now()) AS oldest_s FROM system.mutations WHERE NOT is_done
 GROUP BY database, table FORMAT JSONEachRow`,
	"replicas": `SELECT database, table, is_readonly, absolute_delay, queue_size, inserts_in_queue, merges_in_queue,
 active_replicas, total_replicas FROM system.replicas FORMAT JSONEachRow`,
	"errors": `SELECT name, sum(value) AS total FROM (SELECT name, value FROM system.errors WHERE value > 0 UNION ALL SELECT 'MEMORY_LIMIT_EXCEEDED', 0 UNION ALL SELECT 'QUERY_MEMORY_LIMIT_EXCEEDED', value FROM system.events WHERE event = 'QueryMemoryLimitExceeded' UNION ALL SELECT 'QUERY_MEMORY_LIMIT_EXCEEDED', 0) GROUP BY name ORDER BY name IN ('MEMORY_LIMIT_EXCEEDED', 'QUERY_MEMORY_LIMIT_EXCEEDED') DESC, total DESC LIMIT 50 FORMAT JSONEachRow`,
	"slow": `SELECT toString(normalized_query_hash) AS id, substring(query, 1, 8192) AS q,
 query_duration_ms AS ms, read_rows, memory_usage AS mem, exception_code AS error FROM system.query_log
 WHERE type IN ('QueryFinish', 'ExceptionWhileProcessing') AND event_time > now() - INTERVAL 60 SECOND
 AND is_initial_query ORDER BY query_duration_ms DESC LIMIT 5 FORMAT JSONEachRow`,
}

// clickhouseHealth runs the health queries; one that fails (an old server, no replicated
// tables, missing grant on a system table) is skipped.
func clickhouseHealth(ctx context.Context, c HTTPConfig, out sink.Sink, now time.Time) {
	for kind, q := range clickhouseHealthQueries {
		b, err := getBody(ctx, c, c.URL+"/?query="+url.QueryEscape(q))
		if err != nil {
			continue
		}
		_ = EmitClickHouseHealth(out, kind, b, now)
	}
}

// chRows decodes JSONEachRow; numbers (quoted or not) stay json.Number or string.
func chRows(body []byte, each func(map[string]any)) error {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.UseNumber()
		var m map[string]any
		if err := d.Decode(&m); err != nil {
			return err
		}
		each(m)
	}
	return sc.Err()
}

func chNum(v any) float64 {
	switch t := v.(type) {
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		return jnum(json.Number(t))
	case bool:
		if t {
			return 1
		}
	}
	return 0
}

func chStr(v any) string { s, _ := v.(string); return s }

// EmitClickHouseHealth turns the rows of one health query (kind as in clickhouseHealthQueries).
func EmitClickHouseHealth(out sink.Sink, kind string, body []byte, now time.Time) error {
	return chRows(body, func(m map[string]any) {
		a := map[string]string{"db.namespace": chStr(m["database"]), "db.collection.name": chStr(m["table"])}
		g := func(name, unit, col string) { out.Gauge(name, unit, chNum(m[col]), a, now) }
		switch kind {
		case "parts":
			g("clickhouse.table.parts", "{parts}", "parts")
			g("clickhouse.table.max_partition_parts", "{parts}", "max_partition_parts")
			g("clickhouse.table.rows", "{rows}", "rows")
			g("clickhouse.table.bytes", "By", "bytes")
		case "merges":
			g("clickhouse.table.merges.running", "{merges}", "merges")
			g("clickhouse.table.mutations.running", "{mutations}", "mutations")
			g("clickhouse.table.merges.longest", "s", "longest_s")
		case "mutations":
			g("clickhouse.table.mutations.pending", "{mutations}", "pending")
			g("clickhouse.table.mutations.failing", "{mutations}", "failing")
			g("clickhouse.table.mutations.oldest_age", "s", "oldest_s")
		case "replicas":
			g("clickhouse.replica.readonly", "1", "is_readonly")
			g("clickhouse.replica.delay", "s", "absolute_delay")
			g("clickhouse.replica.queue", "{entries}", "queue_size")
			g("clickhouse.replica.inserts_in_queue", "{entries}", "inserts_in_queue")
			g("clickhouse.replica.active", "{replicas}", "active_replicas")
			g("clickhouse.replica.total", "{replicas}", "total_replicas")
		case "errors":
			out.Sum("clickhouse.errors", "{errors}", chNum(m["total"]), map[string]string{"error.type": chStr(m["name"])}, now)
		case "slow":
			// The raw text never leaves the agent: only the canonical normalization and its hash.
			text, hash := dbm.HashSQL(chStr(m["q"]), false)
			dbm.EmitSample(out, "clickhouse", "query.sample", "INFO", map[string]any{"query": text, "ms": chNum(m["ms"]),
				"read_rows": chNum(m["read_rows"]), "memory": chNum(m["mem"]), "error_code": chNum(m["error"])},
				map[string]string{"queryid": chStr(m["id"]), "db.query.hash": hash}, now)
		}
	})
}
