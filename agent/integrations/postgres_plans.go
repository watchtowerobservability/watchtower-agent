package integrations

// Database observability depth (CFT-A14, Alloy database_observability parity), opt-in:
// `explain: true` logs the generic plan (EXPLAIN (GENERIC_PLAN, FORMAT JSON), PostgreSQL 16+,
// never ANALYZE, so nothing executes) of the 10 SELECTs with the most total time every 10
// rounds; `schema: true` logs one record per user table with its columns every 120 rounds. The
// session is read-only and each EXPLAIN has a 2 s statement timeout.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	explainEvery = 10
	schemaEvery  = 120
	maxPlanBytes = 16 << 10
)

func pgConn(ctx context.Context, dsn string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "2000"
	return pgx.ConnectConfig(ctx, cfg)
}

// explainable reports a single read-only statement EXPLAIN may plan.
func explainable(q string) bool {
	l := strings.ToLower(strings.TrimSpace(q))
	return (strings.HasPrefix(l, "select") || strings.HasPrefix(l, "with")) && !strings.Contains(l, ";") &&
		!strings.Contains(l, "for update") && !strings.Contains(l, "insert") && !strings.Contains(l, "update ") &&
		!strings.Contains(l, "delete") && len(q) < 32<<10
}

// CollectPlans logs generic plans of the top statements.
func CollectPlans(ctx context.Context, dsn string, out sink.Sink, now time.Time) error {
	conn, err := pgConn(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var ver int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&ver); err != nil || ver < 160000 {
		return nil // GENERIC_PLAN needs PostgreSQL 16
	}
	type stmt struct{ id, q string }
	var top []stmt
	_ = each(ctx, conn, `SELECT queryid::text, query FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 50`,
		func(r pgx.Rows) error {
			var s stmt
			if err := r.Scan(&s.id, &s.q); err != nil {
				return err
			}
			if explainable(s.q) && len(top) < 10 {
				top = append(top, s)
			}
			return nil
		})
	for _, s := range top {
		var plan string
		if err := conn.QueryRow(ctx, "EXPLAIN (GENERIC_PLAN, FORMAT JSON) "+s.q).Scan(&plan); err != nil {
			continue
		}
		EmitPlan(out, "postgresql", s.id, s.q, plan, now)
	}
	return nil
}

// EmitPlan writes one plan as a log record with its total cost.
func EmitPlan(out sink.Sink, engine, id, query, plan string, now time.Time) {
	var p []struct {
		Plan struct {
			TotalCost float64 `json:"Total Cost"`
			NodeType  string  `json:"Node Type"`
		} `json:"Plan"`
	}
	_ = json.Unmarshal([]byte(plan), &p)
	a := map[string]string{"db.system.name": engine, "db.query.id": id, "db.query.text": dbm.BindSafe(query), "event.name": "db.query.plan"}
	if len(p) > 0 {
		a["db.plan.total_cost"] = fmt.Sprint(p[0].Plan.TotalCost)
		a["db.plan.node_type"] = p[0].Plan.NodeType
	} else if c := planCost(plan); c != "" {
		a["db.plan.total_cost"] = c
	}
	out.Log("INFO", sink.Truncate(plan, maxPlanBytes), a, now)
}

var reXMLCost = regexp.MustCompile(`StatementSubTreeCost="([0-9.eE+-]+)"`)

// planCost reads the total cost of a MySQL JSON plan (query_block.cost_info.query_cost) or a SQL
// Server showplan (the first StatementSubTreeCost); "" when there is none.
func planCost(plan string) string {
	if m := reXMLCost.FindStringSubmatch(plan); m != nil {
		return m[1]
	}
	var my struct {
		QB struct {
			Cost struct {
				Q string `json:"query_cost"`
			} `json:"cost_info"`
		} `json:"query_block"`
	}
	_ = json.Unmarshal([]byte(plan), &my)
	return my.QB.Cost.Q
}

// CollectSchema logs the columns of every user table (at most 500 tables).
func CollectSchema(ctx context.Context, dsn string, out sink.Sink, now time.Time) error {
	conn, err := pgConn(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tables := map[string][]string{}
	var order []string
	err = each(ctx, conn, `SELECT table_schema || '.' || table_name, column_name || ' ' || data_type ||
		CASE WHEN is_nullable = 'NO' THEN ' not null' ELSE '' END
		FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY 1, ordinal_position`, func(r pgx.Rows) error {
		var t, col string
		if err := r.Scan(&t, &col); err != nil {
			return err
		}
		if _, ok := tables[t]; !ok {
			if len(order) >= 500 {
				return nil
			}
			order = append(order, t)
		}
		tables[t] = append(tables[t], col)
		return nil
	})
	if err != nil {
		return err
	}
	EmitSchema(out, "postgresql", order, tables, now)
	return nil
}

// EmitSchema writes one log record per table.
func EmitSchema(out sink.Sink, engine string, order []string, tables map[string][]string, now time.Time) {
	for _, t := range order {
		out.Log("INFO", sink.Truncate(strings.Join(tables[t], ", "), maxPlanBytes),
			map[string]string{"db.system.name": engine, "db.collection.name": t, "event.name": "db.schema.table",
				"db.columns": fmt.Sprint(len(tables[t]))}, now)
	}
}
