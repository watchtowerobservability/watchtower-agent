package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// A Neo4j 5.20 reply to the two statements of the neo4j module.
const neo4jFixture = `{"results":[
{"columns":["database","transactionId","currentQuery","ms","status","activeLockCount"],"data":[
 {"row":["neo4j","neo4j-transaction-12","MATCH (u:User {email: \"a@b.c\"}) SET u.age = 42 RETURN u",5400,"Running",3]},
 {"row":["neo4j","neo4j-transaction-13","MATCH (u:User) WHERE u.name = 'bob' DETACH DELETE u",2100,"Blocked by: [neo4j-transaction-12]",0]},
 {"row":["system","system-transaction-1","SHOW TRANSACTIONS YIELD database",1,"Running",0]}]},
{"columns":["name","currentStatus","role"],"data":[{"row":["neo4j","online","primary"]},{"row":["movies","offline","primary"]}]}],"errors":[]}`

func TestNeo4jTransactionsAndChains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/db/system/tx/commit" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, neo4jFixture)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rec := &sink.Recorder{}
	_ = Neo4j(ctx, json.RawMessage(fmt.Sprintf(`{"url":%q,"username":"wt","password":"pw"}`, srv.URL)), rec)
	if v, _ := value(rec, "neo4j.transactions.slow"); v != 2 {
		t.Fatalf("slow %v", v)
	}
	if v, _ := value(rec, "neo4j.transactions.blocked"); v != 1 {
		t.Fatalf("blocked %v", v)
	}
	if v, _ := value(rec, "db.blocking.chain_depth"); v != 1 {
		t.Fatalf("chain depth %v", v)
	}
	offline := false
	for _, s := range rec.Samples {
		if s.Name == "neo4j.database.online" && s.Attrs["db.namespace"] == "movies" && s.Value == 0 {
			offline = true
		}
		if s.Name == "" && (strings.Contains(s.Body, "a@b.c") || strings.Contains(s.Body, "bob") || strings.Contains(s.Body, "42")) {
			t.Fatalf("literal leaked: %s", s.Body)
		}
	}
	if !offline {
		t.Fatal("offline database not reported")
	}
}

// Trimmed CouchDB 3.3 replies.
const couchStatsFixture = `{"couchdb":{"database_reads":{"value":1200,"type":"counter","desc":""},
"open_databases":{"value":12,"type":"counter","desc":""},"open_os_files":{"value":40,"type":"gauge","desc":""},
"request_time":{"value":{"arithmetic_mean":12.5,"percentile":[[50,4.1],[75,8],[90,20],[95,30],[99,80],[999,200]]},"type":"histogram","desc":""},
"httpd_status_codes":{"200":{"value":900,"type":"counter","desc":""},"500":{"value":3,"type":"counter","desc":""}}}}`

func TestCouchDBStatsTasksAndDatabases(t *testing.T) {
	var stats map[string]any
	_ = json.Unmarshal([]byte(couchStatsFixture), &stats)
	rec := &sink.Recorder{}
	now := time.Unix(1_800_000_000, 0)
	if n := EmitCouchStats(rec, stats, now); n != 9 {
		t.Fatalf("series %d", n)
	}
	EmitCouchTasks(rec, []map[string]any{{"type": "database_compaction", "started_on": float64(now.Unix() - 600), "progress": 40.0}}, now)
	EmitCouchReplications(rec, []map[string]any{{"state": "crashing", "source": "https://u:secret@x/db"}}, now)
	EmitCouchDB(rec, "orders", map[string]any{"sizes": map[string]any{"file": 1000.0, "active": 250.0}, "doc_count": 10.0}, now)
	wantNames(t, rec, "couchdb.couchdb.database_reads", "couchdb.couchdb.request_time", "couchdb.couchdb.request_time.mean",
		"couchdb.couchdb.httpd_status_codes", "couchdb.active_tasks.oldest_age", "couchdb.replications", "couchdb.database.fragmentation")
	for _, s := range rec.Samples {
		if strings.Contains(fmt.Sprint(s.Attrs), "secret") {
			t.Fatal("replication endpoint leaked")
		}
		switch {
		case s.Name == "couchdb.couchdb.httpd_status_codes" && s.Attrs["key"] == "500" && s.Value != 3,
			s.Name == "couchdb.active_tasks.oldest_age" && s.Value != 600,
			s.Name == "couchdb.database.fragmentation" && s.Value != 0.75,
			s.Name == "couchdb.replications" && s.Attrs["state"] == "crashing" && s.Value != 1:
			t.Fatalf("%+v", s)
		}
	}
}
