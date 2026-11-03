package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func wantNames(t *testing.T, r *sink.Recorder, names ...string) {
	t.Helper()
	got := r.Names()
	for _, n := range names {
		if !got[n] {
			t.Errorf("missing metric %s (have %v)", n, got)
		}
	}
}

func value(r *sink.Recorder, name string) (float64, bool) {
	for _, s := range r.Samples {
		if s.Name == name {
			return s.Value, true
		}
	}
	return 0, false
}

const redisInfoFixture = "# Server\r\nredis_version:7.2.4\r\nuptime_in_seconds:100\r\n\r\n# Clients\r\nconnected_clients:12\r\n" +
	"# Memory\r\nused_memory:1048576\r\nmaxmemory:0\r\n# Stats\r\ntotal_commands_processed:5000\r\nkeyspace_hits:90\r\n" +
	"keyspace_misses:10\r\nevicted_keys:3\r\n# Replication\r\nrole:slave\r\nmaster_link_status:down\r\n# Keyspace\r\ndb0:keys=42,expires=1,avg_ttl=0\r\n"

func TestRedisInfoParse(t *testing.T) {
	info := ParseRedisInfo(redisInfoFixture)
	if info["connected_clients"] != "12" || info["db0"] != "keys=42,expires=1,avg_ttl=0" || len(info["# Server"]) != 0 {
		t.Fatalf("parse: %v", info)
	}
	var r sink.Recorder
	EmitRedis(&r, info, time.Now())
	wantNames(t, &r, "redis.clients.connected", "redis.memory.used", "redis.commands.processed", "redis.keys.evicted",
		"redis.db.keys", "redis.replication.link_up")
	if v, _ := value(&r, "redis.replication.link_up"); v != 0 {
		t.Fatalf("link is down, got %v", v)
	}
	if v, _ := value(&r, "redis.db.keys"); v != 42 {
		t.Fatalf("keys: %v", v)
	}
}

func TestMemcachedStats(t *testing.T) {
	st, err := ReadMemcachedStats(bufio.NewReader(strings.NewReader("STAT curr_connections 7\r\nSTAT evictions 4\r\nEND\r\n")))
	if err != nil || st["curr_connections"] != "7" {
		t.Fatalf("%v %v", st, err)
	}
	var r sink.Recorder
	EmitMemcached(&r, st, time.Now())
	wantNames(t, &r, "memcached.connections.current", "memcached.evictions")
	if _, err := ReadMemcachedStats(bufio.NewReader(strings.NewReader("ERROR\r\n"))); err == nil {
		t.Fatal("an error reply must not parse as stats")
	}
}

const rabbitFixture = `[{"name":"orders","vhost":"/","messages":120,"messages_unacknowledged":5,"consumers":2},
{"name":"idle","vhost":"/","messages":0,"messages_unacknowledged":0,"consumers":0}]`

func TestRabbitMQFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); !ok || u != "wt" || p != "secret" || req.URL.Path != "/api/queues" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, rabbitFixture)
	}))
	defer srv.Close()
	c := HTTPConfig{URL: srv.URL, Username: "wt", Password: "secret"}
	b, err := getBody(context.Background(), c, srv.URL+"/api/queues?columns=name")
	if err != nil {
		t.Fatal(err)
	}
	var r sink.Recorder
	if err := EmitRabbitQueues(&r, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, &r, "rabbitmq.queue.messages", "rabbitmq.queue.unacknowledged", "rabbitmq.queue.consumers")
	if r.Samples[0].Attrs["queue"] != "orders" || r.Samples[0].Value != 120 {
		t.Fatalf("deepest queue first: %+v", r.Samples[0])
	}
	if _, err := getBody(context.Background(), HTTPConfig{}, srv.URL+"/api/queues"); err == nil {
		t.Fatal("a 401 must be an error")
	}
	if err := EmitRabbitQueues(&r, []byte(`{"error":"x"}`), time.Now()); err == nil {
		t.Fatal("not a queue list accepted")
	}
}

func TestNATSEndpoints(t *testing.T) {
	var r sink.Recorder
	if err := EmitNATSVarz(&r, []byte(`{"connections":3,"slow_consumers":1,"in_msgs":10,"out_msgs":9,"mem":2048}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := EmitNATSJsz(&r, []byte(`{"streams":2,"consumers":4,"messages":100,"bytes":4096}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, &r, "nats.connections", "nats.slow_consumers", "nats.jetstream.streams", "nats.jetstream.bytes")
}

func TestStatusPageParsers(t *testing.T) {
	now := time.Now()
	var r sink.Recorder
	nginx := "Active connections: 291 \nserver accepts handled requests\n 16630948 16630948 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n"
	if err := EmitNginx(&r, []byte(nginx), now); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(&r, "nginx.connections.active"); v != 291 {
		t.Fatalf("active: %v", v)
	}
	if v, _ := value(&r, "nginx.requests"); v != 31070465 {
		t.Fatalf("requests: %v", v)
	}
	if EmitNginx(&r, []byte("<html>login</html>"), now) == nil {
		t.Fatal("html accepted as stub_status")
	}
	if err := EmitApache(&r, []byte("Total Accesses: 10\nBusyWorkers: 3\nIdleWorkers: 7\nServerUptimeSeconds: 99\n"), now); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(&r, "apache.workers.idle"); v != 7 {
		t.Fatalf("idle: %v", v)
	}
	csv := "# pxname,svname,qcur,scur,stot,status,hrsp_5xx,econ\nweb,FRONTEND,,12,100,OPEN,0,\nweb,app1,0,5,90,DOWN,4,1\n"
	if err := EmitHAProxy(&r, []byte(csv), now); err != nil {
		t.Fatal(err)
	}
	downs := 0
	for _, s := range r.Samples {
		if s.Name == "haproxy.up" && s.Value == 0 && s.Attrs["server"] == "app1" {
			downs++
		}
	}
	if downs != 1 {
		t.Fatalf("app1 must be down once: %d", downs)
	}
	if err := EmitElasticsearch(&r, []byte(`{"status":"yellow","number_of_nodes":3,"unassigned_shards":2}`), now); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(&r, "elasticsearch.cluster.status"); v != 1 {
		t.Fatalf("yellow is 1: %v", v)
	}
}

func TestMySQLReplicaBothNamings(t *testing.T) {
	for _, row := range []map[string]string{
		{"Replica_IO_Running": "Yes", "Replica_SQL_Running": "No", "Seconds_Behind_Source": "42"},
		{"Slave_IO_Running": "Yes", "Slave_SQL_Running": "No", "Seconds_Behind_Master": "42"},
	} {
		var r sink.Recorder
		EmitMySQLReplica(&r, row, time.Now())
		if v, _ := value(&r, "mysql.replica.lag"); v != 42 {
			t.Errorf("lag: %v", v)
		}
		if v, _ := value(&r, "mysql.replica.sql_running"); v != 0 {
			t.Errorf("sql thread stopped: %v", v)
		}
	}
	var r sink.Recorder
	EmitMySQLReplica(&r, map[string]string{"Slave_IO_Running": "No", "Seconds_Behind_Master": ""}, time.Now())
	if _, ok := value(&r, "mysql.replica.lag"); ok {
		t.Fatal("NULL lag must not become a point")
	}
}

func TestMongoReplSetLag(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	// Through real BSON bytes, decoded the way the driver decodes a command reply: nested
	// documents come back as bson.D, not bson.M.
	roundTrip := func(in bson.M) bson.D {
		b, err := bson.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out bson.D
		if err := bson.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	rs := roundTrip(bson.M{"members": bson.A{
		bson.M{"name": "a:27017", "stateStr": "PRIMARY", "health": 1.0, "optimeDate": bson.NewDateTimeFromTime(t0)},
		bson.M{"name": "b:27017", "stateStr": "SECONDARY", "health": int32(1), "optimeDate": bson.NewDateTimeFromTime(t0.Add(-17 * time.Second))},
	}})
	var r sink.Recorder
	EmitReplSet(&r, rs, time.Now())
	if v, ok := value(&r, "mongodb.replset.lag"); !ok || v != 17 {
		t.Fatalf("lag: %v %v", v, ok)
	}
	ss := roundTrip(bson.M{"connections": bson.M{"current": int32(5)}, "opcounters": bson.M{"insert": int64(9)},
		"metrics": bson.M{"queryExecutor": bson.M{"scanned": int64(40), "collectionScans": bson.M{"total": int64(3)}}}})
	if !EmitServerStatus(&r, ss, time.Now()) {
		t.Fatal("connection counts not found in a decoded reply")
	}
	wantNames(t, &r, "mongodb.connections.current", "mongodb.operations")
	if v, _ := value(&r, "mongodb.query_executor.collection_scans"); v != 3 {
		t.Fatalf("collection scans: %v", v)
	}
	if v, _ := value(&r, "mongodb.connections.current"); v != 5 {
		t.Fatalf("connections: %v", v)
	}
	// A reply without connection counts is not a healthy server (the module then reports up=0).
	if EmitServerStatus(&sink.Recorder{}, roundTrip(bson.M{"ok": 1.0}), time.Now()) {
		t.Fatal("empty serverStatus accepted")
	}
}

func TestKafkaCapsGroupsTopicsAndSeries(t *testing.T) {
	lags := kadm.DescribedGroupLags{}
	for _, g := range []string{"g1", "g2", "g3"} {
		lag := kadm.GroupLag{}
		for i := 0; i < MaxKafkaTopics+100; i++ {
			lag[fmt.Sprintf("t%04d", i)] = map[int32]kadm.GroupMemberLag{0: {Lag: int64(i)}}
		}
		lags[g] = kadm.DescribedGroupLag{Group: g, Lag: lag}
	}
	var r sink.Recorder
	st := &KafkaState{}
	emitLag(&r, lags, st, time.Now())
	perGroup := map[string]int{}
	topicSeries := 0
	for _, s := range r.Samples {
		switch s.Name {
		case "kafka.consumer_group.lag_sum":
			perGroup[s.Attrs["group"]]++
			if s.Value < 100 {
				t.Fatalf("a small lag kept while a larger one was cut: %v", s.Value)
			}
		case "kafka.consumer_group.lag":
			topicSeries++
		}
	}
	for g, n := range perGroup {
		if n > MaxKafkaTopics {
			t.Fatalf("%s: %d lag_sum series", g, n)
		}
	}
	if topicSeries > maxLagSeries || st.dropped[droppedTopics] != 300 {
		t.Fatalf("partition series %d, dropped %v", topicSeries, st.dropped)
	}
}

func TestHTTPStatusTargetsAreMultiInstance(t *testing.T) {
	good := `{"targets":[{"kind":"nginx","url":"http://127.0.0.1/s","service":"web1"},
		{"kind":"nginx","url":"http://127.0.0.2/s","service":"web2"},{"kind":"elasticsearch","url":"http://127.0.0.1:9200/_cluster/health","timeout":"3s"}]}`
	if err := ValidateConfig("http_status", json.RawMessage(good)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"duplicate service": `{"targets":[{"kind":"nginx","url":"http://a/s"},{"kind":"nginx","url":"http://b/s"}]}`,
		"unknown kind":      `{"targets":[{"kind":"iis","url":"http://a/s"}]}`,
		"no targets":        `{"targets":[]}`,
		"long timeout":      `{"targets":[{"kind":"nginx","url":"http://a/s","timeout":"5m"}]}`,
		"old single form":   `{"kind":"nginx","url":"http://a/s"}`,
	} {
		if ValidateConfig("http_status", json.RawMessage(bad)) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A target's metrics carry its service label.
	var r sink.Recorder
	tg := tagged{&r, "web2"}
	if err := EmitNginx(tg, []byte("Active connections: 1 \nserver accepts handled requests\n 1 1 1 \nReading: 0 Writing: 1 Waiting: 0 \n"), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Samples {
		if s.Attrs["service"] != "web2" {
			t.Fatalf("untagged sample %+v", s)
		}
	}
}

func TestRabbitMQPagedReply(t *testing.T) {
	var r sink.Recorder
	if err := EmitRabbitQueues(&r, []byte(`{"page":1,"items":[`+rabbitFixture[1:len(rabbitFixture)-1]+`]}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, &r, "rabbitmq.queue.messages")
}

// Every manifest's suggested local config must be accepted by the module it names, so the
// "enable" guidance of /integrations/detected cannot hand out a config the agent refuses.
func TestManifestConfigDefaultsPassModuleValidation(t *testing.T) {
	for _, m := range loadAll(t) {
		raw, err := json.Marshal(m.Module.ConfigDefaults)
		if err != nil {
			t.Fatal(err)
		}
		switch m.Module.Kind {
		case "host":
			continue // the host module owns its own config
		case "prometheus":
			var c custom.PromConfig
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil || len(c.Targets) == 0 {
				t.Errorf("%s: prometheus config needs targets: %v", m.Name, err)
			}
		default:
			if err := ValidateConfig(m.Module.Kind, raw); err != nil {
				t.Errorf("%s: %v", m.Name, err)
			}
		}
	}
}

func TestKafkaPartitionHealth(t *testing.T) {
	ps := kadm.PartitionDetails{
		0: {Partition: 0, Leader: 1, Replicas: []int32{1, 2, 3}, ISR: []int32{1, 2, 3}},
		1: {Partition: 1, Leader: 1, Replicas: []int32{1, 2, 3}, ISR: []int32{1}},
		2: {Partition: 2, Leader: -1, Replicas: []int32{1, 2, 3}},
	}
	if under, off := PartitionHealth(ps); under != 1 || off != 1 {
		t.Fatalf("under %d offline %d", under, off)
	}
}

func TestPostgresModuleAgainstLocalPG(t *testing.T) {
	dsn := os.Getenv("WT_PG_URL")
	if dsn == "" {
		t.Skip("WT_PG_URL unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var r sink.Recorder
	if err := CollectPostgres(ctx, dsn, &r, time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, &r, "postgresql.backends", "postgresql.commits", "postgresql.database.xid_age", "postgresql.wal.archive_failures")
	for _, s := range r.Samples {
		if s.Name == "postgresql.database.xid_age" && (s.Value < 0 || s.Value >= XIDWarnAge) {
			t.Fatalf("a fresh test database cannot be near wraparound: %v", s.Value)
		}
	}
}

func TestKafkaLagAgainstLocalKafka(t *testing.T) {
	broker := os.Getenv("WT_KAFKA")
	if broker == "" {
		t.Skip("WT_KAFKA unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cl, err := kgo.NewClient(kgo.SeedBrokers(strings.Split(broker, ",")...), kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	adm := kadm.NewClient(cl)
	topic, group := os.Getenv("WT_RUN_ID")+".i4lag", os.Getenv("WT_RUN_ID")+"-i4-group"
	if _, err := adm.CreateTopic(ctx, 1, 1, nil, topic); err != nil {
		t.Fatal(err)
	}
	defer adm.DeleteTopics(context.Background(), topic)
	for i := 0; i < 3; i++ {
		if err := cl.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: []byte("x")}).FirstErr(); err != nil {
			t.Fatal(err)
		}
	}
	// A group that committed offset 0 on a topic holding 3 records is 3 behind.
	offs := kadm.Offsets{}
	offs.AddOffset(topic, 0, 0, -1)
	if _, err := adm.CommitOffsets(ctx, group, offs); err != nil {
		t.Fatal(err)
	}
	var r sink.Recorder
	if err := CollectKafka(ctx, adm, []string{group}, nil, &r, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Samples {
		if s.Name == "kafka.consumer_group.lag_sum" && s.Attrs["group"] == group && s.Attrs["topic"] == topic {
			if s.Value != 3 {
				t.Fatalf("lag: %v", s.Value)
			}
			return
		}
	}
	t.Fatalf("no lag series for %s/%s in %v", group, topic, r.Names())
}
