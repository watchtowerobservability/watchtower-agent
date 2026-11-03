package integrations

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestMSSQLBlockingEmits(t *testing.T) {
	r := &sink.Recorder{}
	MSSQLBlocking(r, []map[string]string{{"waiting_pid": "55", "blocking_pid": "51", "db": "sales", "wait": "LCK_M_X", "wait_age_secs": "1200"}}, time.Now())
	if len(r.Samples) != 1 || r.Samples[0].Name != "mssql.blocking.wait" || r.Samples[0].Value != 1200 ||
		r.Samples[0].Attrs["blocking_session"] != "51" || r.Samples[0].Attrs["db.namespace"] != "sales" {
		t.Fatalf("%+v", r.Samples)
	}
}

func TestMSSQLConfigCheck(t *testing.T) {
	if (&MSSQLConfig{DSN: "sqlserver://u:p@h:1433"}).check() != nil {
		t.Fatal("valid dsn rejected")
	}
	if (&MSSQLConfig{}).check() == nil {
		t.Fatal("empty dsn accepted")
	}
}
