package main

// `wt-agent postgres bootstrap`: the least-privilege monitoring role, as SQL to print or run.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

// bootstrapSQL is idempotent. password must be hex (generated here), so it cannot break the quoting.
func bootstrapSQL(password string) []string {
	return []string{
		`DO $wt$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wt_monitor') THEN CREATE ROLE wt_monitor LOGIN PASSWORD '` + password +
			`'; ELSE ALTER ROLE wt_monitor LOGIN PASSWORD '` + password + `'; END IF; END $wt$`,
		`GRANT pg_monitor TO wt_monitor`,
		`DO $wt$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO wt_monitor', current_database()); END $wt$`,
	}
}

const statementsCheck = `SELECT EXISTS (SELECT FROM pg_extension WHERE extname = 'pg_stat_statements')`

const statementsHint = "pg_stat_statements is not installed: add it to shared_preload_libraries (restart), then run CREATE EXTENSION pg_stat_statements; in the monitored database"

func postgresCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "bootstrap" {
		fmt.Fprintln(stderr, "usage: wt-agent postgres bootstrap [--dsn ADMIN_DSN] [--print] (prints the SQL when there is no --dsn)")
		return 2
	}
	fs := flag.NewFlagSet("postgres bootstrap", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "admin DSN: with it the SQL runs (unless --print)")
	run := fs.Bool("run", false, "execute the SQL with --dsn instead of printing it")
	print := fs.Bool("print", false, "print the SQL even when --dsn is given")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	pw := hex.EncodeToString(b)
	stmts := bootstrapSQL(pw)
	if *print || (!*run && *dsn == "") {
		for _, s := range stmts {
			fmt.Fprintln(stdout, s+";")
		}
		fmt.Fprintln(stdout, "-- check: "+statementsCheck+";")
		fmt.Fprintln(stdout, "-- the generated password is shown once, here; put it in the agent's postgres dsn, e.g. postgres://wt_monitor:"+pw+"@HOST:5432/DB")
		return 0
	}
	if *dsn == "" {
		fmt.Fprintln(stderr, "--run needs --dsn")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(stderr, "postgres bootstrap: connect failed (the DSN is not echoed):", err.Error())
		return 1
	}
	defer conn.Close(context.Background())
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			fmt.Fprintln(stderr, "postgres bootstrap:", err)
			return 1
		}
	}
	var have bool
	if err := conn.QueryRow(ctx, statementsCheck).Scan(&have); err == nil && !have {
		fmt.Fprintln(stderr, "warning:", statementsHint)
	}
	fmt.Fprintln(stdout, "role wt_monitor ready; password (shown once): "+pw)
	return 0
}
