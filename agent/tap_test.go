package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type nopExp struct{ n int }

func (e *nopExp) Gauge(string, string, float64, map[string]string, time.Time) { e.n++ }
func (e *nopExp) Sum(string, string, float64, map[string]string, time.Time)   { e.n++ }
func (e *nopExp) Log(string, string, map[string]string, time.Time)            { e.n++ }

func TestTapCopiesOneModuleOnly(t *testing.T) {
	var tp taps
	inner := &nopExp{}
	a, b := tp.wrap("prometheus", inner), tp.wrap("host", inner)
	a.Gauge("before", "", 1, nil, time.Now()) // no tap yet
	done := make(chan []byte)
	go func() { done <- tp.Run(context.Background(), "prometheus", 1) }()
	time.Sleep(50 * time.Millisecond)
	a.Gauge("up", "", 1, map[string]string{"target": "x"}, time.Now())
	a.Log("info", "token=supersecretvalue", nil, time.Now())
	b.Gauge("cpu", "", 1, nil, time.Now())
	out := <-done
	var r struct {
		Items []tapItem `json:"items"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Items) != 2 || r.Items[0].Name != "up" || strings.Contains(string(out), "supersecretvalue") {
		t.Fatalf("tap %s", out)
	}
	if inner.n != 4 {
		t.Fatalf("pass-through %d", inner.n)
	}
}
