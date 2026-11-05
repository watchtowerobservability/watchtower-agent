package snmp

import (
	"testing"
	"time"
)

func TestUpdateExpiresStaleSeries(t *testing.T) {
	var r Rates
	t0 := time.Unix(1000, 0)
	r.Update("sw|if1", 100, 64, t0)
	r.Update("sw|if1", 200, 64, t0.Add(time.Second)) // if1 stays fresh
	// A series seen well past the TTL triggers a sweep that drops the now-stale if1 baseline.
	r.Update("sw|if2", 10, 64, t0.Add(2*seriesTTL))
	if _, ok := r.prev["sw|if1"]; ok {
		t.Fatal("a series not seen within seriesTTL should be pruned")
	}
	if _, ok := r.prev["sw|if2"]; !ok {
		t.Fatal("the freshly seen series must remain")
	}
}
