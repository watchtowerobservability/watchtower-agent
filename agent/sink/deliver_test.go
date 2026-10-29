package sink

import (
	"testing"
	"time"
)

func TestBackoffJitterBounds(t *testing.T) {
	for attempt, base := range map[int]time.Duration{0: time.Second, 3: 8 * time.Second, 20: 5 * time.Minute} {
		lo, hi := Backoff(attempt, 0), Backoff(attempt, 0.999999)
		if lo < time.Duration(0.8*float64(base)) || hi > time.Duration(1.2*float64(base)) || lo >= hi {
			t.Fatalf("attempt %d: [%v, %v] outside 20%% of %v", attempt, lo, hi, base)
		}
	}
}
