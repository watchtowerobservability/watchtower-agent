package sink

import (
	"context"
	"time"
)

// Delivering is implemented by a sink that can confirm delivery. A collector that reads from a
// source with offsets (Kafka, Event Hubs) commits them only after Flush returns nil, and pauses
// its reads while Buffered is above its high-water mark, so a slow or failing export never
// makes the sink drop what the source already considers delivered.
type Delivering interface {
	// Flush exports everything buffered now (and waits for an export already in flight).
	Flush(ctx context.Context) error
	// Buffered is the estimated number of bytes waiting to be exported.
	Buffered() int
}

// Backoff is the wait before retry number attempt (0 is the first): 1 s doubling to 5 min, with
// a random 20% either way. r is a uniform value in [0,1) (pass rand.Float64()).
func Backoff(attempt int, r float64) time.Duration {
	d := min(time.Second<<min(max(attempt, 0), 9), 5*time.Minute)
	return time.Duration(float64(d) * (0.8 + 0.4*r))
}
