package integrations

// SAP ABAP application health on top of SAPControl (APM-001): dispatcher queues (the requests
// waiting for a work process, per type) and long-running work processes (a dialog or batch step
// running past long_running_s, the stall signal of an ABAP transaction). Every SAP series carries
// `service` (config `service`, default "sap"), so it lines up with that service's APM views.
// Without username and password the module stays inert: it never dials the instance.

import (
	"errors"
	"strconv"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DefaultSAPLongRunningS is the run time after which a work process counts as long-running.
const DefaultSAPLongRunningS = 300

// SAPConfig is the `sap` module's config.
type SAPConfig struct {
	HTTPConfig
	Service      string `json:"service"`
	LongRunningS int    `json:"long_running_s"`
}

func (c *SAPConfig) check() error {
	if c.LongRunningS < 0 {
		return errors.New("long_running_s must not be negative")
	}
	if c.Service == "" {
		c.Service = "sap"
	}
	if c.LongRunningS == 0 {
		c.LongRunningS = DefaultSAPLongRunningS
	}
	if !c.hasCredentials() {
		return nil // inert, nothing to validate
	}
	return c.HTTPConfig.check()
}

func (c *SAPConfig) hasCredentials() bool { return c.Username != "" && c.Password != "" }

// serviceSink stamps `service` on every gauge.
type serviceSink struct {
	sink.Sink
	service string
}

func (s serviceSink) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	s.Sink.Gauge(name, unit, v, sink.With(a, "service", s.service), at)
}

// EmitSAPQueues parses a GetQueueStatistic response: current, peak and maximum length of each
// dispatcher queue (DIA, BTC, UPD, ...).
func EmitSAPQueues(out sink.Sink, body []byte, now time.Time) error {
	items, err := sapItems(body)
	if err != nil {
		return err
	}
	for _, it := range items {
		a := map[string]string{"type": it["Typ"]}
		for field, name := range map[string]string{"Now": "sap.queue.length", "High": "sap.queue.high", "Max": "sap.queue.max"} {
			if v, err := strconv.ParseFloat(it[field], 64); err == nil {
				out.Gauge(name, "{requests}", v, a, now)
			}
		}
	}
	return nil
}

// EmitSAPLongRunning counts, per type, the work processes of an ABAPGetWPTable response that have
// been running for at least minS seconds.
func EmitSAPLongRunning(out sink.Sink, body []byte, minS int, now time.Time) error {
	items, err := sapItems(body)
	if err != nil {
		return err
	}
	long := map[string]float64{}
	for _, it := range items {
		long[it["Typ"]] += 0 // every type reports, zero included, so the series resolves
		if s, err := strconv.Atoi(it["Time"]); err == nil && s >= minS && it["Status"] == "Run" {
			long[it["Typ"]]++
		}
	}
	for typ, n := range long {
		out.Gauge("sap.workprocess.long_running", "{processes}", n, map[string]string{"type": typ}, now)
	}
	return nil
}
