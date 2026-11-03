package integrations

// SAP NetWeaver / S/4HANA instance health via the SAPControl web service of sapstartsrv
// (CON-010): process list and ABAP work processes. url is the instance's sapstartsrv endpoint,
// http://host:5<NN>13 or https://host:5<NN>14; username/password are an OS user with
// SAPControl read rights (put them in the agent's own config, never in the project).

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// SAPControl polls GetProcessList and ABAPGetWPTable (the latter only exists on ABAP instances).
func SAPControl(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &SAPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if !c.hasCredentials() {
		slog.Info("sap: no username and password configured, staying inert")
		<-ctx.Done()
		return nil
	}
	out = serviceSink{out, c.Service}
	return Loop(ctx, "sap", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		b, err := sapCall(ctx, c.HTTPConfig, "GetProcessList")
		if err != nil {
			return err
		}
		if err := EmitSAPProcesses(out, b, now); err != nil {
			return err
		}
		if b, err := sapCall(ctx, c.HTTPConfig, "ABAPGetWPTable"); err == nil { // Java-only instances have none
			_ = EmitSAPWorkProcesses(out, b, now)
			_ = EmitSAPLongRunning(out, b, c.LongRunningS, now)
		}
		if b, err := sapCall(ctx, c.HTTPConfig, "GetQueueStatistic"); err == nil {
			_ = EmitSAPQueues(out, b, now)
		}
		return nil
	})
}

func sapCall(ctx context.Context, c HTTPConfig, op string) ([]byte, error) {
	env := `<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="urn:SAPControl"><SOAP-ENV:Body><ns:` +
		op + `/></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/", bytes.NewReader([]byte(env)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `""`)
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sap %s: HTTP %d", op, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// sapItems returns the leaf fields of every <item> in a SOAP response, ignoring namespaces.
func sapItems(body []byte) ([]map[string]string, error) {
	d := xml.NewDecoder(bytes.NewReader(body))
	var items []map[string]string
	var cur map[string]string
	var field string
	sawEnvelope := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sap: not a SOAP response: %w", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			switch {
			case e.Name.Local == "Envelope":
				sawEnvelope = true
			case e.Name.Local == "Fault":
				return nil, errors.New("sap: SOAP fault (check the user's SAPControl permissions)")
			case e.Name.Local == "item":
				cur = map[string]string{}
			case cur != nil:
				field = e.Name.Local
			}
		case xml.CharData:
			if cur != nil && field != "" {
				cur[field] += strings.TrimSpace(string(e))
			}
		case xml.EndElement:
			if e.Name.Local == "item" && cur != nil {
				items = append(items, cur)
				cur = nil
			}
			field = ""
		}
	}
	if !sawEnvelope {
		return nil, errors.New("sap: not a SOAP response")
	}
	return items, nil
}

// sapColor maps the SAPControl dispstatus to a health value: green 1, yellow 0.5, red/gray 0.
func sapColor(s string) float64 {
	switch strings.TrimPrefix(strings.ToUpper(s), "SAPCONTROL-") {
	case "GREEN":
		return 1
	case "YELLOW":
		return 0.5
	}
	return 0
}

// EmitSAPProcesses parses a GetProcessList response: one sap.process.status per process.
func EmitSAPProcesses(out sink.Sink, body []byte, now time.Time) error {
	items, err := sapItems(body)
	if err != nil {
		return err
	}
	for _, it := range items {
		out.Gauge("sap.process.status", "1", sapColor(it["dispstatus"]),
			map[string]string{"process": it["name"], "description": it["description"], "pid": it["pid"]}, now)
	}
	out.Gauge("sap.process.count", "{processes}", float64(len(items)), nil, now)
	return nil
}

// EmitSAPWorkProcesses parses an ABAPGetWPTable response: work processes counted by type and
// status (e.g. DIA/Run), plus the busy share per type.
func EmitSAPWorkProcesses(out sink.Sink, body []byte, now time.Time) error {
	items, err := sapItems(body)
	if err != nil {
		return err
	}
	type key struct{ typ, status string }
	counts := map[key]float64{}
	total, busy := map[string]float64{}, map[string]float64{}
	for _, it := range items {
		k := key{it["Typ"], it["Status"]}
		counts[k]++
		total[k.typ]++
		if k.status == "Run" || k.status == "Hold" {
			busy[k.typ]++
		}
	}
	for k, n := range counts {
		out.Gauge("sap.workprocess.count", "{processes}", n, map[string]string{"type": k.typ, "status": k.status}, now)
	}
	for typ, n := range total {
		out.Gauge("sap.workprocess.utilization", "1", busy[typ]/n, map[string]string{"type": typ}, now)
	}
	return nil
}
