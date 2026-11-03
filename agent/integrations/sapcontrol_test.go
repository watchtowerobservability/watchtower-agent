package integrations

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const sapProcessList = `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SAPControl="urn:SAPControl">
<SOAP-ENV:Body><SAPControl:GetProcessListResponse><process>
<item><name>disp+work</name><description>Dispatcher</description><dispstatus>SAPControl-GREEN</dispstatus><pid>4242</pid></item>
<item><name>igswd_mt</name><description>IGS Watchdog</description><dispstatus>SAPControl-YELLOW</dispstatus><pid>4243</pid></item>
<item><name>gwrd</name><description>Gateway</description><dispstatus>SAPControl-RED</dispstatus><pid>4244</pid></item>
</process></SAPControl:GetProcessListResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`

const sapWPTable = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>
<SAPControl:ABAPGetWPTableResponse xmlns:SAPControl="urn:SAPControl"><workprocess>
<item><No>0</No><Typ>DIA</Typ><Status>Run</Status></item>
<item><No>1</No><Typ>DIA</Typ><Status>Wait</Status></item>
<item><No>2</No><Typ>BTC</Typ><Status>Wait</Status></item>
</workprocess></SAPControl:ABAPGetWPTableResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`

func TestSAPProcessListAndWorkProcesses(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	if err := EmitSAPProcesses(&r, []byte(sapProcessList), now); err != nil {
		t.Fatal(err)
	}
	if err := EmitSAPWorkProcesses(&r, []byte(sapWPTable), now); err != nil {
		t.Fatal(err)
	}
	status := map[string]float64{}
	var diaRun, diaUtil float64
	for _, s := range r.Samples {
		switch s.Name {
		case "sap.process.status":
			status[s.Attrs["process"]] = s.Value
		case "sap.workprocess.count":
			if s.Attrs["type"] == "DIA" && s.Attrs["status"] == "Run" {
				diaRun = s.Value
			}
		case "sap.workprocess.utilization":
			if s.Attrs["type"] == "DIA" {
				diaUtil = s.Value
			}
		}
	}
	if status["disp+work"] != 1 || status["igswd_mt"] != 0.5 || status["gwrd"] != 0 {
		t.Fatalf("process status: %v", status)
	}
	if n, _ := value(&r, "sap.process.count"); n != 3 {
		t.Fatalf("process count %v", n)
	}
	if diaRun != 1 || diaUtil != 0.5 {
		t.Fatalf("DIA run %v util %v", diaRun, diaUtil)
	}
}

func TestSAPFaultAndGarbageRefused(t *testing.T) {
	var r sink.Recorder
	fault := `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultstring>Permission denied</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	if err := EmitSAPProcesses(&r, []byte(fault), time.Now()); err == nil || !strings.Contains(err.Error(), "fault") {
		t.Fatalf("fault: %v", err)
	}
	if err := EmitSAPProcesses(&r, []byte(`{"not":"soap"}`), time.Now()); err == nil {
		t.Fatal("non-SOAP body must be refused")
	}
}

func TestSAPCallPostsSOAPWithAuth(t *testing.T) {
	var gotOp, gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotUser, _, _ = r.BasicAuth()
		if r.Method != http.MethodPost || !strings.Contains(r.Header.Get("Content-Type"), "text/xml") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.Contains(string(b), "<ns:GetProcessList/>") {
			gotOp = "GetProcessList"
		}
		_, _ = w.Write([]byte(sapProcessList))
	}))
	defer srv.Close()
	c := HTTPConfig{URL: srv.URL, Username: "sapadm", Password: "x"}
	b, err := sapCall(context.Background(), c, "GetProcessList")
	if err != nil {
		t.Fatal(err)
	}
	if gotOp != "GetProcessList" || gotUser != "sapadm" || !strings.Contains(string(b), "disp+work") {
		t.Fatalf("op %q user %q", gotOp, gotUser)
	}
}

func TestSAPQueuesLongRunningAndService(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	queues := `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>
<SAPControl:GetQueueStatisticResponse xmlns:SAPControl="urn:SAPControl"><queue>
<item><Typ>ABAP/DIA</Typ><Now>7</Now><High>12</High><Max>14000</Max></item>
</queue></SAPControl:GetQueueStatisticResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	out := serviceSink{&r, "erp-prd"}
	if err := EmitSAPQueues(out, []byte(queues), now); err != nil {
		t.Fatal(err)
	}
	wp := strings.Replace(sapWPTable, "<Status>Run</Status>", "<Status>Run</Status><Time>900</Time>", 1)
	if err := EmitSAPLongRunning(out, []byte(wp), DefaultSAPLongRunningS, now); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, s := range r.Samples {
		if s.Attrs["service"] != "erp-prd" {
			t.Fatalf("%s without service: %v", s.Name, s.Attrs)
		}
		got[s.Name+"/"+s.Attrs["type"]] = s.Value
	}
	if got["sap.queue.length/ABAP/DIA"] != 7 || got["sap.queue.high/ABAP/DIA"] != 12 {
		t.Fatalf("queues: %v", got)
	}
	if got["sap.workprocess.long_running/DIA"] != 1 || got["sap.workprocess.long_running/BTC"] != 0 {
		t.Fatalf("long running: %v", got)
	}
}

func TestSAPInertWithoutCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var r sink.Recorder
	// No url either: an unconfigured module neither fails nor dials.
	if err := SAPControl(ctx, []byte(`{}`), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Samples) != 0 {
		t.Fatalf("inert module emitted %v", r.Samples)
	}
	c := &SAPConfig{}
	if err := load([]byte(`{"username":"sapadm","password":"x"}`), c); err == nil {
		t.Fatal("credentials without url must be refused")
	}
}
