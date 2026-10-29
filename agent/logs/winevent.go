package logs

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// WinEvent configures the Windows Event Log subscription (Windows only; elsewhere it waits).
type WinEvent struct {
	Channels []string `json:"channels"` // default System and Application
	Query    string   `json:"query"`    // XPath filter, default "*"
}

type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       int    `xml:"Level"`
		TimeCreated struct {
			At string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	Data []struct {
		Name string `xml:"Name,attr"`
		Text string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

var winLevel = map[int]string{1: "ERROR", 2: "ERROR", 3: "WARN", 4: "INFO", 5: "DEBUG"}

// ParseEventXML converts a rendered event (EvtRenderEventXml) into a record. The body is the
// provider, the event id and the event data; the localized message text is not resolved.
func ParseEventXML(x string) (Record, error) {
	var e eventXML
	if err := xml.Unmarshal([]byte(x), &e); err != nil {
		return Record{}, fmt.Errorf("event xml: %w", err)
	}
	sev := winLevel[e.System.Level]
	if sev == "" {
		sev = "INFO" // level 0 is "LogAlways"
	}
	at := time.Now()
	if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.At); err == nil {
		at = t
	}
	var parts []string
	attrs := map[string]string{
		"log.source": "windows_events", "windows.event.provider": e.System.Provider.Name,
		"windows.event.id": strings.TrimSpace(e.System.EventID), "windows.event.channel": e.System.Channel,
		"syslog.hostname": e.System.Computer,
	}
	for _, d := range e.Data {
		t := strings.TrimSpace(d.Text)
		if t == "" {
			continue
		}
		if d.Name != "" {
			t = d.Name + "=" + t
		}
		parts = append(parts, t)
	}
	body := fmt.Sprintf("%s event %s", e.System.Provider.Name, attrs["windows.event.id"])
	if len(parts) > 0 {
		body += ": " + strings.Join(parts, "; ")
	}
	return Record{Severity: sev, Body: body, At: at, Attrs: attrs}, nil
}
