package trace

import (
	"strings"
	"testing"
)

func TestPayloadRulesCaptureMaskedServerBodies(t *testing.T) {
	if NewPayload([]PayloadRule{{Service: "svc"}}) != nil {
		t.Fatal("a rule without body_bytes must not enable capture")
	}
	p := NewPayload([]PayloadRule{{Service: "svc", Route: "/api/*", BodyBytes: 30}})
	serve := func(dir Dir, path string) Span {
		a := NewAssembler()
		a.Bodies = true
		other := Send
		if dir == Send {
			other = Recv
		}
		a.Handle(ev(dir, "POST "+path+" HTTP/1.1\r\nHost: s\r\nContent-Type: application/json\r\n\r\n"+
			`{"password":"hunter2","email":"a@b.io","note":"ok"}`))
		sp, ok := a.Handle(ev(other, "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\npng"))
		if !ok {
			t.Fatal("no span")
		}
		return sp
	}
	sp := serve(Recv, "/api/login")
	p.apply(&sp, "svc")
	got, _ := sp.Attrs["http.request.body"].(string)
	if got == "" || len(got) > 30 || strings.Contains(got, "hunter2") || strings.Contains(got, "a@b.io") {
		t.Fatalf("request body %q", got)
	}
	if _, ok := sp.Attrs["http.response.body"]; ok {
		t.Fatal("binary response captured")
	}
	for _, c := range []struct {
		dir       Dir
		path, svc string
	}{{Send, "/api/login", "svc"}, {Recv, "/health", "svc"}, {Recv, "/api/login", "other"}} {
		sp := serve(c.dir, c.path)
		p.apply(&sp, c.svc)
		if _, ok := sp.Attrs["http.request.body"]; ok {
			t.Fatalf("captured for %+v", c)
		}
	}
}
