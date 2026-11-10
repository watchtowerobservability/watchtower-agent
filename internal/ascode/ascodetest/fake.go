// Package ascodetest is an in-memory Watchtower project API for the as-code tests: it follows the
// REST shapes of the kinds table (list pages, POST create, PUT/PATCH/DELETE by id or name).
package ascodetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
)

// Server is the fake; Calls records "METHOD path" lines.
type Server struct {
	*httptest.Server
	mu    sync.Mutex
	Calls []string
	// Secrets are the check-secret values the API received.
	Secrets []string
	store   map[string]map[string]map[string]any // kind -> ref -> body
	seq     int
}

// Project is the project id the fake serves.
const Project = "prj_test"

// Org is the org id the fake serves for the org-scoped kinds.
const Org = "org_test"

// New starts the fake and stops it with the test.
func New(t testing.TB) *Server {
	s := &Server{store: map[string]map[string]map[string]any{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// Count returns how many stored objects of kind exist.
func (s *Server) Count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.store[kind])
}

// Body returns a copy of one stored object by its name.
func (s *Server) Body(kind, name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ascode.ByKind(kind)
	for _, b := range s.store[kind] {
		if b[k.NameKey()] == name {
			return b
		}
	}
	return nil
}

// Writes counts the mutating calls so far.
func (s *Server) Writes() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.Calls {
		if !strings.HasPrefix(c, "GET ") {
			n++
		}
	}
	return n
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-key" {
		reply(w, http.StatusUnauthorized, nil)
		return
	}
	if r.URL.Path == "/v1/projects/"+Project { // the project, for its org id
		reply(w, 200, map[string]any{"id": Project, "org_id": Org})
		return
	}
	prefix := "/v1/projects/" + Project + "/"
	rel, ok := strings.CutPrefix(r.URL.Path, prefix)
	if o, isOrg := strings.CutPrefix(r.URL.Path, "/v1/orgs/"+Org+"/"); !ok && isOrg {
		rel, ok = "/v1/orgs/{org}/"+o, true
	}
	if !ok {
		reply(w, http.StatusNotFound, nil)
		return
	}
	s.Calls = append(s.Calls, r.Method+" "+rel)
	var k *ascode.Kind
	var ref string
	for _, c := range ascode.Kinds {
		if rel == c.Path {
			k = c
		} else if r, ok := strings.CutPrefix(rel, c.Path+"/"); ok && !strings.Contains(r, "/") {
			k, ref = c, r
		}
	}
	if k == nil {
		reply(w, http.StatusNotFound, nil)
		return
	}
	var body map[string]any
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodDelete {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if s.store[k.Name] == nil {
		s.store[k.Name] = map[string]map[string]any{}
	}
	s.serve(w, r, k, ref, body)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, k *ascode.Kind, ref string, body map[string]any) {
	st := s.store[k.Name]
	if k.Name == "NotificationRule" { // two sets, replaced whole
		if r.Method == http.MethodPut {
			st[ref] = body
			reply(w, 200, body)
			return
		}
		out := map[string]any{"audible": []any{}, "quiet": []any{}}
		for set, b := range st {
			out[set] = b["rules"]
		}
		reply(w, 200, out)
		return
	}
	switch {
	case k.Singleton && k.Org: // org documents are flat
		if r.Method == http.MethodPut {
			st["tree"] = body
		}
		reply(w, 200, st["tree"])
	case k.Singleton && r.Method == http.MethodGet:
		tree := st["tree"]
		if tree == nil {
			tree = map[string]any{"id": "root", "receiver": nil}
		}
		reply(w, 200, map[string]any{"version": 1, "tree": tree})
	case k.Singleton:
		if k.Name == "Routing" && r.Header.Get("If-Match") == "" { // the real API: 428 without the version
			reply(w, http.StatusPreconditionRequired, nil)
			return
		}
		st["tree"] = body
		reply(w, 200, map[string]any{"version": 2, "tree": body})
	case ref == "" && r.Method == http.MethodGet:
		data := []any{}
		for _, b := range st {
			data = append(data, b)
		}
		reply(w, 200, map[string]any{"data": data, "next_cursor": nil})
	case ref == "" && r.Method == http.MethodPost:
		s.seq++
		id := fmt.Sprintf("%s_%d", strings.ToLower(k.Name), s.seq)
		body["id"], body["created_at"], body["version"] = id, "2026-10-29T00:00:00Z", 1
		st[id] = body
		out := map[string]any{}
		for f, v := range body {
			out[f] = v
		}
		if k.Name == "ChangeSource" || k.Name == "CiSource" {
			out["secret"] = "cs_once_" + id // shown once, never stored
		}
		if k.Name == "SecretStore" {
			s.Secrets = append(s.Secrets, fmt.Sprint(body["credential"]))
			delete(body, "credential")
			delete(out, "credential")
			body["has_credential"], out["has_credential"] = true, true
		}
		if k.Name == "ApiKey" {
			out["token"] = "wta_once_" + id
		}
		if k.Name == "IngestKey" {
			out["token"] = "wti_once_" + id
			body["prefix"] = "wti_once"
		}
		if k.Name == "HealthToken" {
			out["token"] = "wth_once_" + id
			body["prefix"] = "wth_once"
		}
		reply(w, 201, out)
	case ref != "" && r.Method == http.MethodPut && k.ByName:
		old := st[ref]
		if k.NoList {
			// the rule group answers whether the PUT changed anything
			same := old != nil && reflect.DeepEqual(old, body)
			st[ref] = body
			reply(w, 200, map[string]any{"name": ref, "unchanged": same})
			return
		}
		if k.NameKey() != "name" || k.Name == "CheckSecret" {
			body[k.NameKey()] = ref
		}
		body["created_at"] = "2026-10-29T00:00:00Z"
		if k.Name == "CheckSecret" {
			s.Secrets = append(s.Secrets, fmt.Sprint(body["value"]))
			delete(body, "value") // the API never returns a secret
		}
		st[ref] = body
		reply(w, 200, body)
	case ref != "":
		cur, ok := st[ref]
		if !ok {
			reply(w, http.StatusNotFound, nil)
			return
		}
		switch r.Method {
		case http.MethodGet:
			reply(w, 200, cur)
		case http.MethodDelete:
			delete(st, ref)
			reply(w, 204, nil)
		default: // PUT replaces, PATCH merges
			if r.Method == http.MethodPut {
				cur = map[string]any{"id": ref, "created_at": cur["created_at"]}
			}
			for f, v := range body {
				cur[f] = v
			}
			cur["version"] = 2
			st[ref] = cur
			reply(w, 200, cur)
		}
	default:
		reply(w, http.StatusMethodNotAllowed, nil)
	}
}
