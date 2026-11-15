package redact

import "testing"

func TestScrubURL(t *testing.T) {
	for in, want := range map[string]string{
		"/api/feed/AbCdEfGhIjKlMnOpQrStUvWxYz012/csv?since=1":                     "/api/feed/:redacted/csv",
		"/api/status/ping/3f2504e0-4f89-11d3-9a0c-0305e82c3301/s3cr3tTok3n99ZzQq": "/api/status/ping/:redacted/:redacted",
		"https://u:pw@forumulate.com/api/x/abc123def4567890xyz#frag":              "https://forumulate.com/api/x/:redacted",
		"/users/profile/settings":                                                 "/users/profile/settings",
		"/orders/12345":                                                           "/orders/12345",
		"/v1/projects/:redacted/items":                                            "/v1/projects/:redacted/items",
		"https://example.com":                                                     "https://example.com",
		"/a?b=c":                                                                  "/a",
		"/o/12345678901":                                                          "/o/12345678901",
		"https://formize.net/atlas/.well-known/jwks.json":                         "https://formize.net/atlas/.well-known/jwks.json",
		"https://formize2.net/atlas/x":                                            "https://formize2.net/atlas/x",
		"https://localhost:30000/atlas/x":                                         "https://localhost:30000/atlas/x",
		"//cdn1234567.example.com/a":                                              "//cdn1234567.example.com/a",
		"https://api.cookiemunch.net/config/default":                              "https://api.cookiemunch.net/config/default",
		"https://api.cookiemunch.net/config/a1b2c3d4":                             "https://api.cookiemunch.net/config/a1b2c3d4",
		"https://api.cookiemunch.net/config/Xk29dLq0aPz7Xk29":                     "https://api.cookiemunch.net/config/:redacted",
		"/gallery/legal-consultation-intake":                                      "/gallery/legal-consultation-intake",
		"/reports/invoice-2024-q1-summary":                                        "/reports/invoice-2024-q1-summary",
		"/api/feed/Xk29dLq0aPz7Xk29dLq0aPz7/csv?since=1":                          "/api/feed/:redacted/csv",
		"/invite/3b241101-e2bb-4255-8caf-4136c566a962/accept":                     "/invite/:redacted/accept",
		"/s/0123456789abcdef":                                                     "/s/:redacted",
		"/t/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln":                            "/t/:redacted",
		"/c/1234567890123456":                                                     "/c/:redacted",
	} {
		if got := ScrubURL(in); got != want {
			t.Errorf("ScrubURL(%q) = %q, want %q", in, got, want)
		}
	}
}
