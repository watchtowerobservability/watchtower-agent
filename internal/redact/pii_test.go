package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPIIKindsMatchRust pins PIIPatterns and the checksum rules against the shared fixture that
// crates/wt-pipeline/tests/redact.rs also asserts.
func TestPIIKindsMatchRust(t *testing.T) {
	b, err := readFixture("redaction/pii_kinds.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Kinds   []Pattern `json:"kinds"`
		Vectors []struct {
			Kind string `json:"kind"`
			Text string `json:"text"`
			Hit  bool   `json:"hit"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Kinds) != len(PIIPatterns) {
		t.Fatalf("fixture has %d kinds, PIIPatterns %d", len(f.Kinds), len(PIIPatterns))
	}
	for i, k := range f.Kinds {
		if k != PIIPatterns[i] {
			t.Fatalf("kind %d: fixture %+v, PIIPatterns %+v", i, k, PIIPatterns[i])
		}
	}
	for _, v := range f.Vectors {
		got := NewPII([]Detector{{Kind: v.Kind, Action: ActionReplace}}, nil).Text(v.Text)
		if hit := got != v.Text; hit != v.Hit {
			t.Errorf("%s %q: hit=%v want %v (%q)", v.Kind, v.Text, hit, v.Hit, got)
		}
	}
}

func TestSecretDetectors(t *testing.T) {
	// built by concatenation so the repository holds no token-shaped literal
	cases := map[string]string{
		"aws_key":           "AKIA" + strings.Repeat("Q", 16),
		"aws_secret":        "aws_secret_access_key = " + strings.Repeat("a1B/", 10),
		"github_token":      "ghp_" + strings.Repeat("x", 36),
		"gitlab_token":      "glpat-" + strings.Repeat("y", 20),
		"slack_token":       "xoxb-" + strings.Repeat("1", 12),
		"stripe_key":        "sk_" + "live_" + strings.Repeat("z", 24),
		"sendgrid_key":      "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
		"npm_token":         "npm_" + strings.Repeat("c", 36),
		"twilio_key":        "SK" + strings.Repeat("0f", 16),
		"private_key":       "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"azure_storage_key": "AccountKey=" + strings.Repeat("k", 86) + "==",
	}
	for k, secret := range cases {
		got := NewPII([]Detector{{Kind: k, Action: ActionReplace}}, nil).Text("v=" + secret + " end")
		if strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:"+k+"]") {
			t.Errorf("%s not masked: %q", k, got)
		}
	}
}

func TestKeywordProximity(t *testing.T) {
	r := NewPII([]Detector{{Kind: "ssn", Action: ActionReplace, Keywords: []string{"SSN", "social security"}}}, nil)
	if got := r.Text("Social Security: 123-45-6789"); got != "Social Security: [REDACTED:ssn]" {
		t.Fatalf("keyword before the match must mask: %q", got)
	}
	if got := r.Text("part 123-45-6789"); got != "part 123-45-6789" {
		t.Fatalf("no keyword: kept, got %q", got)
	}
	far := "ssn" + strings.Repeat(" ", keywordWindow) + "123-45-6789"
	if r.Text(far) != far {
		t.Fatal("a keyword outside the window must not count")
	}
	if (Detector{Kind: "ssn", Action: ActionReplace, Keywords: []string{""}}).Valid() ||
		(Detector{Kind: "ssn", Action: ActionReplace, SamplePercent: 101}).Valid() {
		t.Fatal("bad keyword or sample accepted")
	}
	if !(Detector{Kind: "ssn", SamplePercent: 10}).Scoped() || (Detector{Kind: "ssn", SamplePercent: 100}).Scoped() {
		t.Fatal("Scoped")
	}
}
