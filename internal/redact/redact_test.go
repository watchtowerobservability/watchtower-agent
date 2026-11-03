package redact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type fixture struct {
	Patterns []Pattern `json:"patterns"`
	Cases    []struct {
		Name   string `json:"name"`
		Level  Level  `json:"level"`
		Input  string `json:"input"`
		Output string `json:"output"`
	} `json:"cases"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	b, err := readFixture("redaction/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPatternsMatchSharedCases(t *testing.T) {
	f := loadFixture(t)
	if !reflect.DeepEqual(f.Patterns, Defaults) {
		t.Fatal("testdata/redaction/cases.json patterns differ from redact.Defaults")
	}
	for _, c := range f.Cases {
		if got := New(c.Level, nil, nil).Text(c.Input); got != c.Output {
			t.Errorf("%s: got %q want %q", c.Name, got, c.Output)
		}
	}
}

func TestLuhnVectorsMatchRust(t *testing.T) {
	b, err := readFixture("redact_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Luhn []struct {
			Digits string `json:"digits"`
			Valid  bool   `json:"valid"`
		} `json:"luhn"`
		CardTexts []struct{ Input, Output string } `json:"card_texts"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Luhn {
		if got := Luhn(c.Digits); got != c.Valid {
			t.Errorf("Luhn(%q) = %v want %v", c.Digits, got, c.Valid)
		}
	}
	r := New(Standard, nil, nil)
	for _, c := range v.CardTexts {
		if got := r.Text(c.Input); got != c.Output {
			t.Errorf("%q: got %q want %q", c.Input, got, c.Output)
		}
	}
}

func TestPIIActions(t *testing.T) {
	r := NewPII([]Detector{{Kind: "card", Action: ActionPartial}, {Kind: "email", Action: ActionHash}, {Kind: "ssn", Action: ActionReplace}}, []byte("s"))
	in := "c 4111 1111 1111 1111 e a@b.io s 123-45-6789 ip 10.0.0.1 jwt eyJa.eyJb.c"
	got := r.Text(in)
	for _, want := range []string{"****1111", "[HASH:email:", "[REDACTED:ssn]", "10.0.0.1", "eyJa.eyJb.c"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing from %q", want, got)
		}
	}
	if strings.Contains(got, "a@b.io") || got != r.Text(in) {
		t.Errorf("email kept or hash unstable: %q", got)
	}
}

func TestGlob(t *testing.T) {
	for pat, ok := range map[string]bool{"user.*": true, "*.id": true, "USER.id": true, "x*": false} {
		if Glob(pat, "user.id") != ok {
			t.Errorf("Glob(%q)", pat)
		}
	}
}

func TestBlockedFieldsDropped(t *testing.T) {
	r := New(Standard, nil, []string{"user.ssn", "*.credit_card"})
	in := `{"user":{"ssn":"x","name":"a"},"pay":{"credit_card":"4"},"ok":1}`
	got := string(r.JSON([]byte(in)))
	if strings.Contains(got, "ssn") || strings.Contains(got, "credit_card") {
		t.Fatalf("blocked field kept: %s", got)
	}
	if !strings.Contains(got, `"ok":1`) || !strings.Contains(got, `"name":"a"`) {
		t.Fatalf("unblocked data lost: %s", got)
	}
}

func TestJSONMasksValuesAndSensitiveKeys(t *testing.T) {
	r := New(Standard, []Pattern{{Kind: "order", Regex: `ORD-\d+`}}, nil)
	got := string(r.JSON([]byte(`{"a":["mail bob@example.com"],"password":"hunter2","n":"ORD-77"}`)))
	for _, bad := range []string{"bob@example.com", "hunter2", "ORD-77"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived: %s", bad, got)
		}
	}
}

func TestJSONNonJSONFallsBackToText(t *testing.T) {
	got := string(New(Standard, nil, nil).JSON([]byte("not json bob@example.com")))
	if strings.Contains(got, "bob@") {
		t.Fatal(got)
	}
}
