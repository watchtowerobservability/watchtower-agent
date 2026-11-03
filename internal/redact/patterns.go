package redact

// Level selects the pattern set: standard is the default, strict adds IP addresses.
type Level string

// Redaction levels (R10).
const (
	Standard Level = "standard"
	Strict   Level = "strict"
)

// Pattern is one named regex (RE2 syntax, also valid for the Rust regex crate: the shared
// fixture testdata/redaction/cases.json is asserted by both sides).
type Pattern struct {
	Kind   string `json:"kind"`
	Regex  string `json:"regex"`
	Strict bool   `json:"strict,omitempty"` // applied only at Strict level
}

// Defaults is the ordered built-in set. Order matters: specific secrets before generic shapes.
var Defaults = []Pattern{
	{Kind: "pem", Regex: `-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`},
	{Kind: "jwt", Regex: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`},
	{Kind: "bearer", Regex: `(?i:bearer\s+[A-Za-z0-9._~+/-]+=*)`},
	{Kind: "anthropic_key", Regex: `sk-ant-[A-Za-z0-9_-]{8,}`},
	{Kind: "api_key", Regex: `sk-[A-Za-z0-9_-]{20,}`},
	{Kind: "aws_key", Regex: `(?:AKIA|ASIA)[0-9A-Z]{16}`},
	{Kind: "gcp_key", Regex: `AIza[0-9A-Za-z_-]{35}`},
	{Kind: "github_token", Regex: `gh[pousr]_[A-Za-z0-9]{36,}`},
	{Kind: "slack_token", Regex: `xox[bap]-[A-Za-z0-9-]{10,}`},
	{Kind: "stripe_key", Regex: `[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`},
	{Kind: "watchtower_key", Regex: `wt[ikm]_[a-z0-9]{8}_[A-Za-z0-9_-]{43}`},
	{Kind: "email", Regex: `[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`},
	{Kind: "iban", Regex: `\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b`},
	{Kind: "card", Regex: `\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b`},
	{Kind: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`},
	{Kind: "phone", Regex: `\+\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}\b`},
	{Kind: "ipv4", Regex: `\b(?:\d{1,3}\.){3}\d{1,3}\b`, Strict: true},
	{Kind: "ipv6", Regex: `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b`, Strict: true},
}

// sensitiveKeys: JSON object keys whose string values are always masked.
const sensitiveKeys = `(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|password|passwd|secret|token|access[-_]token|refresh[-_]token|client[-_]secret)$`
