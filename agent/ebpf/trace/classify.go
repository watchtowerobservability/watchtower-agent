package trace

// Payload-derived protocols (CFT-E06) and GenAI/MCP spans (CFT-E07), from the captured 512 B
// head only: GraphQL, JSON-RPC and MCP, Elasticsearch, AWS APIs (S3, SQS, SNS, DynamoDB, ...),
// and LLM APIs (OpenAI and compatible, Anthropic, Gemini, Bedrock, Ollama). Only operation
// names, models and token counts are kept, never prompt or payload text. Token counts come from
// the response head, so they appear only when the usage fields fall inside it (Anthropic's
// streaming message_start, small non-streaming answers).

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

var (
	reModel   = regexp.MustCompile(`"model"\s*:\s*"([^"]{1,128})"`)
	reOpName  = regexp.MustCompile(`"operationName"\s*:\s*"([A-Za-z_][A-Za-z0-9_]{0,127})"`)
	reGQL     = regexp.MustCompile(`"query"\s*:\s*"\s*(query|mutation|subscription)?\s*([A-Za-z_][A-Za-z0-9_]*)?`)
	reRPC     = regexp.MustCompile(`"method"\s*:\s*"([^"]{1,128})"`)
	reTool    = regexp.MustCompile(`"params"\s*:\s*\{\s*"name"\s*:\s*"([^"]{1,128})"`)
	reAction  = regexp.MustCompile(`(?:^|&)Action=([A-Za-z0-9]{1,64})`)
	reInTok   = regexp.MustCompile(`"(?:prompt_tokens|input_tokens|promptTokenCount)"\s*:\s*(\d{1,9})`)
	reOutTok  = regexp.MustCompile(`"(?:completion_tokens|output_tokens|candidatesTokenCount)"\s*:\s*(\d{1,9})`)
	genAIHost = map[string]string{"api.openai.com": "openai", "api.anthropic.com": "anthropic",
		"generativelanguage.googleapis.com": "gcp.gemini", "api.mistral.ai": "mistral_ai", "api.groq.com": "groq",
		"api.deepseek.com": "deepseek", "api.cohere.com": "cohere", "openrouter.ai": "openrouter"}
	genAIPath = map[string]string{"/v1/chat/completions": "chat", "/chat/completions": "chat", "/v1/completions": "text_completion",
		"/v1/messages": "chat", "/v1/embeddings": "embeddings", "/v1/responses": "chat", "/api/chat": "chat",
		"/api/generate": "text_completion", "/api/embed": "embeddings"}
	esOps = []string{"_search", "_msearch", "_bulk", "_doc", "_count", "_update", "_delete_by_query", "_update_by_query", "_mget"}
)

func bodyOf(b []byte) []byte {
	if _, body, ok := bytes.Cut(b, []byte("\r\n\r\n")); ok {
		return body
	}
	return nil
}

func host(authority string) string {
	h, _, _ := strings.Cut(authority, ":")
	return strings.ToLower(h)
}

// classifyRequest adds protocol attributes derived from the request path, host and body head.
func classifyRequest(p *pending, m HTTPMsg, body []byte) {
	h := host(m.Authority)
	switch {
	case genAI(p, m, h, body):
	case storeRequest(p, m, h, body):
	case bytes.Contains(body, []byte(`"jsonrpc"`)):
		jsonRPC(p, body)
	case strings.HasSuffix(m.Path, "/graphql") || strings.HasSuffix(m.Path, "/graphql/"):
		typ, name := "query", ""
		if g := reGQL.FindSubmatch(body); g != nil {
			if len(g[1]) > 0 {
				typ = string(g[1])
			}
			name = string(g[2])
		}
		if n := reOpName.FindSubmatch(body); n != nil {
			name = string(n[1])
		}
		p.Attrs["graphql.operation.type"] = typ
		p.Name = typ
		if name != "" {
			p.Attrs["graphql.operation.name"] = name
			p.Name = typ + " " + name
		}
	case strings.HasSuffix(h, ".amazonaws.com"):
		aws(p, m, h, body)
	default:
		elasticsearch(p, m)
	}
}

func genAI(p *pending, m HTTPMsg, h string, body []byte) bool {
	sys := genAIHost[h]
	op := genAIPath[m.Path]
	switch {
	case strings.HasPrefix(h, "bedrock-runtime.") && strings.HasSuffix(h, ".amazonaws.com"):
		sys, op = "aws.bedrock", "chat"
	case sys == "gcp.gemini":
		if strings.Contains(m.Path, ":embedContent") {
			op = "embeddings"
		} else {
			op = "chat"
		}
	case sys == "" && op != "" && strings.HasPrefix(m.Path, "/api/"):
		sys = "ollama"
	case sys == "" && op != "" && reModel.Match(body):
		sys = "openai" // an OpenAI-compatible server (vLLM, LiteLLM, gateways)
	}
	if sys == "" || op == "" {
		return false
	}
	p.Attrs["gen_ai.provider.name"] = sys
	p.Attrs["gen_ai.operation.name"] = op
	p.Name = op
	if mm := reModel.FindSubmatch(body); mm != nil {
		p.Attrs["gen_ai.request.model"] = string(mm[1])
		p.Name = op + " " + string(mm[1])
	}
	return true
}

func jsonRPC(p *pending, body []byte) {
	mm := reRPC.FindSubmatch(body)
	if mm == nil {
		return
	}
	method := string(mm[1])
	// MCP is JSON-RPC 2.0 with these method families.
	if strings.HasPrefix(method, "tools/") || strings.HasPrefix(method, "resources/") || strings.HasPrefix(method, "prompts/") || method == "initialize" {
		p.Attrs["mcp.method.name"] = method
		p.Name = method
		if t := reTool.FindSubmatch(body); t != nil && method == "tools/call" {
			p.Attrs["gen_ai.tool.name"] = string(t[1])
			p.Name = method + " " + string(t[1])
		}
		return
	}
	p.Attrs["rpc.system"] = "jsonrpc"
	p.Attrs["rpc.method"] = method
	p.Name = method
}

func aws(p *pending, m HTTPMsg, h string, body []byte) {
	labels := strings.Split(strings.TrimSuffix(h, ".amazonaws.com"), ".")
	svc := labels[0]
	for _, l := range labels { // bucket.s3.region / s3.region / sqs.region
		if l == "s3" || strings.HasPrefix(l, "s3-") {
			svc = "s3"
		}
	}
	p.Attrs["rpc.system"] = "aws-api"
	p.Attrs["rpc.service"] = svc
	op := ""
	if _, after, ok := strings.Cut(m.AmzTarget, "."); ok {
		op = after
	} else if a := reAction.FindSubmatch(body); a != nil {
		op = string(a[1])
	}
	if svc == "s3" {
		bucket := ""
		if labels[0] != "s3" && !strings.HasPrefix(labels[0], "s3-") {
			bucket = labels[0]
		} else if seg := strings.Split(strings.TrimPrefix(m.Path, "/"), "/"); seg[0] != "" {
			bucket = seg[0]
		}
		if bucket != "" {
			p.Attrs["aws.s3.bucket"] = bucket
		}
		op = map[string]string{"GET": "GetObject", "PUT": "PutObject", "DELETE": "DeleteObject", "HEAD": "HeadObject", "POST": "PostObject"}[m.Method]
	}
	if op != "" {
		p.Attrs["rpc.method"] = op
		p.Name = svc + "." + op
	}
}

func elasticsearch(p *pending, m HTTPMsg) {
	segs := strings.Split(strings.TrimPrefix(m.Path, "/"), "/")
	for i, s := range segs {
		for _, op := range esOps {
			if s == op {
				p.Attrs["db.system.name"] = "elasticsearch"
				p.Attrs["db.operation.name"] = op
				p.Name = op
				if i > 0 && !strings.HasPrefix(segs[0], "_") {
					p.Attrs["db.collection.name"] = segs[0]
					p.Name = op + " " + segs[0]
				}
				return
			}
		}
	}
}

// classifyResponse adds GenAI token usage and the response model when they are in the head.
func classifyResponse(p *pending, data []byte) {
	if _, ok := p.Attrs["gen_ai.operation.name"]; !ok {
		return
	}
	body := bodyOf(data)
	if body == nil {
		body = data // an SSE continuation
	}
	if m := reInTok.FindSubmatch(body); m != nil {
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		p.Attrs["gen_ai.usage.input_tokens"] = n
	}
	if m := reOutTok.FindSubmatch(body); m != nil {
		n, _ := strconv.ParseInt(string(m[1]), 10, 64)
		p.Attrs["gen_ai.usage.output_tokens"] = n
	}
	if m := reModel.FindSubmatch(body); m != nil {
		p.Attrs["gen_ai.response.model"] = string(m[1])
	}
}

var reN1QL = regexp.MustCompile(`"statement"\s*:\s*"((?:[^"\\\\]|\\\\.){1,512})`)

// storeRequest marks HTTP calls to Couchbase's query service (SQL++) and to vector databases.
func storeRequest(p *pending, m HTTPMsg, h string, body []byte) bool {
	sys := ""
	switch {
	case strings.HasSuffix(m.Path, "/query/service"):
		if g := reN1QL.FindSubmatch(body); g != nil {
			p.Attrs["db.query.text"] = string(g[1])
		}
		sys = "couchbase"
	case strings.HasSuffix(h, ".pinecone.io"):
		sys = "pinecone"
	case strings.Contains(m.Path, "/points/search") || strings.Contains(m.Path, "/points/query"):
		sys = "qdrant"
	case strings.Contains(m.Path, "/api/v1/collections") || strings.Contains(m.Path, "/api/v2/tenants/"):
		sys = "chroma"
	case strings.HasPrefix(m.Path, "/v1/objects") || strings.HasPrefix(m.Path, "/v1/batch/objects"):
		sys = "weaviate"
	case strings.HasPrefix(m.Path, "/v2/vectordb/") || strings.HasPrefix(m.Path, "/v1/vector/"):
		sys = "milvus"
	default:
		return false
	}
	p.Attrs["db.system.name"] = sys
	return true
}
