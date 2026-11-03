package trace

import "testing"

func reqSpan(t *testing.T, raw string) *pending {
	t.Helper()
	m, ok := ParseHTTP1([]byte(raw))
	if !ok {
		t.Fatal("not http")
	}
	p := &pending{Span: Span{Client: true, Attrs: map[string]any{}}}
	applyHTTP(p, m)
	classifyRequest(p, m, bodyOf([]byte(raw)))
	return p
}

func TestClassifiers(t *testing.T) {
	p := reqSpan(t, "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"secret\"}]}")
	if p.Attrs["gen_ai.provider.name"] != "openai" || p.Attrs["gen_ai.request.model"] != "gpt-4o" || p.Name != "chat gpt-4o" {
		t.Fatalf("openai %v %s", p.Attrs, p.Name)
	}
	classifyResponse(p, []byte("HTTP/1.1 200 OK\r\n\r\n{\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":3}}"))
	if p.Attrs["gen_ai.usage.input_tokens"] != int64(12) || p.Attrs["gen_ai.usage.output_tokens"] != int64(3) {
		t.Fatalf("tokens %v", p.Attrs)
	}
	for k, v := range p.Attrs {
		if s, ok := v.(string); ok && s == "secret" {
			t.Fatalf("prompt text kept in %s", k)
		}
	}
	p = reqSpan(t, "POST /mcp HTTP/1.1\r\nHost: tools.local\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_weather\"}}")
	if p.Attrs["mcp.method.name"] != "tools/call" || p.Attrs["gen_ai.tool.name"] != "get_weather" {
		t.Fatalf("mcp %v", p.Attrs)
	}
	p = reqSpan(t, "POST /graphql HTTP/1.1\r\nHost: api\r\n\r\n{\"query\":\"mutation AddUser { add }\",\"operationName\":\"AddUser\"}")
	if p.Attrs["graphql.operation.type"] != "mutation" || p.Attrs["graphql.operation.name"] != "AddUser" {
		t.Fatalf("graphql %v", p.Attrs)
	}
	p = reqSpan(t, "POST / HTTP/1.1\r\nHost: dynamodb.us-east-1.amazonaws.com\r\nX-Amz-Target: DynamoDB_20120810.PutItem\r\n\r\n{}")
	if p.Attrs["rpc.service"] != "dynamodb" || p.Attrs["rpc.method"] != "PutItem" {
		t.Fatalf("aws %v", p.Attrs)
	}
	p = reqSpan(t, "GET /logs-2026/_search HTTP/1.1\r\nHost: es:9200\r\n\r\n")
	if p.Attrs["db.system.name"] != "elasticsearch" || p.Attrs["db.collection.name"] != "logs-2026" {
		t.Fatalf("es %v", p.Attrs)
	}
	p = reqSpan(t, "PUT /my-bucket/a.txt HTTP/1.1\r\nHost: s3.eu-west-1.amazonaws.com\r\n\r\n")
	if p.Attrs["aws.s3.bucket"] != "my-bucket" || p.Attrs["rpc.method"] != "PutObject" {
		t.Fatalf("s3 %v", p.Attrs)
	}
}
