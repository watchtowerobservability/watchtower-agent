package aiserving

var vllm = []mapping{
	{Prom: "vllm:time_to_first_token_seconds", Name: "gen_ai.server.time_to_first_token", Unit: "s", Kind: histMean},
	{Prom: "vllm:time_per_output_token_seconds", Name: "gen_ai.server.time_per_output_token", Unit: "s", Kind: histMean},
	{Prom: "vllm:inter_token_latency_seconds", Name: "gen_ai.server.time_per_output_token", Unit: "s", Kind: histMean},
	{Prom: "vllm:e2e_request_latency_seconds", Name: "gen_ai.server.request.duration", Unit: "s", Kind: histMean},
	{Prom: "vllm:num_requests_waiting", Name: "llm.queue.depth", Unit: "{request}", Kind: gauge},
}
