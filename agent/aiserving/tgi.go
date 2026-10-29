package aiserving

var tgi = []mapping{
	{Prom: "tgi_request_duration", Name: "gen_ai.server.request.duration", Unit: "s", Kind: histMean},
	{Prom: "tgi_request_mean_time_per_token_duration", Name: "gen_ai.server.time_per_output_token", Unit: "s", Kind: histMean},
	{Prom: "tgi_queue_size", Name: "llm.queue.depth", Unit: "{request}", Kind: gauge},
}
