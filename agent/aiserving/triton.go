package aiserving

// Triton exposes cumulative microseconds and a request count, so the mean is their ratio.
var triton = []mapping{
	{Prom: "nv_inference_request_duration_us", Den: "nv_inference_count", Name: "gen_ai.server.request.duration", Unit: "s", Kind: ratioMean, Scale: 1e-6},
	{Prom: "nv_inference_pending_request_count", Name: "llm.queue.depth", Unit: "{request}", Kind: gauge},
	{Prom: "nv_gpu_utilization", Name: "gpu.utilization", Unit: "1", Kind: gauge},
	{Prom: "nv_gpu_memory_used_bytes", Name: "gpu.memory.used", Unit: "By", Kind: gauge},
	{Prom: "nv_gpu_power_usage", Name: "gpu.power", Unit: "W", Kind: gauge},
}
