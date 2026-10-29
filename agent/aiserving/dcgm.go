package aiserving

// MIG slices carry GPU_I_ID and GPU_I_PROFILE labels, which attrs() maps to gpu.mig.instance and
// gpu.mig.profile, so every metric below is per MIG instance when the exporter reports MIG.
var dcgm = []mapping{
	{Prom: "DCGM_FI_DEV_GPU_UTIL", Name: "gpu.utilization", Unit: "1", Kind: gauge, Scale: 0.01},
	{Prom: "DCGM_FI_DEV_FB_USED", Name: "gpu.memory.used", Unit: "By", Kind: gauge, Scale: 1024 * 1024}, // MiB
	{Prom: "DCGM_FI_DEV_GPU_TEMP", Name: "gpu.temperature", Unit: "Cel", Kind: gauge},
	{Prom: "DCGM_FI_DEV_POWER_USAGE", Name: "gpu.power", Unit: "W", Kind: gauge},
	// the last XID code the driver raised (0 when none); alert on a non-zero value
	{Prom: "DCGM_FI_DEV_XID_ERRORS", Name: "gpu.xid.last", Unit: "{code}", Kind: gauge},
	{Prom: "DCGM_FI_PROF_NVLINK_TX_BYTES", Name: "gpu.nvlink.tx", Unit: "By", Kind: gauge},
	{Prom: "DCGM_FI_PROF_NVLINK_RX_BYTES", Name: "gpu.nvlink.rx", Unit: "By", Kind: gauge},
	{Prom: "DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL", Name: "gpu.nvlink.bandwidth.total", Unit: "By", Kind: gauge},
	{Prom: "DCGM_FI_PROF_PIPE_TENSOR_ACTIVE", Name: "gpu.tensor.active", Unit: "1", Kind: gauge},
	{Prom: "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", Name: "gpu.ecc.double_bit", Unit: "{error}", Kind: gauge},
}
