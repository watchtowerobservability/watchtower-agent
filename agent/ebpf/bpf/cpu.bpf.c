#include "common.h"

// Attached once per CPU to a software CPU_CLOCK perf event (default 19 Hz).
SEC("perf_event")
int on_cpu(void *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0) // idle
		return 0;
	struct key k = {
		.pid = pid,
		.user = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP),
		.kern = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP),
	};
	add_count(&k, 1);
	return 0;
}
