#include "common.h"

// Set by the loader (floor in nanoseconds, default 1 ms).
const volatile u64 min_ns = 1000000;

struct wt_start {
	u64 ts;
	u32 tgid;
	s32 user;
	s32 kern;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); // tid
	__type(value, struct wt_start);
	__uint(max_entries, 65536);
} starts SEC(".maps");

// Layout of the sched:sched_switch tracepoint (see its format file).
struct wt_switch_args {
	u64 common;
	char prev_comm[16];
	s32 prev_pid;
	s32 prev_prio;
	long long prev_state;
	char next_comm[16];
	s32 next_pid;
	s32 next_prio;
};

SEC("tracepoint/sched/sched_switch")
int on_switch(struct wt_switch_args *ctx)
{
	u64 now = bpf_ktime_get_ns();
	// A task leaving the CPU in a non-runnable state starts blocking; preemption (state 0) is not off-CPU time.
	if (ctx->prev_state != 0 && ctx->prev_pid != 0) {
		u32 tid = ctx->prev_pid;
		struct wt_start s = {
			.ts = now,
			.tgid = bpf_get_current_pid_tgid() >> 32,
			.user = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP),
			.kern = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP),
		};
		bpf_map_update_elem(&starts, &tid, &s, BPF_ANY);
	}
	u32 next = ctx->next_pid;
	struct wt_start *s = bpf_map_lookup_elem(&starts, &next);
	if (!s)
		return 0;
	u64 delta = now - s->ts;
	if (delta >= min_ns && s->tgid != 0) {
		struct wt_key k = { .pid = s->tgid, .user = s->user, .kern = s->kern };
		add_count(&k, delta);
	}
	bpf_map_delete_elem(&starts, &next);
	return 0;
}
