#define USE_VMLINUX 1 // BTF vmlinux.h, see common.h
// offcpu.bpf.c with DWARF unwinding of the stack a task blocks on. The tables are cpu_dwarf's maps
// (the loader passes them in). A tracepoint has no user registers, so this needs bpf_task_pt_regs
// (5.15+); the loader uses offcpu_bpfel.o otherwise. See dwarf.h.
#include "dwarf.h"

// Set by the loader (floor in nanoseconds, default 1 ms).
const volatile u64 min_ns = 1000000;

struct wt_start {
	u64 ts;
	u64 dwarf;
	u32 tgid;
	s32 user;
	s32 kern;
	s32 pad;
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

static __always_inline int finish(struct wt_switch_args *ctx, struct wt_walk *w)
{
	struct wt_start s = { .ts = w->ts, .dwarf = store_stack(w), .tgid = w->pid, .kern = w->kern, .user = -1 };
	if (!s.dwarf)
		s.user = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
	bpf_map_update_elem(&starts, &w->tid, &s, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int unwind_step(struct wt_switch_args *ctx)
{
	u32 zero = 0;
	struct wt_walk *w = bpf_map_lookup_elem(&walks, &zero);
	if (!w)
		return 0;
	if (walk_step(w))
		bpf_tail_call(ctx, &progs, 0);
	return finish(ctx, w);
}

SEC("tracepoint/sched/sched_switch")
int on_switch(struct wt_switch_args *ctx)
{
	u64 now = bpf_ktime_get_ns();
	u32 next = ctx->next_pid, zero = 0;
	struct wt_start *b = bpf_map_lookup_elem(&starts, &next);
	if (b) {
		u64 delta = now - b->ts;
		if (delta >= min_ns && b->tgid != 0) {
			struct wt_key k = { .pid = b->tgid, .user = b->user, .kern = b->kern, .dwarf = b->dwarf };
			add_count(&k, delta);
		}
		bpf_map_delete_elem(&starts, &next);
	}
	// A task leaving the CPU in a non-runnable state starts blocking; preemption (state 0) is not off-CPU time.
	if (ctx->prev_state == 0 || ctx->prev_pid == 0)
		return 0;
	struct wt_walk *w = bpf_map_lookup_elem(&walks, &zero);
	if (!w)
		return 0;
	w->pid = bpf_get_current_pid_tgid() >> 32;
	w->tid = ctx->prev_pid;
	w->ts = now;
	w->kern = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP);
	w->n = 0;
	w->step = 0;
	if (bpf_map_lookup_elem(&procs, &w->pid) && task_regs(w))
		bpf_tail_call(ctx, &progs, 0);
	return finish(ctx, w);
}
