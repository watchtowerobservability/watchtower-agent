#define USE_VMLINUX 1 // BTF vmlinux.h, see common.h
// on_cpu with DWARF unwinding of user stacks. Without a table, or on a tail-call failure, the
// sample falls back to frame pointers (bpf_get_stackid). See dwarf.h.
#include "dwarf.h"

static __always_inline int finish(struct bpf_perf_event_data *ctx, struct wt_walk *w)
{
	struct wt_key k = { .pid = w->pid, .kern = w->kern, .user = -1, .dwarf = store_stack(w) };
	if (!k.dwarf)
		k.user = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
	add_count(&k, 1);
	return 0;
}

SEC("perf_event")
int unwind_step(struct bpf_perf_event_data *ctx)
{
	u32 zero = 0;
	struct wt_walk *w = bpf_map_lookup_elem(&walks, &zero);
	if (!w)
		return 0;
	if (walk_step(w))
		bpf_tail_call(ctx, &progs, 0);
	return finish(ctx, w);
}

SEC("perf_event")
int on_cpu(struct bpf_perf_event_data *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == 0)
		return 0;
	u32 zero = 0;
	struct wt_walk *w = bpf_map_lookup_elem(&walks, &zero);
	if (!w)
		return 0;
	w->pid = pid;
	w->kern = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP);
	w->n = 0;
	w->step = 0;
	if (bpf_map_lookup_elem(&procs, &pid)) {
		// A sample in the kernel has kernel registers in ctx: the task's user ones are saved apart.
		int ok = 1;
		if (REGS_USER((uregs *)&ctx->regs))
			REGS_LOAD(w, (uregs *)&ctx->regs);
		else
			ok = task_regs(w);
		if (ok)
			bpf_tail_call(ctx, &progs, 0);
	}
	return finish(ctx, w);
}
