// Hands user registers of on-CPU threads of watched processes (Node, JVM) to user space, which
// walks their runtime's frames (nodeframes.go, jvmframes.go). No stack data is copied here.
#include <linux/bpf.h>
#include <linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef unsigned long long u64;

char LICENSE[] SEC("license") = "GPL";

// Set by the loader when bpf_task_pt_regs exists (5.15+); a dead branch otherwise.
const volatile u32 have_task_regs = 0;

struct ev {
	u32 pid, tid;
	u64 pc, sp, fp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, unsigned char);
	__uint(max_entries, 64);
} rt_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} rt_events SEC(".maps");

#if defined(__TARGET_ARCH_arm64)
typedef struct user_pt_regs uregs;
#define REGS_USER(r) (((r)->pstate & 0xf) == 0)
#define REGS_LOAD(e, r) ((e).pc = (r)->pc, (e).sp = (r)->sp, (e).fp = (r)->regs[29])
#else
typedef struct pt_regs uregs;
#define REGS_USER(r) (((r)->cs & 3) == 3)
#define REGS_LOAD(e, r) ((e).pc = (r)->ip, (e).sp = (r)->sp, (e).fp = (r)->bp)
#endif

SEC("perf_event")
int on_cpu(struct bpf_perf_event_data *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	if (!bpf_map_lookup_elem(&rt_pids, &pid))
		return 0;
	struct ev e = { .pid = pid, .tid = (u32)id };
	if (REGS_USER(&ctx->regs)) {
		REGS_LOAD(e, &ctx->regs);
	} else {
		uregs u;
		if (!have_task_regs)
			return 0;
		void *r = (void *)bpf_task_pt_regs(bpf_get_current_task_btf());
		if (!r || bpf_probe_read_kernel(&u, sizeof(u), r) || !REGS_USER(&u))
			return 0;
		REGS_LOAD(e, &u);
	}
	bpf_ringbuf_output(&rt_events, &e, sizeof(e), 0); // dropped when the ring is full
	return 0;
}
