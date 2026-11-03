// Lock contention (PRF-010, opt-in `lock_contention`): nanoseconds a thread waits in
// pthread_mutex_lock / pthread_rwlock_{rd,wr}lock (uprobe + uretprobe on the libc the loader
// names) and, with `lock_futex`, in untimed futex waits and PI lock syscalls outside those calls.
// Waits shorter than min_ns are dropped in the kernel; the rest add to counts by caller stack.
#include "common.h"

const volatile u64 min_ns = 10000;

struct start {
	u64 ts;
	s32 user;
	s32 kern;
};

// Thread inside a hooked libc lock call; its futex wait is part of that call, not counted twice.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct start);
	__uint(max_entries, 65536);
} locks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct start);
	__uint(max_entries, 65536);
} futexes SEC(".maps");

static __always_inline void begin(void *ctx, void *map)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct start s = {
		.ts = bpf_ktime_get_ns(),
		.user = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP),
		.kern = -1,
	};
	bpf_map_update_elem(map, &tid, &s, BPF_ANY);
}

static __always_inline void end(void *map)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;
	struct start *s = bpf_map_lookup_elem(map, &tid);
	if (!s)
		return;
	u64 delta = bpf_ktime_get_ns() - s->ts;
	if (delta >= min_ns && (id >> 32) != 0) {
		struct key k = { .pid = id >> 32, .user = s->user, .kern = s->kern };
		add_count(&k, delta);
	}
	bpf_map_delete_elem(map, &tid);
}

SEC("uprobe/lock_enter")
int lock_enter(void *ctx)
{
	begin(ctx, &locks);
	return 0;
}

SEC("uretprobe/lock_exit")
int lock_exit(void *ctx)
{
	end(&locks);
	return 0;
}

// Layout of syscalls:sys_enter_futex (every argument is 8 bytes after the syscall number).
struct futex_enter {
	u64 common;
	s32 nr;
	u32 pad;
	u64 uaddr;
	u64 op;
	u64 val;
	u64 utime;
};

#define FUTEX_WAIT 0
#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_BITSET 9
#define FUTEX_LOCK_PI2 13
#define FUTEX_CMD_MASK 0x7f

SEC("tracepoint/syscalls/sys_enter_futex")
int futex_enter(struct futex_enter *ctx)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&locks, &tid))
		return 0;
	u32 cmd = ctx->op & FUTEX_CMD_MASK;
	// A wait with a timeout is a timed sleep or condition wait, not a lock.
	int lock = cmd == FUTEX_LOCK_PI || cmd == FUTEX_LOCK_PI2 ||
		   ((cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) && ctx->utime == 0);
	if (lock)
		begin(ctx, &futexes);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int futex_exit(void *ctx)
{
	end(&futexes);
	return 0;
}
