// Workload Protection probes for runtime_security (Datadog-parity D1). Three raw-syscall
// tracepoints — execve, openat, connect — emit one struct rt_event per matched syscall into the
// `events` ring buffer. The Go side (runtimesec/loader_linux.go + event.go) decodes, resolves the
// container service name from the pid's cgroup, matches the policy, and emits a security signal.
// Build with `make ebpf-gen` -> objects/runtimesec_bpfel.o (see objects/README.md). These programs
// use only stable tracepoint layouts and helpers, so no CO-RE / BTF relocation is required.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;

#define AF_INET 2
#define AF_INET6 10
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_TRUNC 00001000

#define KIND_EXEC 0
#define KIND_FILE 1
#define KIND_NETWORK 2
#define OP_READ 0
#define OP_WRITE 1

// Mirrored by runtimesec/event.go (DecodeEvent, EventSize=312). 8-byte aligned, no implicit padding.
struct rt_event {
	u64 ts;       // 0
	u64 cgroup;   // 8
	u32 pid;      // 16
	u32 uid;      // 20
	u32 kind;     // 24
	u32 op;       // 28
	u32 dport;    // 32  host order
	u32 pad;      // 36
	char comm[16]; // 40
	char path[256]; // 56
};                 // 312

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // resized by the loader from ring_buffer_kb
} events SEC(".maps");

// Raw syscall tracepoint arg layouts. The 8-byte `common` covers the trace_entry header; each
// syscall argument is stored as an 8-byte slot.
struct enter_execve_args {
	u64 common;
	s32 __syscall_nr;
	u32 _pad;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct enter_openat_args {
	u64 common;
	s32 __syscall_nr;
	u32 _pad;
	u64 dfd;
	const char *filename;
	u64 flags;
	u64 mode;
};

struct enter_connect_args {
	u64 common;
	s32 __syscall_nr;
	u32 _pad;
	u64 fd;
	const void *uservaddr;
	u64 addrlen;
};

static __always_inline struct rt_event *new_event(u32 kind)
{
	struct rt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct enter_execve_args *ctx)
{
	struct rt_event *e = new_event(KIND_EXEC);
	if (!e)
		return 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), ctx->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct enter_openat_args *ctx)
{
	struct rt_event *e = new_event(KIND_FILE);
	if (!e)
		return 0;
	u64 f = ctx->flags;
	e->op = (f & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) ? OP_WRITE : OP_READ;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), ctx->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct enter_connect_args *ctx)
{
	u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	// sockaddr_in / sockaddr_in6 both carry the port as a big-endian u16 right after the family.
	u16 be_port = 0;
	bpf_probe_read_user(&be_port, sizeof(be_port), (const char *)ctx->uservaddr + 2);
	struct rt_event *e = new_event(KIND_NETWORK);
	if (!e)
		return 0;
	e->op = OP_WRITE; // egress (a connect is always outbound)
	e->dport = __builtin_bswap16(be_port); // network order -> host order
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
