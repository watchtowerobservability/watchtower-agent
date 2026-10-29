#include "trace.h"

// Plaintext capture on the syscall tracepoints: their argument layout is stable across kernels
// (no struct offsets, no CO-RE). The Go side drops fds that are not TCP sockets. Not covered:
// writev/sendmsg/recvmsg (Node, JVM NIO) and io_uring.
struct sys_enter {
	u64 common;
	s64 nr;
	u64 a[6];
};
struct sys_exit {
	u64 common;
	s64 nr;
	s64 ret;
};

struct rd_args {
	s32 fd;
	const void *buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct rd_args);
	__uint(max_entries, 16384);
} reading SEC(".maps");

static __always_inline void begin_read(struct sys_enter *c)
{
	u64 id = bpf_get_current_pid_tgid();
	struct rd_args a = {.fd = (s32)c->a[0], .buf = (const void *)c->a[1]};
	bpf_map_update_elem(&reading, &id, &a, BPF_ANY);
}

static __always_inline void end_read(struct sys_exit *c)
{
	u64 id = bpf_get_current_pid_tgid();
	struct rd_args *a = bpf_map_lookup_elem(&reading, &id);
	if (!a)
		return;
	if (c->ret > 0)
		emit(a->fd, a->buf, c->ret, 1, 0);
	bpf_map_delete_elem(&reading, &id);
}

SEC("tracepoint/syscalls/sys_enter_write")
int enter_write(struct sys_enter *c)
{
	emit((s32)c->a[0], (const void *)c->a[1], c->a[2], 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int enter_sendto(struct sys_enter *c)
{
	emit((s32)c->a[0], (const void *)c->a[1], c->a[2], 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct sys_enter *c)
{
	begin_read(c);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int enter_recvfrom(struct sys_enter *c)
{
	begin_read(c);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct sys_exit *c)
{
	end_read(c);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int exit_recvfrom(struct sys_exit *c)
{
	end_read(c);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
