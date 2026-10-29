// Per-connection TCP summaries for ebpf_net (INF-038). One event per closed connection, so the
// event rate is the connection rate, not the packet rate. Build with `make ebpf-gen`.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define AF_INET 2

// Only the fields read below; CO-RE relocates them against the running kernel's BTF.
struct tcp_sock {
	u32 srtt_us;
	u32 total_retrans;
	u64 bytes_received;
	u64 bytes_sent;
} __attribute__((preserve_access_index));

// sock:inet_sock_set_state tracepoint (layout from its format file, ports in host order).
struct set_state {
	u64 common;
	const void *skaddr;
	s32 oldstate;
	s32 newstate;
	u16 sport;
	u16 dport;
	u16 family;
	u16 protocol;
	u8 saddr[4];
	u8 daddr[4];
	u8 saddr_v6[16];
	u8 daddr_v6[16];
};

// tcp:tcp_receive_reset
struct rcv_reset {
	u64 common;
	const void *skaddr;
};

struct conn {
	u64 start_ns;
	u64 connect_ns;
	u64 cgroup;
	u32 pid; // 0 for a passive (accepted) connection: the softirq context is not the owner
	u8 reset;
};

// Mirrored by trace of net/tcp_linux.go (connEvent): 8-byte aligned, no implicit padding.
struct conn_ev {
	u64 ts;
	u64 bytes_sent;
	u64 bytes_recv;
	u64 connect_ns;
	u64 cgroup;
	u32 retrans;
	u32 srtt_us;
	u32 pid;
	u16 sport;
	u16 dport;
	u8 saddr[16];
	u8 daddr[16];
	u8 v6;
	u8 failed;
	u8 reset;
	u8 active;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct conn);
	__uint(max_entries, 65536);
} conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // resized by the loader from ring_buffer_kb
} conn_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} drops SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int set_state(struct set_state *c)
{
	if (c->protocol != 6) // IPPROTO_TCP
		return 0;
	u64 sk = (u64)c->skaddr;
	u64 now = bpf_ktime_get_ns();
	if (c->newstate == TCP_SYN_SENT) {
		struct conn n = {.start_ns = now, .cgroup = bpf_get_current_cgroup_id(),
				 .pid = bpf_get_current_pid_tgid() >> 32};
		bpf_map_update_elem(&conns, &sk, &n, BPF_ANY);
		return 0;
	}
	struct conn *cn = bpf_map_lookup_elem(&conns, &sk);
	if (c->newstate == TCP_ESTABLISHED) {
		if (cn) {
			cn->connect_ns = now - cn->start_ns;
		} else {
			struct conn n = {.start_ns = now};
			bpf_map_update_elem(&conns, &sk, &n, BPF_ANY);
		}
		return 0;
	}
	if (c->newstate != TCP_CLOSE)
		return 0;
	struct conn_ev *e = bpf_ringbuf_reserve(&conn_events, sizeof(*e), 0);
	if (!e) {
		u32 z = 0;
		u64 *d = bpf_map_lookup_elem(&drops, &z);
		if (d)
			__sync_fetch_and_add(d, 1);
		goto out;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = now;
	e->sport = c->sport;
	e->dport = c->dport;
	e->v6 = c->family != AF_INET;
	if (e->v6) {
		__builtin_memcpy(e->saddr, c->saddr_v6, 16);
		__builtin_memcpy(e->daddr, c->daddr_v6, 16);
	} else {
		__builtin_memcpy(e->saddr, c->saddr, 4);
		__builtin_memcpy(e->daddr, c->daddr, 4);
	}
	struct tcp_sock *tp = (struct tcp_sock *)c->skaddr;
	e->bytes_sent = BPF_CORE_READ(tp, bytes_sent);
	e->bytes_recv = BPF_CORE_READ(tp, bytes_received);
	e->retrans = BPF_CORE_READ(tp, total_retrans);
	e->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
	e->failed = c->oldstate == TCP_SYN_SENT;
	if (cn) {
		e->connect_ns = cn->connect_ns;
		e->cgroup = cn->cgroup;
		e->pid = cn->pid;
		e->reset = cn->reset;
		e->active = cn->pid != 0;
	}
	bpf_ringbuf_submit(e, 0);
out:
	bpf_map_delete_elem(&conns, &sk);
	return 0;
}

SEC("tracepoint/tcp/tcp_receive_reset")
int receive_reset(struct rcv_reset *c)
{
	u64 sk = (u64)c->skaddr;
	struct conn *cn = bpf_map_lookup_elem(&conns, &sk);
	if (cn)
		cn->reset = 1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
