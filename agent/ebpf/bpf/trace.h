// Shared by http.bpf.c and tls.bpf.c (ebpf_trace). Build with `make ebpf-gen`.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;

#define HEAD_BYTES 512 // request and response heads only; never bodies

// One captured read or write; the Go side (trace/probe_linux.go) decodes the same bytes.
struct ev {
	u64 ts;
	u32 pid; // tgid
	s32 fd;  // socket fd, or the low bits of the SSL*/tls.Conn pointer for TLS
	u32 len; // bytes captured, <= HEAD_BYTES
	u8 dir;  // 0 send, 1 recv
	u8 tls;
	u16 pad;
	u8 data[HEAD_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20); // resized by the loader from ring_buffer_kb
} events SEC(".maps");

// Events lost because the ring buffer was full.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} drops SEC(".maps");

static __always_inline void emit(s32 fd, const void *buf, u64 n, u8 dir, u8 tls)
{
	if (n < 4)
		return;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct ev *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		u32 z = 0;
		u64 *d = bpf_map_lookup_elem(&drops, &z);
		if (d)
			__sync_fetch_and_add(d, 1);
		return;
	}
	u32 len = n > HEAD_BYTES ? HEAD_BYTES : n;
	e->ts = bpf_ktime_get_ns();
	e->pid = pid;
	e->fd = fd;
	e->len = len;
	e->dir = dir;
	e->tls = tls;
	e->pad = 0;
	if (bpf_probe_read_user(e->data, len, buf) < 0) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	bpf_ringbuf_submit(e, 0);
}
