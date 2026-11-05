#define USE_VMLINUX 1 // BTF vmlinux.h, see common.h
#include "trace.h"
#include "regs.h"

// Uprobes for OpenSSL (SSL_write/SSL_read, SysV ABI) and Go crypto/tls
// ((*Conn).Write/(*Conn).Read, Go register ABI). Shares the `events` ring buffer with http.bpf.c
// (the loader passes it as a map replacement). Java, Node's bundled BoringSSL and other TLS
// libraries are not covered.
#if defined(__TARGET_ARCH_x86)
// vmlinux.h pt_regs names (no UAPI r-prefix).
#define SYSV(c, n) ((n) == 1 ? (c)->di : (n) == 2 ? (c)->si : (c)->dx)
#define SYSV_RET(c) ((c)->ax)
#define GO_ARG(c, n) ((n) == 0 ? (c)->ax : (n) == 1 ? (c)->bx : (c)->cx)
#define GO_RET(c) ((c)->ax)
#define GO_G(c) ((c)->r14)
#elif defined(__TARGET_ARCH_arm64)
#define SYSV(c, n) (((uregs *)(c))->regs[(n) - 1])
#define SYSV_RET(c) (((uregs *)(c))->regs[0])
#define GO_ARG(c, n) (((uregs *)(c))->regs[n])
#define GO_RET(c) (((uregs *)(c))->regs[0])
#define GO_G(c) (((uregs *)(c))->regs[28])
#endif

struct wt_rd_args {
	s32 conn;
	const void *buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct wt_rd_args);
	__uint(max_entries, 16384);
} tls_reading SEC(".maps");

static __always_inline s32 conn_id(u64 p) { return (s32)(p >> 4); }

SEC("uprobe/ssl_write")
int ssl_write(struct pt_regs *c)
{
	emit(conn_id(SYSV(c, 1)), (const void *)SYSV(c, 2), SYSV(c, 3), 0, 1);
	return 0;
}

SEC("uprobe/ssl_read")
int ssl_read(struct pt_regs *c)
{
	u64 id = bpf_get_current_pid_tgid();
	struct wt_rd_args a = {.conn = conn_id(SYSV(c, 1)), .buf = (const void *)SYSV(c, 2)};
	bpf_map_update_elem(&tls_reading, &id, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/ssl_read")
int ssl_read_ret(struct pt_regs *c)
{
	u64 id = bpf_get_current_pid_tgid();
	struct wt_rd_args *a = bpf_map_lookup_elem(&tls_reading, &id);
	if (!a)
		return 0;
	long n = (long)SYSV_RET(c);
	if (n > 0)
		emit(a->conn, a->buf, n, 1, 1);
	bpf_map_delete_elem(&tls_reading, &id);
	return 0;
}

SEC("uprobe/go_tls_write")
int go_tls_write(struct pt_regs *c)
{
	emit(conn_id(GO_ARG(c, 0)), (const void *)GO_ARG(c, 1), GO_ARG(c, 2), 0, 1);
	return 0;
}

// Keyed by the goroutine pointer: a goroutine can change threads between entry and return.
SEC("uprobe/go_tls_read")
int go_tls_read(struct pt_regs *c)
{
	u64 g = GO_G(c);
	struct wt_rd_args a = {.conn = conn_id(GO_ARG(c, 0)), .buf = (const void *)GO_ARG(c, 1)};
	bpf_map_update_elem(&tls_reading, &g, &a, BPF_ANY);
	return 0;
}

// Attached by the loader at every RET instruction of (*Conn).Read (a uretprobe would crash Go).
SEC("uprobe/go_tls_read_ret")
int go_tls_read_ret(struct pt_regs *c)
{
	u64 g = GO_G(c);
	struct wt_rd_args *a = bpf_map_lookup_elem(&tls_reading, &g);
	if (!a)
		return 0;
	long n = (long)GO_RET(c);
	if (n > 0)
		emit(a->conn, a->buf, n, 1, 1);
	bpf_map_delete_elem(&tls_reading, &g);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
