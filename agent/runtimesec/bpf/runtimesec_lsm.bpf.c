// Workload Protection enforcement for runtime_security: BPF LSM hooks that refuse an exec or a file
// open when the file's inode is in a deny map the agent fills from `block` rules (see
// runtimesec/block.go). Inodes, not paths, so a bind mount or a relative path cannot slip past, and
// the agent re-resolves the paths every minute so a replaced file is covered again.
//
// Needs a kernel with CONFIG_BPF_LSM and `bpf` in the active LSM list (lsm=...,bpf); the loader
// refuses to start block rules otherwise (block_linux.go). CO-RE: built against the vmlinux.h that
// scripts/ebpf-gen.sh dumps from the build host's BTF.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define FMODE_WRITE 0x2
#define KIND_EXEC 0
#define KIND_FILE 1
#define FLAG_ANY 1
#define FLAG_WRITE 2

// Mirrored by runtimesec/block.go (denyKey): 16 bytes.
struct inode_key {
	__u64 ino;
	__u32 dev; // kernel dev_t (major << 20 | minor)
	__u32 pad;
};

// Mirrored by block.go (decodeDenied, deniedSize = 48).
struct denied {
	__u64 ts;
	__u64 ino;
	__u32 dev;
	__u32 pid;
	__u32 kind;
	__u32 pad;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct inode_key);
	__type(value, __u32);
} deny_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct inode_key);
	__type(value, __u32); // FLAG_ANY: refuse every open; FLAG_WRITE: refuse opens for writing
} deny_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} denied SEC(".maps");

static __always_inline void report(struct inode_key *k, __u32 kind)
{
	struct denied *d = bpf_ringbuf_reserve(&denied, sizeof(*d), 0);
	if (!d)
		return;
	__builtin_memset(d, 0, sizeof(*d));
	d->ts = bpf_ktime_get_ns();
	d->ino = k->ino;
	d->dev = k->dev;
	d->pid = bpf_get_current_pid_tgid() >> 32;
	d->kind = kind;
	bpf_get_current_comm(&d->comm, sizeof(d->comm));
	bpf_ringbuf_submit(d, 0);
}

static __always_inline int key_of(struct file *f, struct inode_key *k)
{
	struct inode *in = BPF_CORE_READ(f, f_inode);
	if (!in)
		return -1;
	k->ino = BPF_CORE_READ(in, i_ino);
	k->dev = BPF_CORE_READ(in, i_sb, s_dev);
	k->pad = 0;
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(wt_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct inode_key k = {};
	if (ret)
		return ret; // an earlier hook already refused
	if (key_of(BPF_CORE_READ(bprm, file), &k))
		return 0;
	if (!bpf_map_lookup_elem(&deny_exec, &k))
		return 0;
	report(&k, KIND_EXEC);
	return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(wt_file_open, struct file *file, int ret)
{
	struct inode_key k = {};
	if (ret)
		return ret;
	if (key_of(file, &k))
		return 0;
	__u32 *flags = bpf_map_lookup_elem(&deny_file, &k);
	if (!flags)
		return 0;
	if (!(*flags & FLAG_ANY) && !((*flags & FLAG_WRITE) && (BPF_CORE_READ(file, f_mode) & FMODE_WRITE)))
		return 0;
	report(&k, KIND_FILE);
	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
