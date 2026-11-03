// Shared by cpu.bpf.c and offcpu.bpf.c. Build with `make ebpf-gen` (clang, libbpf headers).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;

#define MAX_STACK_DEPTH 127

// Key of the count map; the Go side reads the same 24 bytes (explicit padding).
struct key {
	u32 pid; // tgid
	s32 user; // stack id, negative on failure
	s32 kern;
	u32 pad;
	u64 dwarf; // id in dwarf_stacks (cpu_dwarf.bpf.c), 0 when user is the stack
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 16384);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key);
	__type(value, u64);
	__uint(max_entries, 32768);
} counts SEC(".maps");

static __always_inline void add_count(struct key *k, u64 v)
{
	u64 *c = bpf_map_lookup_elem(&counts, k);
	if (c) {
		__sync_fetch_and_add(c, v);
		return;
	}
	bpf_map_update_elem(&counts, k, &v, BPF_NOEXIST);
}

char LICENSE[] SEC("license") = "GPL";
