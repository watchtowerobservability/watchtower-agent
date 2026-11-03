// DWARF stack walking shared by cpu_dwarf.bpf.c and offcpu_dwarf.bpf.c (x86-64, arm64). User space
// parses each sampled binary's .eh_frame / .debug_frame into rows (unwind_tables.go) and fills
// `procs` and `rows`; the walker uses them and falls back to frame pointers where a PC has no
// row (JIT, unsupported CFA rules).
//
// Verifier budget: the entry program only saves the registers and tail-calls unwind_step, which
// walks FRAMES_PER_STEP frames (each a mapping scan of <= 8 and a binary search of <= 20 steps)
// and tail-calls itself, at most MAX_STEPS times (the kernel allows 33 tail calls). Each program
// stays small on every path without bpf_loop.
#include "common.h"
#include <linux/bpf_perf_event.h>

typedef unsigned short u16;
typedef short s16;
typedef unsigned char u8;

// Set by the loader when bpf_task_pt_regs exists (5.15+); a dead branch otherwise, which the
// verifier removes along with the helper call.
const volatile u32 have_task_regs = 0;

#define MAX_MAPS 8
#define MAX_ROWS (1 << 19)
#define FRAMES_PER_STEP 4
#define MAX_STEPS 16
#define MAX_FRAMES (FRAMES_PER_STEP * MAX_STEPS) // 64, maxDwarfFrames in unwind_linux.go
#define SEARCH_STEPS 20 // 2^20 > the 1<<17 rows a binary may have

enum { CFA_NONE, CFA_RSP, CFA_RBP, CFA_UNSUPPORTED, CFA_END };
enum { RBP_SAME, RBP_OFFSET };

struct umap {
	u64 start, end, bias;
	u32 off, len;
};

struct uproc {
	u32 n, pad;
	struct umap m[MAX_MAPS];
};

struct row {
	u64 pc;
	u8 cfa_reg, rbp_rule;
	s16 cfa_off, rbp_off;
	s16 ra_off; // 0: at CFA-8 on x86-64, still in x30 on arm64
};

struct stack {
	u64 pcs[MAX_FRAMES];
};

// Walk state carried across tail calls (one per CPU: a perf event program does not nest).
struct walk {
	u64 ip, sp, bp, lr;
	u32 n, step, pid, tid;
	s32 kern, pad;
	u64 ts;
	struct stack s;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct uproc);
	__uint(max_entries, 1024);
} procs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct row);
	__uint(max_entries, MAX_ROWS);
} rows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); // ids outlive upload windows: a blocked task reports later
	__type(key, u64);
	__type(value, struct stack);
	__uint(max_entries, 8192);
} dwarf_stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct walk);
	__uint(max_entries, 1);
} walks SEC(".maps");

// Slot 0 holds unwind_step; the loader fills it (loader_linux.go).
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} progs SEC(".maps");

// The row covering table pc in rows[off, off+len), or 0.
static __always_inline struct row *find_row(u32 off, u32 len, u64 pc)
{
	u32 lo = 0, hi = len;
	for (int i = 0; i < SEARCH_STEPS && lo < hi; i++) {
		u32 mid = lo + (hi - lo) / 2, k = off + mid;
		struct row *r = bpf_map_lookup_elem(&rows, &k);
		if (!r)
			return 0;
		if (r->pc <= pc)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo == 0)
		return 0;
	u32 k = off + lo - 1;
	return bpf_map_lookup_elem(&rows, &k);
}

static __always_inline struct row *lookup(struct uproc *p, u64 pc)
{
	for (int i = 0; i < MAX_MAPS; i++) {
		if (i >= p->n)
			break;
		struct umap *m = &p->m[i];
		if (pc >= m->start && pc < m->end)
			return find_row(m->off, m->len, pc - m->bias);
	}
	return 0;
}

#if defined(__TARGET_ARCH_arm64)
typedef struct user_pt_regs uregs;
#define REGS_USER(r) (((r)->pstate & 0xf) == 0)
#define REGS_LOAD(w, r) ((w)->ip = (r)->pc, (w)->sp = (r)->sp, (w)->bp = (r)->regs[29], (w)->lr = (r)->regs[30])
#define CODE_ADDR(a) ((a) & 0x0000ffffffffffffULL) // strips pointer authentication
#else
typedef struct pt_regs uregs;
#define REGS_USER(r) (((r)->cs & 3) == 3)
#define REGS_LOAD(w, r) ((w)->ip = (r)->ip, (w)->sp = (r)->sp, (w)->bp = (r)->bp, (w)->lr = 0)
#define CODE_ADDR(a) (a)
#endif

// The current task's user registers, also when the event hit it in the kernel.
static __always_inline int task_regs(struct walk *w)
{
	uregs u;
	if (!have_task_regs)
		return 0;
	void *r = (void *)bpf_task_pt_regs(bpf_get_current_task_btf());
	if (!r || bpf_probe_read_kernel(&u, sizeof(u), r) || !REGS_USER(&u))
		return 0;
	REGS_LOAD(w, &u);
	return 1;
}

// A stack id for the walked frames in dwarf_stacks, 0 when the walk found nothing past the leaf.
static __always_inline u64 store_stack(struct walk *w)
{
	if (w->n <= 1)
		return 0;
	u64 h = 14695981039346656037ULL; // FNV-1a over the PCs
	for (int i = 0; i < MAX_FRAMES; i++) {
		if (i >= w->n)
			w->s.pcs[i] = 0;
		h = (h ^ w->s.pcs[i]) * 1099511628211ULL;
	}
	h |= 1; // 0 means "no dwarf stack"
	bpf_map_update_elem(&dwarf_stacks, &h, &w->s, BPF_ANY);
	return h;
}

// One frame: records w->ip and moves ip/sp/bp to the caller; returns 0 when the walk ends.
static __always_inline int walk_frame(struct uproc *p, struct walk *w)
{
	u32 i = w->n;
	if (i >= MAX_FRAMES)
		return 0;
	w->s.pcs[i] = w->ip;
	w->n = i + 1;
	struct row *r = lookup(p, i == 0 ? w->ip : w->ip - 1); // a return address points past its call
	u64 cfa, ra = 0, nbp = w->bp;
	if (r && r->cfa_reg == CFA_END)
		return 0;
	if (r && (r->cfa_reg == CFA_RSP || r->cfa_reg == CFA_RBP)) {
		cfa = (r->cfa_reg == CFA_RSP ? w->sp : w->bp) + r->cfa_off;
#if defined(__TARGET_ARCH_arm64)
		if (r->ra_off) {
			if (bpf_probe_read_user(&ra, 8, (void *)(cfa + r->ra_off)))
				return 0;
		} else {
			ra = w->lr; // only the interrupted frame can still have it in x30
		}
#else
		if (bpf_probe_read_user(&ra, 8, (void *)(cfa - 8)))
			return 0;
#endif
		if (r->rbp_rule == RBP_OFFSET && bpf_probe_read_user(&nbp, 8, (void *)(cfa + r->rbp_off)))
			return 0;
	} else { // frame pointers: [fp] is the caller's, [fp+8] the return address, on both
		if (!w->bp || bpf_probe_read_user(&ra, 8, (void *)(w->bp + 8)) ||
		    bpf_probe_read_user(&nbp, 8, (void *)w->bp))
			return 0;
		cfa = w->bp + 16;
	}
	ra = CODE_ADDR(ra);
	if (!ra)
		return 0;
	w->ip = ra, w->sp = cfa, w->bp = nbp, w->lr = 0;
	return 1;
}

// FRAMES_PER_STEP frames; 1 when the walk should continue in another tail call.
static __always_inline int walk_step(struct walk *w)
{
	struct uproc *p = bpf_map_lookup_elem(&procs, &w->pid);
	int more = p != 0;
	for (int i = 0; i < FRAMES_PER_STEP && more; i++)
		more = walk_frame(p, w);
	w->step++;
	return more && w->step < MAX_STEPS;
}
