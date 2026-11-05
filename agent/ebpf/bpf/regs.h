// User-register view shared by the vmlinux.h probes (dwarf.h, rtregs.bpf.c, tls.bpf.c). The release
// builds both arches on one host, so vmlinux.h is that host's BTF: its pt_regs is x86 even for the
// arm64 object. x86 therefore uses the BTF struct (CO-RE relocated at load); arm64 reads the fixed
// user_pt_regs ABI layout through our own struct and casts the kernel's pointer to it.
#if defined(__TARGET_ARCH_arm64)
struct wt_uregs {
	u64 regs[31];
	u64 sp;
	u64 pc;
	u64 pstate;
};
typedef struct wt_uregs uregs;
#define REGS_USER(r) (((r)->pstate & 0xf) == 0)
#else
typedef struct pt_regs uregs;
#define REGS_USER(r) (((r)->cs & 3) == 3)
#endif
