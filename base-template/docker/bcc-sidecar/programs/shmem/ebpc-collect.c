// shm_monitor_final.bpf.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

// For PT_REGS_PARMx access
#include <uapi/linux/ptrace.h> 
// For bpf_trace_printk, often included by bcc itself, but can be explicit if needed
// #include <bcc/proto.h> 

#include <uapi/linux/shm.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/mman.h>

// Define SEC macro
#ifndef SEC
# define SEC(name) __attribute__((section(name), used))
#endif

typedef unsigned long long u64;
typedef unsigned int u32;
#define TASK_COMM_LEN 16
#define SHM_NAME_LEN 64

// --- Manually define tracepoint context structures ---
struct trace_event_raw_sys_enter {
    unsigned long long __unused_common_fields;
    long syscall_nr;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    unsigned long long __unused_common_fields;
    long syscall_nr;
    long ret;
};

// --- Aggregated Stats Structures ---
struct shm_tgid_stats_t {
    u64 shmget_calls;
    u64 shmget_success;
    u64 shmat_calls;
    u64 shmdt_calls;
    u64 shmctl_rmid_calls;
    u64 total_shmget_size_bytes;
    u64 shm_open_calls;
    u64 shm_open_success;
    u64 shm_unlink_calls;
    u64 mmap_shared_calls;
    u64 munmap_shared_calls;
    u64 total_mmap_shared_size_bytes;
};

BPF_HASH(proc_shm_stats, u32, struct shm_tgid_stats_t);

struct shmget_args_t {
    size_t size;
};
BPF_HASH(active_shmgets, u32, struct shmget_args_t);

struct mmap_args_t {
    u64 len;
    int flags;
    int fd;
};
BPF_HASH(active_mmaps, u32, struct mmap_args_t);

struct shm_open_kprobe_args_t {
    char name[SHM_NAME_LEN];
};
BPF_HASH(active_shm_opens_kprobe, u32, struct shm_open_kprobe_args_t);


static __always_inline struct shm_tgid_stats_t* get_tgid_stats(u32 tgid) {
    struct shm_tgid_stats_t zero_stats = {0};
    struct shm_tgid_stats_t *stats = proc_shm_stats.lookup_or_try_init(&tgid, &zero_stats);
    if (!stats) {
        bpf_trace_printk("BPF_ERR: get_stats failed TGID: %u\n", sizeof("BPF_ERR: get_stats failed TGID: %u\n")-1, tgid);
    }
    return stats;
}

// --- SysV Shared Memory Syscalls (Using Tracepoints - Unchanged) ---
SEC("tracepoint/syscalls/sys_enter_shmget")
int trace_enter_shmget(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("BPF_TP: enter_shmget TGID: %u\n", sizeof("BPF_TP: enter_shmget TGID: %u\n")-1, current_tgid);
    u32 tgid = current_tgid;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->shmget_calls++;
    struct shmget_args_t args = {};
    args.size = (size_t)ctx->args[1];
    active_shmgets.update(&tid, &args);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_shmget")
int trace_exit_shmget(struct trace_event_raw_sys_exit* ctx) { /* ... as before ... */ 
    u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    long retval = ctx->ret;
    bpf_trace_printk("BPF_TP: exit_shmget TGID: %u ret: %ld\n", sizeof("BPF_TP: exit_shmget TGID: %u ret: %ld\n")-1, current_tgid, retval);
    u32 tgid = current_tgid;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct shmget_args_t *entry_args = active_shmgets.lookup(&tid);
    if (!entry_args) return 0; 
    if (ctx->ret >= 0) {
        struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
        if (!stats) { active_shmgets.delete(&tid); return 0; }
        stats->shmget_success++;
        stats->total_shmget_size_bytes += entry_args->size;
    }
    active_shmgets.delete(&tid);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_shmat")
int trace_enter_shmat(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->shmat_calls++;
    bpf_trace_printk("BPF_TP: enter_shmat TGID: %u\n", sizeof("BPF_TP: enter_shmat TGID: %u\n")-1, tgid);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_shmdt")
int trace_enter_shmdt(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->shmdt_calls++;
    bpf_trace_printk("BPF_TP: enter_shmdt TGID: %u\n", sizeof("BPF_TP: enter_shmdt TGID: %u\n")-1, tgid);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_shmctl")
int trace_enter_shmctl(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    int cmd = (int)ctx->args[1];
    if (cmd == IPC_RMID) {
        u32 tgid = bpf_get_current_pid_tgid() >> 32;
        struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
        if (!stats) return 0;
        stats->shmctl_rmid_calls++;
        bpf_trace_printk("BPF_TP: enter_shmctl (IPC_RMID) TGID: %u\n", sizeof("BPF_TP: enter_shmctl (IPC_RMID) TGID: %u\n")-1, tgid);
    }
    return 0;
}


// --- POSIX Shared Memory (shm_open, shm_unlink via Kprobes) ---

// Standard kprobe signature: first arg is struct pt_regs *ctx
// Kernel function shm_open(const char *name, int oflag, mode_t mode)
SEC("kprobe/shm_open")
int kp_shm_open(struct pt_regs *ctx) { // Changed signature
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_trace_printk("BPF_KP: kp_shm_open TGID: %u\n", sizeof("BPF_KP: kp_shm_open TGID: %u\n")-1, tgid);

    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->shm_open_calls++;

    // Access arguments using PT_REGS_PARMx(ctx)
    // These macros depend on architecture (e.g. x86_64 uses di, si, dx, cx, r8, r9)
    // PT_REGS_PARM1(ctx) is the first argument, PT_REGS_PARM2(ctx) the second, etc.
    // The types must match the kernel function's arguments.
    const char *name_user_ptr = (const char *)PT_REGS_PARM1(ctx);
    // int oflag = (int)PT_REGS_PARM2(ctx);       // If needed
    // mode_t mode = (mode_t)PT_REGS_PARM3(ctx); // If needed


    struct shm_open_kprobe_args_t k_args = {};
    bpf_probe_read_user_str(&k_args.name, sizeof(k_args.name), (void *)name_user_ptr);
    active_shm_opens_kprobe.update(&tid, &k_args);
    
    return 0;
}

// Standard kretprobe signature: first arg is struct pt_regs *ctx
// The return value of the probed function is in PT_REGS_RC(ctx)
SEC("kretprobe/shm_open")
int krp_shm_open(struct pt_regs *ctx) { // Changed signature
    int ret_val = (int)PT_REGS_RC(ctx); // Get return value

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_trace_printk("BPF_KP: krp_shm_open TGID: %u, ret: %d\n", sizeof("BPF_KP: krp_shm_open TGID: %u, ret: %d\n")-1, tgid, ret_val);

    struct shm_open_kprobe_args_t *k_args __attribute__((unused)) = active_shm_opens_kprobe.lookup(&tid);
    active_shm_opens_kprobe.delete(&tid); 

    if (ret_val >= 0) { // Success (ret_val is fd)
        struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
        if (!stats) return 0;
        stats->shm_open_success++;
    }
    return 0;
}

// Kernel function shm_unlink(const char *name)
SEC("kprobe/shm_unlink") 
int kp_shm_unlink(struct pt_regs *ctx) { // Changed signature
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("BPF_KP: kp_shm_unlink TGID: %u\n", sizeof("BPF_KP: kp_shm_unlink TGID: %u\n")-1, tgid);

    // const char *name_user_ptr = (const char *)PT_REGS_PARM1(ctx); // If you need to read the name
    // char name_buf[SHM_NAME_LEN];
    // bpf_probe_read_user_str(&name_buf, sizeof(name_buf), (void *)name_user_ptr);
    // bpf_trace_printk("BPF_KP: shm_unlink path: %s (cannot print directly)\n", ...);


    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->shm_unlink_calls++;
    return 0;
}


// --- mmap/munmap (Using Tracepoints - Unchanged) ---
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    int flags_arg = (int)ctx->args[3];
    if (!(flags_arg & MAP_SHARED)) {
        return 0;
    }
    u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("BPF_TP: enter_mmap (SHARED) TGID: %u, flags: 0x%x\n", sizeof("BPF_TP: enter_mmap (SHARED) TGID: %u, flags: 0x%x\n")-1, current_tgid, (u64)flags_arg);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct mmap_args_t args = {};
    args.len = (u64)ctx->args[1];
    args.flags = flags_arg;
    args.fd = (int)ctx->args[4];
    active_mmaps.update(&tid, &args);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_exit_mmap(struct trace_event_raw_sys_exit* ctx) { /* ... as before ... */ 
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct mmap_args_t *entry_args = active_mmaps.lookup(&tid);
    if (!entry_args) return 0; 
    if (!(entry_args->flags & MAP_SHARED)) {
        active_mmaps.delete(&tid);
        return 0;
    }
    u64 ret_val_u64 = (u64)ctx->ret;
    bpf_trace_printk("BPF_TP: exit_mmap (SHARED) TGID: %u, ret: 0x%lx\n", sizeof("BPF_TP: exit_mmap (SHARED) TGID: %u, ret: 0x%lx\n")-1, tgid, ret_val_u64);
    if (ret_val_u64 != (u64)-1L) { 
        struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
        if (!stats) { active_mmaps.delete(&tid); return 0; }
        stats->mmap_shared_calls++;
        stats->total_mmap_shared_size_bytes += entry_args->len;
    }
    active_mmaps.delete(&tid);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_munmap") // Corrected closing brace was missing in previous snippet
int trace_enter_munmap(struct trace_event_raw_sys_enter* ctx) { /* ... as before ... */ 
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_tgid_stats(tgid);
    if (!stats) return 0;
    stats->munmap_shared_calls++;
    bpf_trace_printk("BPF_TP: enter_munmap TGID: %u\n", sizeof("BPF_TP: enter_munmap TGID: %u\n")-1, tgid);
    return 0;
} // <--- Added missing brace

