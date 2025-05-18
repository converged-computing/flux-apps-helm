// ebpf-collect-original-with-comm.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <uapi/linux/ptrace.h> 
#include <uapi/linux/shm.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/mman.h>

// Define SEC macro
#ifndef SEC
# define SEC(name) __attribute__((section(name), used))
#endif

typedef unsigned long long u64;
typedef unsigned int u32;
#define TASK_COMM_LEN 16 // As in your Python
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

// --- Aggregated Stats Structures (YOUR ORIGINAL STRUCTURE) ---
struct shm_tgid_stats_t {
    // SysV
    u64 shmget_calls;
    u64 shmget_success;
    u64 shmat_calls;
    u64 shmdt_calls;
    u64 shmctl_rmid_calls;
    u64 total_shmget_size_bytes;
    // POSIX
    u64 shm_open_calls;
    u64 shm_open_success;
    u64 shm_unlink_calls;
    u64 mmap_shared_calls;
    u64 munmap_shared_calls;
    u64 total_mmap_shared_size_bytes;
};

BPF_HASH(proc_shm_stats, u32, struct shm_tgid_stats_t); // Key: TGID

// --- NEW MAP: TGID to Comm ---
struct comm_arr_t {
    char comm[TASK_COMM_LEN];
};
BPF_HASH(tgid_to_comm, u32, struct comm_arr_t); // Key: TGID, Value: char array for comm


// --- Temporary storage maps (YOUR ORIGINAL STRUCTURES) ---
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

struct shm_open_kprobe_args_t { // From when we kprobed shm_open
    char name[SHM_NAME_LEN];
};
BPF_HASH(active_shm_opens_kprobe, u32, struct shm_open_kprobe_args_t);


// Modified helper: gets stats, and ensures comm is stored if not already
static __always_inline struct shm_tgid_stats_t* get_or_init_tgid_stats_and_comm(u32 tgid) {
    struct shm_tgid_stats_t *stats = proc_shm_stats.lookup(&tgid);
    if (stats) { // Stats entry exists
        // Check if comm exists, if not, add it
        // This avoids re-getting comm on every call if already stored
        struct comm_arr_t *comm_entry = tgid_to_comm.lookup(&tgid);
        if (!comm_entry) {
            struct comm_arr_t new_comm = {0};
            bpf_get_current_comm(&new_comm.comm, sizeof(new_comm.comm));
            tgid_to_comm.update(&tgid, &new_comm);
        }
        return stats;
    }

    // Stats entry does NOT exist, create it and comm
    struct shm_tgid_stats_t zero_stats = {0};
    proc_shm_stats.update(&tgid, &zero_stats); // Create stats entry first
    
    stats = proc_shm_stats.lookup(&tgid); // Re-lookup stats
    if (!stats) {
        bpf_trace_printk("BPF_ERR: get_stats (stats) map re-lookup failed TGID: %u\n", sizeof("BPF_ERR: get_stats (stats) map re-lookup failed TGID: %u\n")-1, tgid);
        return NULL;
    }

    struct comm_arr_t new_comm = {0};
    bpf_get_current_comm(&new_comm.comm, sizeof(new_comm.comm));
    tgid_to_comm.update(&tgid, &new_comm); // Create comm entry

    return stats;
}


// --- SysV Shared Memory Syscalls (Using Tracepoints) ---
SEC("tracepoint/syscalls/sys_enter_shmget")
int trace_enter_shmget(struct trace_event_raw_sys_enter* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // bpf_trace_printk("BPF_TP: enter_shmget TGID: %u\n", sizeof("BPF_TP: enter_shmget TGID: %u\n")-1, tgid);

    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid); // Use new helper
    if (!stats) return 0;
    stats->shmget_calls++;

    struct shmget_args_t args = {};
    args.size = (size_t)ctx->args[1];
    active_shmgets.update(&tid, &args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_shmget")
int trace_exit_shmget(struct trace_event_raw_sys_exit* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // long retval = ctx->ret;
    // bpf_trace_printk("BPF_TP: exit_shmget TGID: %u ret: %ld\n", sizeof("BPF_TP: exit_shmget TGID: %u ret: %ld\n")-1, tgid, retval);
    
    struct shmget_args_t *entry_args = active_shmgets.lookup(&tid);
    if (!entry_args) return 0; 

    if (ctx->ret >= 0) {
        struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid); // Use new helper
        if (!stats) { active_shmgets.delete(&tid); return 0; }
        stats->shmget_success++;
        stats->total_shmget_size_bytes += entry_args->size;
    }
    active_shmgets.delete(&tid);
    return 0;
}

// --- Apply get_or_init_tgid_stats_and_comm to other functions ---
SEC("tracepoint/syscalls/sys_enter_shmat")
int trace_enter_shmat(struct trace_event_raw_sys_enter* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
    if (!stats) return 0;
    stats->shmat_calls++;
    // bpf_trace_printk("BPF_TP: enter_shmat TGID: %u\n", sizeof("BPF_TP: enter_shmat TGID: %u\n")-1, tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int trace_enter_shmdt(struct trace_event_raw_sys_enter* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
    if (!stats) return 0;
    stats->shmdt_calls++;
    // bpf_trace_printk("BPF_TP: enter_shmdt TGID: %u\n", sizeof("BPF_TP: enter_shmdt TGID: %u\n")-1, tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int trace_enter_shmctl(struct trace_event_raw_sys_enter* ctx) {
    int cmd = (int)ctx->args[1];
    if (cmd == IPC_RMID) {
        u32 tgid = bpf_get_current_pid_tgid() >> 32;
        struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
        if (!stats) return 0;
        stats->shmctl_rmid_calls++;
        // bpf_trace_printk("BPF_TP: enter_shmctl (IPC_RMID) TGID: %u\n", sizeof("BPF_TP: enter_shmctl (IPC_RMID) TGID: %u\n")-1, tgid);
    }
    return 0;
}

// --- POSIX Shared Memory (shm_open, shm_unlink via Kprobes) ---
// Using the pt_regs method for kprobes as it's most robust with BCC
SEC("kprobe/shm_open")
int kp_shm_open(struct pt_regs *ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // bpf_trace_printk("BPF_KP: kp_shm_open TGID: %u\n", sizeof("BPF_KP: kp_shm_open TGID: %u\n")-1, tgid);

    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
    if (!stats) return 0;
    stats->shm_open_calls++;

    const char *name_user_ptr = (const char *)PT_REGS_PARM1(ctx);
    struct shm_open_kprobe_args_t k_args = {}; // Not strictly needed if only counting, but kept for structure
    bpf_probe_read_user_str(&k_args.name, sizeof(k_args.name), (void *)name_user_ptr);
    active_shm_opens_kprobe.update(&tid, &k_args); // Store for kretprobe if needed (e.g. to log name on exit)
    
    return 0;
}

SEC("kretprobe/shm_open")
int krp_shm_open(struct pt_regs *ctx) {
    int ret_val = (int)PT_REGS_RC(ctx);
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // bpf_trace_printk("BPF_KP: krp_shm_open TGID: %u, ret: %d\n", sizeof("BPF_KP: krp_shm_open TGID: %u, ret: %d\n")-1, tgid, ret_val);

    active_shm_opens_kprobe.delete(&tid); // Clean up map

    if (ret_val >= 0) { 
        struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
        if (!stats) return 0;
        stats->shm_open_success++;
    }
    return 0;
}

SEC("kprobe/shm_unlink") 
int kp_shm_unlink(struct pt_regs *ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("BPF_KP: kp_shm_unlink TGID: %u\n", sizeof("BPF_KP: kp_shm_unlink TGID: %u\n")-1, tgid);

    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
    if (!stats) return 0;
    stats->shm_unlink_calls++;
    return 0;
}

// --- mmap/munmap (Using Tracepoints) ---
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct trace_event_raw_sys_enter* ctx) {
    int flags_arg = (int)ctx->args[3];
    if (!(flags_arg & MAP_SHARED)) {
        return 0;
    }
    // u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("BPF_TP: enter_mmap (SHARED) TGID: %u, flags: 0x%x\n", sizeof("BPF_TP: enter_mmap (SHARED) TGID: %u, flags: 0x%x\n")-1, current_tgid, (u64)flags_arg);
    
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // We need tgid here to store comm if this is the first event for this tgid
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    get_or_init_tgid_stats_and_comm(tgid); // Ensure comm is stored if not already

    struct mmap_args_t args = {};
    args.len = (u64)ctx->args[1];
    args.flags = flags_arg;
    args.fd = (int)ctx->args[4];
    active_mmaps.update(&tid, &args);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_exit_mmap(struct trace_event_raw_sys_exit* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct mmap_args_t *entry_args = active_mmaps.lookup(&tid);
    if (!entry_args) return 0; 

    if (!(entry_args->flags & MAP_SHARED)) {
        active_mmaps.delete(&tid);
        return 0;
    }
    // u64 ret_val_u64 = (u64)ctx->ret;
    // bpf_trace_printk("BPF_TP: exit_mmap (SHARED) TGID: %u, ret: 0x%lx\n", sizeof("BPF_TP: exit_mmap (SHARED) TGID: %u, ret: 0x%lx\n")-1, tgid, ret_val_u64);
    
    if ((u64)ctx->ret != (u64)-1L) { // Check for MAP_FAILED directly
        struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid); // Ensure comm and get stats
        if (!stats) { active_mmaps.delete(&tid); return 0; }
        stats->mmap_shared_calls++;
        stats->total_mmap_shared_size_bytes += entry_args->len;
    }
    active_mmaps.delete(&tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_enter_munmap(struct trace_event_raw_sys_enter* ctx) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct shm_tgid_stats_t *stats = get_or_init_tgid_stats_and_comm(tgid);
    if (!stats) return 0;
    stats->munmap_shared_calls++;
    // bpf_trace_printk("BPF_TP: enter_munmap TGID: %u\n", sizeof("BPF_TP: enter_munmap TGID: %u\n")-1, tgid);
    return 0;
}
