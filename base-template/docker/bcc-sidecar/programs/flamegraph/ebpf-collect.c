#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h> // For TASK_COMM_LEN

// This will be populated by the python script
INSERT_COMMAND_HERE

BPF_STACK_TRACE(stack_traces, 32768);

struct SKey {
    int kstack_id;
    int ustack_id;
    u32 tgid;
    char comm[TASK_COMM_LEN]; // Storing comm in key is good for python side, even if filtered in BPF
};
BPF_HASH(counts_ext, struct SKey, u64);

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u64 zero = 0, *val;
    u32 tgid_current = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    char current_comm[TASK_COMM_LEN];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));

#ifdef FILTER_PID
    if (tgid_current != FILTER_PID) {
        return 0;
    }
#elif defined(FILTER_COMM_NAME) // Note: FILTER_PID takes precedence if both somehow defined
    // Perform string comparison for comm name
    // This is a direct fixed-length comparison.
    // Ensure FILTER_COMM_NAME is null-terminated or handle length carefully.
    char target_comm[FILTER_COMM_LEN + 1] = FILTER_COMM_NAME; // +1 for null if needed from define
    for (int i = 0; i < FILTER_COMM_LEN; ++i) {
        if (current_comm[i] != target_comm[i]) {
            return 0; // Mismatch
        }
    }
#endif

    struct SKey key = {};
    key.tgid = tgid_current;
    // We still store the comm in the key for the Python side, even if filtered.
    // This ensures the Python side knows the comm for file naming.
    __builtin_memcpy(key.comm, current_comm, TASK_COMM_LEN);

    key.kstack_id = -1;
    key.ustack_id = -1;

#ifndef USER_ONLY
    key.kstack_id = stack_traces.get_stackid(&ctx->regs, 0);
#endif

#ifndef KERNEL_ONLY
    if (ctx->sample_period != 0) {
         key.ustack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
    }
#endif

    if (key.kstack_id < 0 && key.ustack_id < 0) return 0;
    
    #if defined(USER_ONLY)
        if (key.ustack_id < 0) return 0;
    #elif defined(KERNEL_ONLY)
        if (key.kstack_id < 0) return 0;
    #endif

    val = counts_ext.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
