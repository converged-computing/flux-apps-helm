#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// Do NOT include <linux/futex.h> here as it can cause compilation issues with BCC

// Define FUTEX constants directly in BPF C code
// These values are from standard Linux UAPI headers (e.g., <uapi/linux/futex.h>)
#ifndef FUTEX_WAIT
#define FUTEX_WAIT		0
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE		1
#endif
// Add other FUTEX_ op codes if we want to trace them, e.g.
// #ifndef FUTEX_LOCK_PI
// #define FUTEX_LOCK_PI		6
// #endif

// Flags for futex op
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG	128
#endif
#ifndef FUTEX_CLOCK_REALTIME
#define FUTEX_CLOCK_REALTIME	256 // Note: If this flag is set, the 'op' argument structure changes for timeout
#endif

// Mask to get the command part of the futex op
// FUTEX_CMD_MASK should correctly isolate the command part from flags.
// A common way to get the command is (op & 0x7F) or (op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))
// The definition of FUTEX_CMD_MASK here assumes we only care about private/realtime flags for masking.
// If other flags are present in the lower bits that are not part of the command, this might need adjustment.
// For simplicity, we often just check `(op & 0x7F) == FUTEX_WAIT` or `op == FUTEX_WAIT` or `op == FUTEX_WAIT_PRIVATE`.
// Let's use a simpler direct check for FUTEX_WAIT and FUTEX_WAIT_PRIVATE.
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#endif


#define TASK_COMM_LEN_EBPF 16

enum event_type {
    EVENT_FUTEX_WAIT_COMPLETED = 0,
};

struct data_t {
    u64 timestamp_ns;
    u32 tgid;
    u32 tid;
    // u32 ppid; // Add back if needed and fetched in BPF
    u64 cgroup_id;
    char comm[TASK_COMM_LEN_EBPF];
    enum event_type type;
    int futex_op_full;      // The original futex op argument (including flags)
    u64 wait_duration_ns;
};
BPF_RINGBUF_OUTPUT(events, 8);

BPF_HASH(futex_start_times, u32, u64); // Key: TID, Value: Start timestamp
BPF_HASH(futex_ops_temp, u32, int);    // Key: TID, Value: Original futex_op_full from enter


// --- Debugging (Optional) ---
enum debug_stage {
    DBG_FUTEX_ENTER_TRACKING = 400,
    DBG_FUTEX_ENTER_NOT_TRACKING = 401,
    DBG_FUTEX_EXIT_FOUND_START = 402,
    DBG_FUTEX_EXIT_NO_START = 403,
    DBG_FUTEX_SUBMITTED = 404,
    DBG_FUTEX_RESERVE_FAIL = 405
};
struct debug_event_t {
    u32 id_tid; // Using u32 for TID
    enum debug_stage stage;
    long val1_op;
    long val2_duration_or_misc;
};
BPF_RINGBUF_OUTPUT(debug_events_rb, 4);

static __always_inline void send_futex_debug_event(u32 current_tid, enum debug_stage stage, long v1, long v2) {
    struct debug_event_t *dbg_evt = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg_evt) {
        dbg_evt->id_tid = current_tid;
        dbg_evt->stage = stage;
        dbg_evt->val1_op = v1;
        dbg_evt->val2_duration_or_misc = v2;
        debug_events_rb.ringbuf_submit(dbg_evt, 0);
    }
}
// --- End Debugging ---

TRACEPOINT_PROBE(syscalls, sys_enter_futex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    // 'args->op' is how BCC TRACEPOINT_PROBE typically exposes tracepoint arguments
    // that match the 'op' field in /sys/kernel/debug/tracing/events/syscalls/sys_enter_futex/format
    int futex_op_full = args->op;
    int futex_op_cmd = futex_op_full & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME); // Get command part

    // We are interested in FUTEX_WAIT or FUTEX_WAIT_PRIVATE
    if (futex_op_cmd == FUTEX_WAIT) {
        u64 start_time_ns = bpf_ktime_get_ns();
        futex_start_times.update(&tid, &start_time_ns);
        futex_ops_temp.update(&tid, &futex_op_full); // Store the original op
        // send_futex_debug_event(tid, DBG_FUTEX_ENTER_TRACKING, futex_op_full, 0);
    } else {
        // send_futex_debug_event(tid, DBG_FUTEX_ENTER_NOT_TRACKING, futex_op_full, 0);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    u64 *start_time_ns_ptr;
    start_time_ns_ptr = futex_start_times.lookup(&tid);

    if (start_time_ns_ptr) {
        u64 end_time_ns = bpf_ktime_get_ns();
        u64 duration_ns = end_time_ns - *start_time_ns_ptr;
        
        int *original_op_ptr = futex_ops_temp.lookup(&tid);
        int original_op = -1; // Default if not found (shouldn't happen if start_time was found)
        if (original_op_ptr) {
            original_op = *original_op_ptr;
        }

        futex_start_times.delete(&tid);
        futex_ops_temp.delete(&tid);

        // send_futex_debug_event(tid, DBG_FUTEX_EXIT_FOUND_START, original_op, duration_ns);

        struct data_t *event_data_ptr = events.ringbuf_reserve(sizeof(*event_data_ptr));
        if (!event_data_ptr) {
            // send_futex_debug_event(tid, DBG_FUTEX_RESERVE_FAIL, original_op, 0);
            return 0;
        }

        event_data_ptr->timestamp_ns = end_time_ns;
        event_data_ptr->tgid = tgid;
        event_data_ptr->tid = tid;
        event_data_ptr->cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&event_data_ptr->comm, sizeof(event_data_ptr->comm));
        event_data_ptr->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
        event_data_ptr->type = EVENT_FUTEX_WAIT_COMPLETED;
        event_data_ptr->futex_op_full = original_op;
        event_data_ptr->wait_duration_ns = duration_ns;

        events.ringbuf_submit(event_data_ptr, 0);
        // send_futex_debug_event(tid, DBG_FUTEX_SUBMITTED, original_op, duration_ns);

    } else {
         // send_futex_debug_event(tid, DBG_FUTEX_EXIT_NO_START, args->ret, 0); // args->ret is syscall return
    }
    return 0;
}

