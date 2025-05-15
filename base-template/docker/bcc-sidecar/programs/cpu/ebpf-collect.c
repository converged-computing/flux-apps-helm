// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

// Define SEC macro because got error and not provided by BCC
#ifndef SEC
# define SEC(name) __attribute__((section(name), used))
#endif

// Basic types, another import error...
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
// pid_t is usually defined by system headers included by BCC

#define TASK_COMM_LEN 16

// --- Manually defined tracepoint context structures (from your original script) ---
struct trace_event_raw_sched_switch {
    unsigned long long __unused_header;
    char prev_comm[TASK_COMM_LEN];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    pid_t next_pid;
    int next_prio;
};

struct trace_event_raw_sched_wakeup {
    unsigned long long __unused_header;
    char comm[TASK_COMM_LEN];
    pid_t pid;
    int prio;
    int success;
    int target_cpu;
};

// Event types sent to user-space
#define EVENT_TYPE_SCHED_STATS 1

// Data structure for events sent to user-space
struct sched_event_data {
    u64 timestamp_ns;
    u32 tgid;
    u32 tid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    u64 on_cpu_ns;
    u64 runq_latency_ns;
    u8 event_type;
    u8 prev_state_task_switched_out;
};

// --- BCC Style Map Definitions ---
BPF_HASH(task_scheduled_in_ts, pid_t, u64, 10240);
BPF_HASH(task_wakeup_ts, pid_t, u64, 10240);

// Use BCC's perf output mechanism
BPF_PERF_OUTPUT(events_out);


// --- BPF Program Functions ---

SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx) {
    pid_t tid = ctx->pid;
    u64 ts = bpf_ktime_get_ns();
    task_wakeup_ts.update(&tid, &ts);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int tp_sched_wakeup_new(struct trace_event_raw_sched_wakeup *ctx) {
    pid_t tid = ctx->pid;
    u64 ts = bpf_ktime_get_ns();
    task_wakeup_ts.update(&tid, &ts);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 current_ts = bpf_ktime_get_ns();
    pid_t prev_tid = ctx->prev_pid;
    pid_t next_tid = ctx->next_pid;
    // This initializes to zero
    struct sched_event_data data = {}; 
    u64 *scheduled_in_ts_ptr;
    u64 *wakeup_ts_ptr;

    // --- Handle previous task switching out ---
    scheduled_in_ts_ptr = task_scheduled_in_ts.lookup(&prev_tid);

    if (scheduled_in_ts_ptr) {
        u64 on_cpu_duration = current_ts - *scheduled_in_ts_ptr;
        task_scheduled_in_ts.delete(&prev_tid);

        data.timestamp_ns = current_ts;
        data.tgid = prev_tid; // Note: This is TID
        data.tid = prev_tid;

        for (int i = 0; i < TASK_COMM_LEN; ++i) {
            data.comm[i] = ctx->prev_comm[i];
            if (ctx->prev_comm[i] == '\0') break;
        }
        data.comm[TASK_COMM_LEN - 1] = '\0';

        data.cgroup_id = bpf_get_current_cgroup_id();
        data.on_cpu_ns = on_cpu_duration;
        data.runq_latency_ns = 0;
        data.event_type = EVENT_TYPE_SCHED_STATS;
        data.prev_state_task_switched_out = (u8)ctx->prev_state;
        
        events_out.perf_submit(ctx, &data, sizeof(data));
    }

    // --- Handle next task switching in ---
    u64 current_ts_val = current_ts;
    task_scheduled_in_ts.update(&next_tid, &current_ts_val);

    wakeup_ts_ptr = task_wakeup_ts.lookup(&next_tid);
    if (wakeup_ts_ptr) {
        u64 runq_latency = current_ts - *wakeup_ts_ptr;
        task_wakeup_ts.delete(&next_tid);
        
        struct sched_event_data data_next = {};
        data_next.timestamp_ns = current_ts;
        data_next.tgid = next_tid; // Note: This is TID
        data_next.tid = next_tid;

        for (int i = 0; i < TASK_COMM_LEN; ++i) {
            data_next.comm[i] = ctx->next_comm[i];
            if (ctx->next_comm[i] == '\0') break;
        }
        data_next.comm[TASK_COMM_LEN - 1] = '\0';

        data_next.cgroup_id = bpf_get_current_cgroup_id();
        data_next.on_cpu_ns = 0;
        data_next.runq_latency_ns = runq_latency;
        data_next.event_type = EVENT_TYPE_SCHED_STATS;
        data_next.prev_state_task_switched_out = 0;

        events_out.perf_submit(ctx, &data_next, sizeof(data_next));
    }
    return 0;
}
