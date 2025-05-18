// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#ifndef SEC
# define SEC(name) __attribute__((section(name), used))
#endif

// --- Standard BPF type definitions ---
// These are usually provided by <linux/bpf.h> or libbpf's bpf_helpers.h
// I was getting errors (I think BCC handles) so adding them manually.
typedef unsigned long long u64;
typedef unsigned int u32;
// Use u32 for PIDs/TIDs in BPF maps for consistency and common practice.
// Kernel's pid_t is usually 'int'.
typedef u32 pid_t_bpf;

#define TASK_COMM_LEN 16

// Max entries for hash maps
// I made this really big because default was slowing down apps
#define MAX_MAP_ENTRIES 10240

// --- Data structure for aggregated stats in the BPF map ---
struct task_aggr_stats {
    u64 total_on_cpu_ns;
    u64 total_runq_latency_ns;
    // Number of times task was scheduled out (completed a CPU burst)
    u64 on_cpu_count;
    // Number of times task experienced runqueue latency
    u64 runq_count;
};

// --- Tracepoint context structures (ensure these match the kernel) ---
// For BCC, these are often implicitly handled or can be derived.
// For libbpf, use CO-RE with vmlinux.h.
struct trace_event_raw_sched_switch {
    unsigned long long __unused_header;
    char prev_comm[TASK_COMM_LEN];
    int prev_pid; // Kernel's pid_t
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    int next_pid; // Kernel's pid_t
    int next_prio;
};

struct trace_event_raw_sched_wakeup {
    unsigned long long __unused_header;
    char comm[TASK_COMM_LEN];
    int pid; // Kernel's pid_t
    int prio;
    int success;
    int target_cpu;
};

// --- BPF Map Definitions ---

// Stores the timestamp when a task was last scheduled IN.
// Key: TID (Thread ID, which is kernel's PID). Value: Timestamp (ns).
BPF_HASH(task_scheduled_in_ts, pid_t_bpf, u64, MAX_MAP_ENTRIES);

// Stores the timestamp when a task was last woken up.
// Key: TID. Value: Timestamp (ns).
BPF_HASH(task_wakeup_ts, pid_t_bpf, u64, MAX_MAP_ENTRIES);

// Stores aggregated CPU metrics per task (TID).
// This is a PERCPU hash map. User-space sums values for a key across all CPUs.
// Key: TID. Value: struct task_aggr_stats.
BPF_PERCPU_HASH(aggregated_task_stats, pid_t_bpf, struct task_aggr_stats, MAX_MAP_ENTRIES);


// --- BPF Program Functions ---

SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx) {
    pid_t_bpf tid = (pid_t_bpf)ctx->pid;
    u64 ts = bpf_ktime_get_ns();
    // Update will insert if key doesn't exist, or overwrite if it does.
    task_wakeup_ts.update(&tid, &ts);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int tp_sched_wakeup_new(struct trace_event_raw_sched_wakeup *ctx) {
    pid_t_bpf tid = (pid_t_bpf)ctx->pid;
    u64 ts = bpf_ktime_get_ns();
    task_wakeup_ts.update(&tid, &ts);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 current_ts = bpf_ktime_get_ns();
    pid_t_bpf prev_tid = (pid_t_bpf)ctx->prev_pid;
    pid_t_bpf next_tid = (pid_t_bpf)ctx->next_pid;
    u64 *scheduled_in_ts_ptr;
    u64 *wakeup_ts_ptr;
    struct task_aggr_stats *stats_ptr;

    // --- Handle previous task switching out (prev_tid) ---
    scheduled_in_ts_ptr = task_scheduled_in_ts.lookup(&prev_tid);
    if (scheduled_in_ts_ptr) {
        u64 on_cpu_duration = current_ts - *scheduled_in_ts_ptr;
        // Basic sanity check for duration (e.g. against time warps)
        if ((s64)on_cpu_duration >= 0) {
            stats_ptr = aggregated_task_stats.lookup(&prev_tid);
            if (stats_ptr) {
                stats_ptr->total_on_cpu_ns += on_cpu_duration;
                stats_ptr->on_cpu_count += 1;
            } else {
                // First time this CPU sees this TID for aggregation, or entry was cleared.
                // BPF_PERCPU_HASH.update will create/initialize if necessary.
                struct task_aggr_stats new_stats = {0};
                new_stats.total_on_cpu_ns = on_cpu_duration;
                new_stats.on_cpu_count = 1;
                aggregated_task_stats.update(&prev_tid, &new_stats);
            }
        }
        task_scheduled_in_ts.delete(&prev_tid); // Clean up timestamp
    }

    // --- Handle next task switching in (next_tid) ---
    // Record that next_tid is now on CPU by storing its start timestamp.
    // The value needs to be on the stack or globally accessible for update.
    u64 current_ts_val = current_ts;
    task_scheduled_in_ts.update(&next_tid, &current_ts_val);

    // Calculate runqueue latency for the task switching in.
    wakeup_ts_ptr = task_wakeup_ts.lookup(&next_tid);
    if (wakeup_ts_ptr) {
        u64 runq_latency = current_ts - *wakeup_ts_ptr;

        // Basic sanity check
        if ((s64)runq_latency >= 0) {
            stats_ptr = aggregated_task_stats.lookup(&next_tid);
            if (stats_ptr) {
                stats_ptr->total_runq_latency_ns += runq_latency;
                stats_ptr->runq_count += 1;
            } else {
                struct task_aggr_stats new_stats = {0};
                new_stats.total_runq_latency_ns = runq_latency;
                new_stats.runq_count = 1;
                aggregated_task_stats.update(&next_tid, &new_stats);
            }
        }
        task_wakeup_ts.delete(&next_tid); // Clean up timestamp
    }
    return 0;
}