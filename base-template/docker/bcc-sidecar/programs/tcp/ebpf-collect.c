// ebpf-collect-tcp-v2.c

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN_EBPF 16

enum event_type {
    EVENT_TCP_SEND = 0,
    EVENT_TCP_RECV = 1,
    EVENT_WRITE = 2,
    EVENT_READ = 3,
};

struct data_t {
    u64 timestamp_ns;
    u32 tgid;
    u32 tid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN_EBPF];
    enum event_type type;
    int fd;
    // Can be -1 on error, or bytes transferred
    s64 bytes_count;
    u64 duration_ns;
};
BPF_RINGBUF_OUTPUT(events, 16); // Ring buffer for events

// Common map to store entry data for syscalls (fd and start time)
struct call_entry_data_t {
    u64 start_ts;
    int fd;
    // You could add more here if needed, e.g., buffer pointer or count for write/read
    // size_t count_arg; // For write/read, this is the 'count' argument
};
BPF_HASH(syscall_entry_info, u32, struct call_entry_data_t); // Key: TID


// --- sendto/recvfrom (Original) ---
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct call_entry_data_t entry_data = {};
    entry_data.start_ts = bpf_ktime_get_ns();
    entry_data.fd = args->fd; 
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_sent = args->ret; // Return value of sendto is bytes sent or -errno

    struct call_entry_data_t *entry_data_ptr = syscall_entry_info.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_info.delete(&tid);

    if (bytes_sent < 0) return 0; // Don't submit errors for now, or handle them differently

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns(); // Or entry_data_ptr->start_ts for start time
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_TCP_SEND; // Still classifying as generic SEND
    event->fd = fd;
    event->bytes_count = bytes_sent;
    event->duration_ns = duration_ns;
    events.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct call_entry_data_t entry_data = {};
    entry_data.start_ts = bpf_ktime_get_ns();
    entry_data.fd = args->fd;
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_recvd = args->ret;

    struct call_entry_data_t *entry_data_ptr = syscall_entry_info.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_info.delete(&tid);

    if (bytes_recvd < 0) return 0;

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_TCP_RECV; // Still classifying as generic RECV
    event->fd = fd;
    event->bytes_count = bytes_recvd;
    event->duration_ns = duration_ns;
    events.ringbuf_submit(event, 0);
    return 0;
}

// --- ADDED: write syscall ---
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct call_entry_data_t entry_data = {};
    entry_data.start_ts = bpf_ktime_get_ns();
    entry_data.fd = args->fd; // First arg to write is fd
    // entry_data.count_arg = args->count; // Third arg to write is count (bytes to write)
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_written = args->ret; // Return value of write is bytes written or -errno

    struct call_entry_data_t *entry_data_ptr = syscall_entry_info.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_info.delete(&tid);

    if (bytes_written < 0) return 0; // Don't submit errors for now

    // HERE: Add logic to check if 'fd' is a socket you care about.
    // This is the hard part. For now, we submit all successful writes.
    // User-space will have to filter based on FD or comm if it's noisy.

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_WRITE; // New event type
    event->fd = fd;
    event->bytes_count = bytes_written;
    event->duration_ns = duration_ns;
    events.ringbuf_submit(event, 0);
    return 0;
}


// --- ADDED: read syscall ---
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct call_entry_data_t entry_data = {};
    entry_data.start_ts = bpf_ktime_get_ns();
    entry_data.fd = args->fd; // First arg to read is fd
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_read = args->ret; // Return value of read is bytes read or -errno

    struct call_entry_data_t *entry_data_ptr = syscall_entry_info.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_info.delete(&tid);

    if (bytes_read < 0) return 0;

    // HERE: Add logic to check if 'fd' is a socket you care about.

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_READ; // New event type
    event->fd = fd;
    event->bytes_count = bytes_read;
    event->duration_ns = duration_ns;
    events.ringbuf_submit(event, 0);
    return 0;
}
