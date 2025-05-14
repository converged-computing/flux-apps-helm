#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// Don't include <linux/socket.h> etc. in BPF
// to avoid potential BCC compilation issues with full kernel headers.

#define TASK_COMM_LEN_EBPF 16

enum event_type {
    EVENT_TCP_SEND = 0, // Generic send
    EVENT_TCP_RECV = 1, // Generic recv
};

struct data_t {
    u64 timestamp_ns;
    u32 tgid;
    u32 tid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN_EBPF];
    enum event_type type;
    int fd;
    s64 bytes_count; // Can be -1 on error
    u64 duration_ns;
};
BPF_RINGBUF_OUTPUT(events, 16);

struct call_entry_data_t {
    u64 start_ts;
    int fd;
};
BPF_HASH(syscall_entry_times, u32, struct call_entry_data_t);

enum debug_stage {
    DBG_SEND_ENTER = 500, DBG_SEND_EXIT = 501,
    DBG_RECV_ENTER = 502, DBG_RECV_EXIT = 503,
    DBG_SUBMITTED = 504, DBG_RESERVE_FAIL = 505,
    DBG_NO_ENTRY_INFO = 506
};
struct debug_event_t {
    u32 id_tid;
    enum debug_stage stage;
    long val1_fd_or_bytes;
    long val2_duration_or_ret;
};
BPF_RINGBUF_OUTPUT(debug_events_rb, 4);

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct call_entry_data_t entry_data = {};
    entry_data.start_ts = bpf_ktime_get_ns();
    entry_data.fd = args->fd; // BCC provides args->fd for sendto fd
    syscall_entry_times.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_sent = args->ret;

    struct call_entry_data_t *entry_data_ptr = syscall_entry_times.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_times.delete(&tid);

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_TCP_SEND;
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
    entry_data.fd = args->fd; // BCC provides args->fd for recvfrom fd
    syscall_entry_times.update(&tid, &entry_data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    s64 bytes_recvd = args->ret;

    struct call_entry_data_t *entry_data_ptr = syscall_entry_times.lookup(&tid);
    if (!entry_data_ptr) return 0;

    u64 duration_ns = bpf_ktime_get_ns() - entry_data_ptr->start_ts;
    int fd = entry_data_ptr->fd;
    syscall_entry_times.delete(&tid);

    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event->type = EVENT_TCP_RECV;
    event->fd = fd;
    event->bytes_count = bytes_recvd;
    event->duration_ns = duration_ns;
    events.ringbuf_submit(event, 0);
    return 0;
}

