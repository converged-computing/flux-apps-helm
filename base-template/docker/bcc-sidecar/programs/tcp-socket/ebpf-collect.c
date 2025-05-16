// ebpf-collect-tcp.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <uapi/linux/ptrace.h>


#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/err.h>

// Define network constants
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_TYPE
#define SO_TYPE 3
#endif
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif

// Define SEC macro
#ifndef SEC
# define SEC(name) __attribute__((section(name), used))
#endif

typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned int u32;
#define TASK_COMM_LEN_EBPF 16

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

enum event_type {
    EVENT_TCP_SEND = 0, EVENT_TCP_RECV = 1, EVENT_WRITE_SOCKET = 2,
    EVENT_READ_SOCKET = 3, EVENT_CONNECT = 4, EVENT_ACCEPT = 5,
    EVENT_SOCKET_CREATE = 6
};

struct data_t {
    u64 timestamp_ns; u32 tgid; u32 tid; u64 cgroup_id;
    char comm[TASK_COMM_LEN_EBPF]; enum event_type type; int fd;
    s64 bytes_count; u64 duration_ns;
};
BPF_RINGBUF_OUTPUT(events, 16);

struct call_entry_data_t { u64 start_ts; int fd; };
BPF_HASH(syscall_entry_info, u32, struct call_entry_data_t);

struct socket_state_t { u8 is_tcp; };
BPF_HASH(tracked_sockets, int, struct socket_state_t);

struct socket_args_t { int domain; int type; int protocol; };
BPF_HASH(active_socket_args, u32, struct socket_args_t);

SEC("tracepoint/syscalls/sys_enter_socket")
int tp_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct socket_args_t args_data = {};
    args_data.domain = (int)ctx->args[0]; args_data.type = (int)ctx->args[1];
    args_data.protocol = (int)ctx->args[2];
    active_socket_args.update(&tid, &args_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tp_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    int new_fd = (int)ctx->ret;
    if (new_fd < 0) { active_socket_args.delete(&tid); return 0; }
    struct socket_args_t *entry_args = active_socket_args.lookup(&tid);
    if (!entry_args) return 0;
    if ((entry_args->domain == AF_INET || entry_args->domain == AF_INET6) &&
        (entry_args->type & SOCK_STREAM) &&
        (entry_args->protocol == IPPROTO_TCP || entry_args->protocol == 0)) {
        struct socket_state_t sock_state = {.is_tcp = 1};
        tracked_sockets.update(&new_fd, &sock_state);
        struct data_t *event = events.ringbuf_reserve(sizeof(*event));
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
            event->cgroup_id = bpf_get_current_cgroup_id();
            bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
            event->type = EVENT_SOCKET_CREATE; event->fd = new_fd;
            event->bytes_count = 0; event->duration_ns = 0;
            events.ringbuf_submit(event, 0);
        }
    }
    active_socket_args.delete(&tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); int fd = (int)ctx->args[0];
    struct call_entry_data_t entry_data = {.start_ts = bpf_ktime_get_ns(), .fd = fd};
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tp_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    int ret = (int)ctx->ret;
    struct call_entry_data_t *entry = syscall_entry_info.lookup(&tid);
    if (!entry) return 0;
    int fd = entry->fd; u64 duration = bpf_ktime_get_ns() - entry->start_ts;
    syscall_entry_info.delete(&tid);
    if (ret == 0 || ret == -EINPROGRESS) {
        struct socket_state_t sock_state = {.is_tcp = 1};
        tracked_sockets.update(&fd, &sock_state);
    }
    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;
    event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
    event->type = EVENT_CONNECT; event->fd = fd; event->bytes_count = ret; event->duration_ns = duration;
    events.ringbuf_submit(event, 0);
    bpf_trace_printk("BPF_SUBMIT: CONNECT ev TID:%u FD:%d ret:%d\n",
                     tid, fd, ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tp_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    int new_client_fd = (int)ctx->ret;
    if (new_client_fd >= 0) {
        struct socket_state_t sock_state = {.is_tcp = 1};
        tracked_sockets.update(&new_client_fd, &sock_state);
        struct data_t *event = events.ringbuf_reserve(sizeof(*event));
        if (!event) return 0;
        event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
        event->cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
        event->type = EVENT_ACCEPT; event->fd = new_client_fd;
        event->bytes_count = 0; event->duration_ns = 0;
        events.ringbuf_submit(event, 0);
        bpf_trace_printk("BPF_SUBMIT: ACCEPT ev TID:%u newFD:%d\n",
                         tid, new_client_fd);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct trace_event_raw_sys_enter *ctx) {
    int fd_to_close = (int)ctx->args[0];
    tracked_sockets.delete(&fd_to_close);
    return 0;
}

static __always_inline int is_tracked_globally_tcp_socket(int fd) {
    struct socket_state_t *state = tracked_sockets.lookup(&fd);
    return (state && state->is_tcp);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); int fd = (int)ctx->args[0];
    if (!is_tracked_globally_tcp_socket(fd)) return 0;
    struct call_entry_data_t entry_data = {.start_ts = bpf_ktime_get_ns(), .fd = fd};
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tp_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    s64 bytes_sent = (s64)ctx->ret;
    struct call_entry_data_t *entry = syscall_entry_info.lookup(&tid);
    if (!entry || !is_tracked_globally_tcp_socket(entry->fd)) {
        if(entry) syscall_entry_info.delete(&tid); return 0;
    }
    u64 duration = bpf_ktime_get_ns() - entry->start_ts; int fd = entry->fd;
    syscall_entry_info.delete(&tid);
    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;
    event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
    event->type = EVENT_TCP_SEND; event->fd = fd; event->bytes_count = bytes_sent; event->duration_ns = duration;
    events.ringbuf_submit(event, 0);
    bpf_trace_printk("BPF_SUBMIT: SENDTO ev TID:%u FD:%d bytes:%lld\n",
                     tid, fd, bytes_sent);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); int fd = (int)ctx->args[0];
    if (!is_tracked_globally_tcp_socket(fd)) return 0;
    struct call_entry_data_t entry_data = {.start_ts = bpf_ktime_get_ns(), .fd = fd};
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    s64 bytes_recvd = (s64)ctx->ret;
    struct call_entry_data_t *entry = syscall_entry_info.lookup(&tid);
    if (!entry || !is_tracked_globally_tcp_socket(entry->fd)) {
        if(entry) syscall_entry_info.delete(&tid); return 0;
    }
    u64 duration = bpf_ktime_get_ns() - entry->start_ts; int fd = entry->fd;
    syscall_entry_info.delete(&tid);
    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;
    event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
    event->type = EVENT_TCP_RECV; event->fd = fd; event->bytes_count = bytes_recvd; event->duration_ns = duration;
    events.ringbuf_submit(event, 0);
    bpf_trace_printk("BPF_SUBMIT: RECVFROM ev TID:%u FD:%d bytes:%lld\n",
                     tid, fd, bytes_recvd);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); int fd = (int)ctx->args[0];
    if (!is_tracked_globally_tcp_socket(fd)) return 0;
    struct call_entry_data_t entry_data = {.start_ts = bpf_ktime_get_ns(), .fd = fd};
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_exit_write(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    s64 bytes_written = (s64)ctx->ret;
    struct call_entry_data_t *entry = syscall_entry_info.lookup(&tid);
    if (!entry || !is_tracked_globally_tcp_socket(entry->fd)) {
        if(entry) syscall_entry_info.delete(&tid); return 0;
    }
    u64 duration = bpf_ktime_get_ns() - entry->start_ts; int fd = entry->fd;
    syscall_entry_info.delete(&tid);
    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;
    event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
    event->type = EVENT_WRITE_SOCKET; event->fd = fd; event->bytes_count = bytes_written; event->duration_ns = duration;
    events.ringbuf_submit(event, 0);
    bpf_trace_printk("BPF_SUBMIT: WRITE ev TID:%u FD:%d bytes:%lld\n",
                     tid, fd, bytes_written);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid(); int fd = (int)ctx->args[0];
    if (!is_tracked_globally_tcp_socket(fd)) return 0;
    struct call_entry_data_t entry_data = {.start_ts = bpf_ktime_get_ns(), .fd = fd};
    syscall_entry_info.update(&tid, &entry_data);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid(); u32 tgid = id >> 32; u32 tid = (u32)id;
    s64 bytes_read = (s64)ctx->ret;
    struct call_entry_data_t *entry = syscall_entry_info.lookup(&tid);
    if (!entry || !is_tracked_globally_tcp_socket(entry->fd)) {
        if(entry) syscall_entry_info.delete(&tid); return 0;
    }
    u64 duration = bpf_ktime_get_ns() - entry->start_ts; int fd = entry->fd;
    syscall_entry_info.delete(&tid);
    struct data_t *event = events.ringbuf_reserve(sizeof(*event));
    if (!event) return 0;
    event->timestamp_ns = bpf_ktime_get_ns(); event->tgid = tgid; event->tid = tid;
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm)); event->comm[TASK_COMM_LEN_EBPF-1] = '\0';
    event->type = EVENT_READ_SOCKET; event->fd = fd; event->bytes_count = bytes_read; event->duration_ns = duration;
    events.ringbuf_submit(event, 0);
    bpf_trace_printk("BPF_SUBMIT: READ ev TID:%u FD:%d bytes:%lld\n",
                     tid, fd, bytes_read);
    return 0;
}

