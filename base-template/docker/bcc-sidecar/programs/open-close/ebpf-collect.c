#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_FILENAME_LEN_EBPF 256
#define TASK_COMM_LEN_EBPF 16

enum event_type { EVENT_OPEN = 0, EVENT_CLOSE = 1 };

struct data_t {
    u64 timestamp_ns; 
    u32 ppid;      
    u32 tgid; // 'pid' is actually 'tgid' for clarity (Thread Group ID / Process ID)
    u32 tid;  // Thread ID (kernel's PID)
    u64 cgroup_id;
    char comm[TASK_COMM_LEN_EBPF];
    enum event_type type; 
    char filename[MAX_FILENAME_LEN_EBPF];
    int fd; 
    int ret_val;
};
BPF_RINGBUF_OUTPUT(events, 8);

struct temp_filename_t { char fname[MAX_FILENAME_LEN_EBPF]; };
BPF_HASH(open_filenames_map, u64, struct temp_filename_t);

enum debug_stage {
    DBG_OPEN_ENTRY_START = 100, DBG_OPEN_ENTRY_READ_DONE = 101,
    DBG_OPEN_RETURN_START = 200, DBG_OPEN_RETURN_LOOKUP_DONE = 201,
};
struct debug_event_t { u64 id; enum debug_stage stage; long val1; long val2; };
BPF_RINGBUF_OUTPUT(debug_events_rb, 4);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct temp_filename_t temp_fn_data = {};
    long read_res = 0;
    const char __user *filename_ptr_from_args = (const char __user *)args->filename;

    struct debug_event_t *dbg_evt = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg_evt) {
        dbg_evt->id = id; dbg_evt->stage = DBG_OPEN_ENTRY_START;
        dbg_evt->val1 = 0; dbg_evt->val2 = 0;
        debug_events_rb.ringbuf_submit(dbg_evt, 0);
    }

    read_res = bpf_probe_read_user_str(&temp_fn_data.fname, sizeof(temp_fn_data.fname), (void *)filename_ptr_from_args);

    dbg_evt = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg_evt) {
        dbg_evt->id = id; dbg_evt->stage = DBG_OPEN_ENTRY_READ_DONE;
        dbg_evt->val1 = read_res; dbg_evt->val2 = (read_res > 0) ? 1 : 0;
        debug_events_rb.ringbuf_submit(dbg_evt, 0);
    }
    
    if (read_res <= 0) { return 0; }
    temp_fn_data.fname[MAX_FILENAME_LEN_EBPF - 1] = '\0'; // CORRECTED
    open_filenames_map.update(&id, &temp_fn_data);
    return 0;
}

int trace_openat_return_kretprobe(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid(); // full 64-bit ID
    u32 tgid = id >> 32;                 // upper 32 bits is TGID
    u32 tid = (u32)id;                   // lower 32 bits is TID (kernel's PID)
    int ret_fd = PT_REGS_RC(ctx);

    struct temp_filename_t *temp_fn_ptr = NULL;
    long lookup_success = 0;

    struct debug_event_t *dbg_evt = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg_evt) {
        dbg_evt->id = id; dbg_evt->stage = DBG_OPEN_RETURN_START;
        dbg_evt->val1 = ret_fd; dbg_evt->val2 = 0;
        debug_events_rb.ringbuf_submit(dbg_evt, 0);
    }

    if (ret_fd < 0) {
        open_filenames_map.delete(&id);
        return 0;
    }

    temp_fn_ptr = open_filenames_map.lookup(&id);
    lookup_success = (temp_fn_ptr != NULL) ? 1 : 0;

    dbg_evt = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg_evt) {
        dbg_evt->id = id; dbg_evt->stage = DBG_OPEN_RETURN_LOOKUP_DONE;
        dbg_evt->val1 = ret_fd; dbg_evt->val2 = lookup_success;
        debug_events_rb.ringbuf_submit(dbg_evt, 0);
    }

    if (!temp_fn_ptr) { return 0; }

    struct data_t *event_data_ptr = events.ringbuf_reserve(sizeof(struct data_t));
    if (!event_data_ptr) {
        open_filenames_map.delete(&id);
        return 0;
    }
    event_data_ptr->timestamp_ns = bpf_ktime_get_ns();
    event_data_ptr->tgid = tgid; 
    event_data_ptr->tid  = tid; 
    bpf_get_current_comm(&event_data_ptr->comm, sizeof(event_data_ptr->comm));
    event_data_ptr->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event_data_ptr->type = EVENT_OPEN;
    event_data_ptr->fd = ret_fd;
    event_data_ptr->ret_val = ret_fd;
    __builtin_memcpy(event_data_ptr->filename, temp_fn_ptr->fname, MAX_FILENAME_LEN_EBPF);
    event_data_ptr->filename[MAX_FILENAME_LEN_EBPF - 1] = '\0';
    events.ringbuf_submit(event_data_ptr, 0);
    //open_filenames_map.delete(&id);
    return 0;
}

int trace_close_entry_kprobe(struct pt_regs *ctx, int fd_to_close) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;                 
    u32 tid = (u32)id;                  
    
    struct data_t *event_data_ptr = events.ringbuf_reserve(sizeof(struct data_t));
    if (!event_data_ptr) { return 0; }
    event_data_ptr->timestamp_ns = bpf_ktime_get_ns();
    event_data_ptr->tgid = tgid; 
    event_data_ptr->tid  = tid; 

    // Read parent's TGID carefully
    u64 cgroup_id = bpf_get_current_cgroup_id();
    struct task_struct *real_parent_task = NULL;
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();    
    int res = bpf_probe_read_kernel(&real_parent_task, sizeof(real_parent_task), &current_task->real_parent);
    if (res == 0 && real_parent_task != NULL) { 
        bpf_probe_read_kernel(&event_data_ptr->ppid, sizeof(event_data_ptr->ppid), &real_parent_task->tgid);
    } else {
        // Error or no parent found this way
        event_data_ptr->ppid = 0; 
    }

    struct temp_filename_t *temp_fn_ptr = NULL;
    temp_fn_ptr = open_filenames_map.lookup(&id);
    if (!temp_fn_ptr) { 
        events.ringbuf_discard(event_data_ptr, 0);
        return 0; 
    }

    bpf_get_current_comm(&event_data_ptr->comm, sizeof(event_data_ptr->comm));
    event_data_ptr->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
    event_data_ptr->type = EVENT_CLOSE;
    event_data_ptr->fd = fd_to_close;
    //event_data_ptr->filename[0] = '\0';
    __builtin_memcpy(event_data_ptr->filename, temp_fn_ptr->fname, MAX_FILENAME_LEN_EBPF);
    event_data_ptr->filename[MAX_FILENAME_LEN_EBPF - 1] = '\0';    
    event_data_ptr->ret_val = 0;
    event_data_ptr->cgroup_id = cgroup_id;
    events.ringbuf_submit(event_data_ptr, 0);
    open_filenames_map.delete(&id);
    return 0;
}
