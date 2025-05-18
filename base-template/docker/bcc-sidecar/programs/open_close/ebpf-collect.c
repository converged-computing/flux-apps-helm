#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_FILENAME_LEN_EBPF 256
#define TASK_COMM_LEN_EBPF 16
#define MAX_STAT_ENTRIES 10240      
#define MAX_ACTIVE_FDS   40960      

// --- Struct definitions ---
struct file_key_t {
    char filename[MAX_FILENAME_LEN_EBPF];
};

struct file_summary_t {
    u64 open_count;
    u64 close_count;
    u32 tgid;      
    char comm[TASK_COMM_LEN_EBPF]; 
    u64 cgroup_id; 
};

struct fd_key_t {
    u32 tgid; 
    int fd;   
};

// --- Maps definitions ---
BPF_HASH(temp_open_filenames, u64, struct file_key_t); 
BPF_HASH(active_fds_map, struct fd_key_t, struct file_key_t, MAX_ACTIVE_FDS);
BPF_HASH(file_stats_map, struct file_key_t, struct file_summary_t, MAX_STAT_ENTRIES);

// --- Scratch Space Maps ---
BPF_PERCPU_ARRAY(scratch_file_key, struct file_key_t, 1);
BPF_PERCPU_ARRAY(scratch_summary, struct file_summary_t, 1);


// --- Debug facilities ---
enum debug_stage {
    DBG_OPEN_ENTRY_START = 100, DBG_OPEN_ENTRY_READ_DONE = 101, DBG_OPEN_ENTRY_UPDATE_FAIL = 102,
    DBG_OPEN_RETURN_START = 200, DBG_OPEN_RETURN_LOOKUP_FAIL = 201, DBG_OPEN_RETURN_NO_KEY = 202,
    DBG_OPEN_RETURN_ACTIVE_FD_UPDATE_FAIL = 203, DBG_OPEN_RETURN_STATS_UPDATE_FAIL = 204,
    DBG_CLOSE_ENTRY_START = 300, DBG_CLOSE_ACTIVE_FD_LOOKUP_FAIL = 301, DBG_CLOSE_STATS_LOOKUP_FAIL = 302,
    DBG_CLOSE_STATS_UPDATE_FAIL = 303
};
struct debug_event_t { 
    u64 id; // Will store the pid_tgid_val
    enum debug_stage stage; 
    long val1; 
    long val2; 
    char SDBGa[16]; 
    char SDBGb[16]; 
};
BPF_RINGBUF_OUTPUT(debug_events_rb, 8); 

// Helper to submit debug events (to reduce boilerplate)
static __always_inline void submit_debug_event(u64 event_id, enum debug_stage stage, long v1, long v2, const char* s1, const char* s2) {
    struct debug_event_t *dbg = debug_events_rb.ringbuf_reserve(sizeof(struct debug_event_t));
    if (dbg) {
        dbg->id = event_id; dbg->stage = stage; dbg->val1 = v1; dbg->val2 = v2;
        if (s1) bpf_probe_read_kernel_str(&dbg->SDBGa, sizeof(dbg->SDBGa), s1); else dbg->SDBGa[0] = '\0';
        if (s2) bpf_probe_read_kernel_str(&dbg->SDBGb, sizeof(dbg->SDBGb), s2); else dbg->SDBGb[0] = '\0';
        debug_events_rb.ringbuf_submit(dbg, 0);
    }
}


TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid_val = bpf_get_current_pid_tgid(); // Renamed variable
    u32 zero = 0; 
    struct file_key_t *fk_scratch;

    // submit_debug_event(pid_tgid_val, DBG_OPEN_ENTRY_START, 0, 0, NULL, NULL);

    fk_scratch = scratch_file_key.lookup(&zero);
    if (!fk_scratch) {
        return 0; 
    }
    __builtin_memset(fk_scratch, 0, sizeof(struct file_key_t));

    const char __user *filename_ptr = (const char __user *)args->filename;
    long read_res = bpf_probe_read_user_str(&fk_scratch->filename, sizeof(fk_scratch->filename), (void *)filename_ptr);
    
    if (read_res <= 0 || read_res >= MAX_FILENAME_LEN_EBPF) { 
        // submit_debug_event(pid_tgid_val, DBG_OPEN_ENTRY_READ_DONE, read_res, 1, "READ_FAIL", NULL); 
        return 0; 
    }
    // submit_debug_event(pid_tgid_val, DBG_OPEN_ENTRY_READ_DONE, read_res, 0, fk_scratch->filename, NULL); 

    int ret = temp_open_filenames.update(&pid_tgid_val, fk_scratch); // Use pid_tgid_val as key
    // if (ret != 0) {
    //    submit_debug_event(pid_tgid_val, DBG_OPEN_ENTRY_UPDATE_FAIL, ret, 0, fk_scratch->filename, NULL);
    // }
    return 0;
}

int trace_openat_return_kretprobe(struct pt_regs *ctx) {
    u64 pid_tgid_val = bpf_get_current_pid_tgid(); // Renamed variable
    u32 tgid_val = pid_tgid_val >> 32;             // Extracted tgid
    int ret_fd = PT_REGS_RC(ctx);
    u32 zero = 0; 

    struct file_key_t *fk_val_ptr_from_temp; 
    struct file_key_t *fk_scratch;          
    struct file_summary_t *summary_scratch; 

    // submit_debug_event(pid_tgid_val, DBG_OPEN_RETURN_START, ret_fd, tgid_val, NULL, NULL);

    if (ret_fd < 0) { 
        temp_open_filenames.delete(&pid_tgid_val); 
        return 0;
    }

    fk_val_ptr_from_temp = temp_open_filenames.lookup(&pid_tgid_val);
    if (!fk_val_ptr_from_temp) {
        // submit_debug_event(pid_tgid_val, DBG_OPEN_RETURN_NO_KEY, ret_fd, 0, "NO_FK_PTR_TEMP", NULL);
        return 0; 
    }

    fk_scratch = scratch_file_key.lookup(&zero);
    if (!fk_scratch) { return 0; } 
    __builtin_memcpy(fk_scratch, fk_val_ptr_from_temp, sizeof(struct file_key_t));
    
    temp_open_filenames.delete(&pid_tgid_val); 

    struct fd_key_t afd_key = {.tgid = tgid_val, .fd = ret_fd}; // Use extracted tgid_val
    int ret = active_fds_map.update(&afd_key, fk_scratch); 
    // if (ret != 0) {
    //    submit_debug_event(pid_tgid_val, DBG_OPEN_RETURN_ACTIVE_FD_UPDATE_FAIL, ret, ret_fd, fk_scratch->filename, NULL);
    // }

    struct file_summary_t *summary_from_map = file_stats_map.lookup(fk_scratch); 
    
    summary_scratch = scratch_summary.lookup(&zero); 
    if (!summary_scratch) { return 0; } 

    if (summary_from_map) {
        __builtin_memcpy(summary_scratch, summary_from_map, sizeof(struct file_summary_t));
        summary_scratch->open_count++; 
        ret = file_stats_map.update(fk_scratch, summary_scratch); 
        // if (ret != 0) { submit_debug_event(pid_tgid_val, DBG_OPEN_RETURN_STATS_UPDATE_FAIL, ret, 1, fk_scratch->filename, "EXISTING"); }
    } else {
        __builtin_memset(summary_scratch, 0, sizeof(struct file_summary_t)); 
        summary_scratch->open_count = 1;
        summary_scratch->close_count = 0;
        summary_scratch->tgid = tgid_val; // Use extracted tgid_val
        bpf_get_current_comm(&summary_scratch->comm, sizeof(summary_scratch->comm));
        summary_scratch->comm[TASK_COMM_LEN_EBPF - 1] = '\0';
        summary_scratch->cgroup_id = bpf_get_current_cgroup_id(); 
        ret = file_stats_map.update(fk_scratch, summary_scratch); 
        // if (ret != 0) { submit_debug_event(pid_tgid_val, DBG_OPEN_RETURN_STATS_UPDATE_FAIL, ret, 0, fk_scratch->filename, "NEW"); }
    }
    return 0;
}

int trace_close_entry_kprobe(struct pt_regs *ctx, int fd_to_close) {
    u64 pid_tgid_val = bpf_get_current_pid_tgid(); // Renamed variable
    u32 tgid_val = pid_tgid_val >> 32;             // Extracted tgid
    u32 zero = 0;

    struct file_key_t *fk_val_ptr_from_active; 
    struct file_key_t *fk_scratch;           
    struct file_summary_t *summary_scratch;  

    // submit_debug_event(pid_tgid_val, DBG_CLOSE_ENTRY_START, fd_to_close, tgid_val, NULL, NULL);

    struct fd_key_t afd_key = {.tgid = tgid_val, .fd = fd_to_close}; // Use extracted tgid_val
    fk_val_ptr_from_active = active_fds_map.lookup(&afd_key);

    if (!fk_val_ptr_from_active) {
        // submit_debug_event(pid_tgid_val, DBG_CLOSE_ACTIVE_FD_LOOKUP_FAIL, fd_to_close, tgid_val, "NO_FK_PTR_active_fds", NULL);
        return 0;
    }

    fk_scratch = scratch_file_key.lookup(&zero);
    if (!fk_scratch) { return 0; } 
    __builtin_memcpy(fk_scratch, fk_val_ptr_from_active, sizeof(struct file_key_t));
    
    active_fds_map.delete(&afd_key); 

    struct file_summary_t *summary_from_map = file_stats_map.lookup(fk_scratch);
    if (summary_from_map) {
        summary_scratch = scratch_summary.lookup(&zero); 
        if (!summary_scratch) { return 0; }

        __builtin_memcpy(summary_scratch, summary_from_map, sizeof(struct file_summary_t)); 
        summary_scratch->close_count++; 
        int ret = file_stats_map.update(fk_scratch, summary_scratch); 
        // if (ret != 0) { submit_debug_event(pid_tgid_val, DBG_CLOSE_STATS_UPDATE_FAIL, ret, 0, fk_scratch->filename, NULL); }
    } else {
        // submit_debug_event(pid_tgid_val, DBG_CLOSE_STATS_LOOKUP_FAIL, fd_to_close, 0, fk_scratch->filename, "NO_SUMMARY_FOR_FILE");
    }
    return 0;
}
