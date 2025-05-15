from bcc import BPF
import ctypes as ct
import time
import os
import traceback
import signal
import json
import sys

# Should match C code
TASK_COMM_LEN = 16  # This is used for the new comm_arr_t as well

running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__))


class ShmTgidStats(ct.Structure):
    _fields_ = [
        # SysV
        ("shmget_calls", ct.c_ulonglong),
        ("shmget_success", ct.c_ulonglong),
        ("shmat_calls", ct.c_ulonglong),
        ("shmdt_calls", ct.c_ulonglong),
        ("shmctl_rmid_calls", ct.c_ulonglong),
        ("total_shmget_size_bytes", ct.c_ulonglong),
        # POSIX
        ("shm_open_calls", ct.c_ulonglong),
        ("shm_open_success", ct.c_ulonglong),
        ("shm_unlink_calls", ct.c_ulonglong),
        ("mmap_shared_calls", ct.c_ulonglong),
        ("munmap_shared_calls", ct.c_ulonglong),
        ("total_mmap_shared_size_bytes", ct.c_ulonglong),
    ]


# --- NEW CTYPES STRUCT for comm_arr_t ---
class CommArr(ct.Structure):
    _fields_ = [("comm", ct.c_char * TASK_COMM_LEN)]


# --- Functions (from your script, largely unchanged but using globals carefully) ---
def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def collect_trace(
    start_indicator_file=None,
    stop_indicator_file=None,
    output_as_table=True,
    debug_flag=False,
):
    global running, as_table  # Ensure these globals are modified

    as_table = output_as_table  # Set based on argument
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    print("Initializing eBPF for Shared Memory monitoring...")
    bpf_instance = None  # For finally block
    try:
        # Use the globally loaded bpf_text_content
        bpf_instance = BPF(text=bpf_text, debug=0)
        print("BPF C code compiled and loaded.")

        if start_indicator_file is not None:
            helpers.log(
                f"\nStart Indicator file defined '{start_indicator_file}'. Waiting."
            )
            while running and not os.path.exists(start_indicator_file):
                time.sleep(0.5)
            if not running:
                helpers.log("Stopped while waiting for start.")
                return
            helpers.log("Start indicator found. Proceeding.")

        # Explicitly attach tracepoints (as in your previous script)
        print("Attaching tracepoints...")
        tracepoint_syscalls = ["shmget", "shmat", "shmdt", "shmctl", "mmap", "munmap"]
        has_exit_handler = {"shmget", "mmap"}
        for syscall in tracepoint_syscalls:
            enter_fn_name = f"trace_enter_{syscall}"
            exit_fn_name = f"trace_exit_{syscall}"
            try:
                bpf_instance.attach_tracepoint(
                    tp=f"syscalls:sys_enter_{syscall}", fn_name=enter_fn_name
                )
                # print(f"  Attached TP syscalls:sys_enter_{syscall} to {enter_fn_name}")
            except Exception as e:
                print(f"  WARNING: Failed to attach TP sys_enter_{syscall}: {e}")
            if syscall in has_exit_handler:
                try:
                    bpf_instance.attach_tracepoint(
                        tp=f"syscalls:sys_exit_{syscall}", fn_name=exit_fn_name
                    )
                    # print(f"  Attached TP syscalls:sys_exit_{syscall} to {exit_fn_name}")
                except Exception as e:
                    print(f"  WARNING: Failed to attach TP sys_exit_{syscall}: {e}")
        print("  Kprobes for shm_open/shm_unlink should auto-attach if symbols exist.")
        print("Finished attaching probes.")

        if debug_flag:
            print(
                "Check kernel trace pipe for BPF messages: sudo cat /sys/kernel/debug/tracing/trace_pipe\n"
            )

        interval_s = 5
        while running:
            time.sleep(interval_s)
            if not running:
                break
            print(
                f"\n--- Shared Memory Stats Summary at {time.strftime('%H:%M:%S')} ---"
            )

            proc_stats_map = bpf_instance.get_table("proc_shm_stats")
            tgid_comm_map = bpf_instance.get_table(
                "tgid_to_comm"
            )  # <<< GET THE NEW COMM MAP
            current_map_items = list(proc_stats_map.items())

            if not current_map_items and as_table:
                print("No data collected in proc_shm_stats map yet.")
                if stop_indicator_file and os.path.exists(stop_indicator_file):
                    running = False
                if not running:
                    break
                continue

            display_data = []
            for tgid_b, stats_b in current_map_items:
                tgid = tgid_b.value
                stats = stats_b

                comm_entry = tgid_comm_map.get(tgid_b)  # <<< LOOKUP COMM FROM NEW MAP
                comm_str = "<unk>"
                if comm_entry:
                    try:
                        comm_str = (
                            comm_entry.comm.decode("utf-8", "replace")
                            .strip("\x00")
                            .strip()
                        )
                    except Exception:
                        comm_str = "<comm_err>"
                if (
                    not comm_str or comm_str == "<unk>"
                ):  # Fallback if not in map or empty
                    comm_str = f"<unk:{tgid}>"

                display_data.append((tgid, comm_str, stats))

            sorted_data = sorted(
                display_data,
                key=lambda x: (x[2].mmap_shared_calls + x[2].shmget_calls),
                reverse=True,
            )

            if sorted_data and as_table:
                print(
                    f"{'TGID':<7} {'COMM':<15} | {'SHMGET':>7} {'SHMAT':>7} {'SHMDT':>7} {'RMID':>6} {'GET_MB':>8} | "
                    f"{'SHMOPEN':>8} {'UNLINK':>7} {'MMAP_SH':>8} {'MUNMAP':>7} {'MMAP_MB':>9}"
                )
                print("-" * 125)

            for tgid_val, comm_val, stats_obj in sorted_data[:20]:
                shmget_mb = stats_obj.total_shmget_size_bytes / (1024.0 * 1024.0)
                mmap_sh_mb = stats_obj.total_mmap_shared_size_bytes / (1024.0 * 1024.0)
                if as_table:
                    print(
                        f"{tgid_val:<7} {comm_val:<15} | "
                        f"{stats_obj.shmget_success:>7} {stats_obj.shmat_calls:>7} {stats_obj.shmdt_calls:>7} {stats_obj.shmctl_rmid_calls:>6} {shmget_mb:>8.2f} | "
                        f"{stats_obj.shm_open_success:>8} {stats_obj.shm_unlink_calls:>7} {stats_obj.mmap_shared_calls:>8} {stats_obj.munmap_shared_calls:>7} {mmap_sh_mb:>9.2f}"
                    )

                else:
                    print(
                        json.dumps(
                            {
                                "tgid": tgid_val,
                                "comm": comm_val,
                                "shmget": stats_obj.shmget_success,
                                "shmat": stats_obj.shmat_calls,
                                "shmdt": stats_obj.shmdt_calls,
                                "rmid": stats_obj.shmctl_rmid_calls,
                                "get_mb": shmget_mb,
                                "shmopen": stats_obj.shm_open_success,
                                "unlink": stats_obj.shm_unlink_calls,
                                "mmap_sh": stats_obj.mmap_shared_calls,
                                "munmap": stats_obj.munmap_shared_calls,
                                "mmap_sh_mb": mmap_sh_mb,
                            }
                        )
                    )

            if stop_indicator_file and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False
            if not running:
                break

    except Exception as e_main:
        print(f"Error or interrupt during execution: {e_main}")
        traceback.print_exc()
    finally:
        print("Cleaning up BPF resources...")
        if bpf_instance:
            bpf_instance.cleanup()
        print("Cleanup complete.")


def main():
    global include_patterns
    global exclude_patterns

    if os.geteuid() != 0:
        helpers.log("This script must be run as root.", exit_flag=True)

    parser = helpers.get_parser("eBPF Shared Memory Analyzer.")
    args, _ = parser.parse_known_args()

    include_patterns = args.include_pattern
    exclude_patterns = args.exclude_pattern

    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,  # as_table
        args.debug,
    )


if __name__ == "__main__":
    main()
