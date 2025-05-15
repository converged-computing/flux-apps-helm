from bcc import BPF
import ctypes as ct
import time
import os
import traceback
import argparse
import signal
import json
import sys

# Should match C code
TASK_COMM_LEN = 16


def read_file(filename):
    with open(filename, "r") as fd:
        content = fd.read()
    return content


# Global indicator to set to stop running
running = True
as_table = True
include_patterns = None
exclude_patterns = None


# Ensure we get the c program alongside
here = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(here, "ebpf-collect.c")
print(f"Looking for {filename}")
if not os.path.exists(filename):
    sys.exit(f"Missing c code {filename}")

# Define the C code for the eBPF program
bpf_text = read_file(filename)


class ShmTgidStats(ct.Structure):
    _fields_ = [
        ("shmget_calls", ct.c_ulonglong),
        ("shmget_success", ct.c_ulonglong),
        ("shmat_calls", ct.c_ulonglong),
        ("shmdt_calls", ct.c_ulonglong),
        ("shmctl_rmid_calls", ct.c_ulonglong),
        ("total_shmget_size_bytes", ct.c_ulonglong),
        ("shm_open_calls", ct.c_ulonglong),
        ("shm_open_success", ct.c_ulonglong),
        ("shm_unlink_calls", ct.c_ulonglong),
        ("mmap_shared_calls", ct.c_ulonglong),
        ("munmap_shared_calls", ct.c_ulonglong),
        ("total_mmap_shared_size_bytes", ct.c_ulonglong),
    ]


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def get_parser():
    parser = argparse.ArgumentParser(description="eBPF Futex Wait Time Analyzer.")
    parser.add_argument(
        "--cgroup-indicator-file", help="Filename with a cgroup ID to filter to"
    )
    parser.add_argument(
        "--stop-indicator-file", help="Indicator file path to stop tracing"
    )
    parser.add_argument(
        "--start-indicator-file", help="Indicator file path to start tracing"
    )
    parser.add_argument(
        "--include-pattern",
        default=None,
        action="append",
        help="Include comm patterns only",
    )
    parser.add_argument(
        "--exclude-pattern", default=None, action="append", help="Exclude comm patterns"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print BPF debug events via ring buffer",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        default=False,
        help="Print records as JSON instead of table",
    )
    return parser


def collect_trace(
    start_indicator_file=None, stop_indicator_file=None, table=True, debug=False
):
    global running
    global as_table
    global cgroup_indicator_file

    as_table = table
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    print("Initializing eBPF for Shared Memory monitoring...")
    try:
        b = BPF(text=bpf_text)
        print("BPF C code compiled and loaded.")

        # --- Explicitly attach tracepoints that we know should work ---
        print("Attaching tracepoints...")
        tracepoint_syscalls = ["shmget", "shmat", "shmdt", "shmctl", "mmap", "munmap"]
        # Define which ones have exit handlers in our C code
        has_exit_handler = {"shmget", "mmap"}

        for syscall in tracepoint_syscalls:
            enter_fn_name = f"trace_enter_{syscall}"
            exit_fn_name = f"trace_exit_{syscall}"
            try:
                b.attach_tracepoint(
                    tp=f"syscalls:sys_enter_{syscall}", fn_name=enter_fn_name
                )
                print(f"  Attached TP syscalls:sys_enter_{syscall} to {enter_fn_name}")
            except Exception as e:
                print(
                    f"  WARNING: Failed to attach TP syscalls:sys_enter_{syscall}: {e}"
                )

            if syscall in has_exit_handler:
                try:
                    b.attach_tracepoint(
                        tp=f"syscalls:sys_exit_{syscall}", fn_name=exit_fn_name
                    )
                    print(
                        f"  Attached TP syscalls:sys_exit_{syscall} to {exit_fn_name}"
                    )
                except Exception as e:
                    print(
                        f"  WARNING: Failed to attach TP syscalls:sys_exit_{syscall}: {e}"
                    )

        # Kprobes for shm_open and shm_unlink will be auto-attached by BCC
        # if the kernel symbols ("shm_open", "shm_unlink") exist and match the SEC() in C.
        # BCC prints warnings if kprobe attachment fails due to missing symbols.
        print(
            "  Kprobes for shm_open and shm_unlink should be auto-attached by BCC if symbols exist."
        )
        print("  (BCC will warn if kprobe attachment fails for these).")

        print("Finished attaching probes.")
        print("Monitoring shared memory syscalls... Press Ctrl-C to stop.\n")
        print(
            "Check kernel trace pipe for BPF messages: sudo cat /sys/kernel/debug/tracing/trace_pipe\n"
        )

        interval_s = 5
        while True:
            time.sleep(interval_s)
            print(
                f"\n--- Shared Memory Stats Summary at {time.strftime('%H:%M:%S')} ---"
            )
            proc_stats_map = b.get_table("proc_shm_stats")
            current_map_items = list(proc_stats_map.items())

            if not current_map_items:
                print("No data collected in proc_shm_stats map yet.")
                continue

            display_data = []
            for tgid_b, stats_b in current_map_items:
                tgid = tgid_b.value
                stats = stats_b  # ShmTgidStats instance
                try:
                    # Be careful with /proc access, can be slow or cause issues if PIDs are gone
                    with open(f"/proc/{tgid}/comm", "r") as f_comm:
                        comm = f_comm.read().strip()
                except FileNotFoundError:
                    comm = f"<unk:{tgid}>"
                except Exception as e_proc:
                    comm = f"<err:{tgid}>"
                display_data.append((tgid, comm, stats))

            sorted_data = sorted(
                display_data,
                key=lambda item: (item[2].mmap_shared_calls + item[2].shmget_calls),
                reverse=True,
            )

            if sorted_data and as_table:
                print(
                    f"{'TGID':<7} {'COMM':<15} | {'SHMGET':>7} {'SHMAT':>7} {'SHMDT':>7} {'RMID':>6} {'GET_MB':>8} | "
                    f"{'SHMOPEN':>8} {'UNLINK':>7} {'MMAP_SH':>8} {'MUNMAP':>7} {'MMAP_MB':>9}"
                )
                print("-" * 125)
            for tgid, comm, stats in sorted_data[:20]:  # Display top 20
                shmget_mb = stats.total_shmget_size_bytes / (1024.0 * 1024.0)
                mmap_sh_mb = stats.total_mmap_shared_size_bytes / (1024.0 * 1024.0)
                if as_table:
                    print(
                        f"{tgid:<7} {comm:<15} | "
                        f"{stats.shmget_success:>7} {stats.shmat_calls:>7} {stats.shmdt_calls:>7} {stats.shmctl_rmid_calls:>6} {shmget_mb:>8.2f} | "
                        f"{stats.shm_open_success:>8} {stats.shm_unlink_calls:>7} {stats.mmap_shared_calls:>8} {stats.munmap_shared_calls:>7} {mmap_sh_mb:>9.2f}"
                    )
                else:
                    body = {
                        "tgid": tgid,
                        "comm": comm,
                        "shmget": stats.shmget_success,
                        "shmat": stats.shmat_calls,
                        "shmdt": stats.shmdt_calls,
                        "rmid": stats.shmctl_rmid_calls,
                        "get_mb": shmget_mb,
                        "shmopen": stats.shm_open_success,
                        "unlink": stats.shm_unlink_calls,
                        "mmap_sh": stats.mmap_shared_calls,
                        "munmap": stats.munmap_shared_calls,
                        "mmap_sh_mb": mmap_sh_mb,
                    }
                    print(json.dumps(body))

    except KeyboardInterrupt:
        print("\nDetaching and exiting...")
    except Exception as e:
        print(f"Error during execution: {e}")
        traceback.print_exc()
    finally:
        if b:  # Ensure bpf object exists before trying to cleanup
            b.cleanup()


def main():
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = get_parser()
    args = parser.parse_args()

    if args.debug and args.json:
        log(
            "Warning: Debug output is formatted as table, not JSON. Forcing table output for debug."
        )
        args.json = False

    include_patterns = args.include_pattern
    exclude_patterns = args.exclude_pattern
    cgroup_indicator_file = args.cgroup_indicator_file

    # Run the main program to collect the trace
    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,
        args.debug,
    )


if __name__ == "__main__":
    main()
