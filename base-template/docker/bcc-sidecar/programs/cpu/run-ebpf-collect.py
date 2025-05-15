from bcc import BPF
import ctypes as ct
import argparse
import time
import os
import re
import sys
import json
import signal


# Global state
running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

# Ensure we get the c program alongside
here = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(here, "ebpf-collect.c")
print(f"Looking for {filename}")
if not os.path.exists(filename):
    sys.exit(f"Missing c code {filename}")

def get_cgroup_filter(cgroup_indicator_file):
    """
    Filtering to a cgroup id can scope the results to one container.
    """
    try:
        with open(cgroup_indicator_file, "r") as f:
            cgroup_id_filter = f.read().strip()
            if cgroup_id_filter:
                log(f"Scoping to cgroup {cgroup_id_filter}")
            else:
                log(
                    f"Warning: Cgroup indicator file '{cgroup_indicator_file}' is empty."
                )
                cgroup_id_filter = None
    except Exception as e:
        log(
            f"Warning: Could not read cgroup indicator file '{cgroup_indicator_file}': {e}"
        )
        cgroup_id_filter = None  # Treat as no filter
    return cgroup_id_filter


def read_file(filename):
    with open(filename, "r") as fd:
        content = fd.read()
    return content


# BPF C code as a multi-line string
bpf_c_text = read_file(filename)

# Define the sched_event_data structure for Python
TASK_COMM_LEN = 16


class SchedEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("on_cpu_ns", ct.c_ulonglong),
        ("runq_latency_ns", ct.c_ulonglong),
        ("event_type", ct.c_ubyte),
        ("prev_state_task_switched_out", ct.c_ubyte),
    ]


# Callback function for perf buffer
def print_event(cpu, data, size):

    global as_table
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file
    global cgroup_id_filter

    # if a cgroup filter is set
    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = get_cgroup_filter(cgroup_indicator_file)

    event = ct.cast(data, ct.POINTER(SchedEventData)).contents
    on_cpu_ms = 0.0
    runq_latency_ms = 0.0

    if event.on_cpu_ns > 0:
        on_cpu_ms = event.on_cpu_ns / 1000000.0
    if event.runq_latency_ns > 0:
        runq_latency_ms = event.runq_latency_ns / 1000000.0

    # this is the command
    comm = event.comm.decode("utf-8", "replace").strip("\\x00").strip()

    if include_patterns and not any(re.search(p, comm) for p in include_patterns):
        return
    if exclude_patterns and any(re.search(p, comm) for p in exclude_patterns):
        return
    if cgroup_id_filter is not None and str(event.cgroup_id) != cgroup_id_filter:
        return
    prev_state = event.prev_state_task_switched_out if event.on_cpu_ns > 0 else "-"
    if as_table:
        print(
            f"{event.timestamp_ns / 1000000000.0:.6f} "
            f"COMM={comm:<15} "
            f"TID={event.tid:<7} "
            f"TGID={event.tgid:<7} "
            f"CGROUP={event.cgroup_id} "
            f"ON_CPU_MS={on_cpu_ms:.3f} "
            f"RUNQ_LAT_MS={runq_latency_ms:.3f} "
            f"PREV_STATE={prev_state}"
        )
    else:
        body = {
            "timestamp": event.timestamp_ns,
            "comm": comm,
            "tid": event.tid,
            "tgid": event.tgid,
            "cgroup_id": event.cgroup_id,
            "on_cpu_ms": on_cpu_ms,
            "ring_latency_ms": runq_latency_ms,  # Raw byte count
            "prev_state": prev_state,
        }
        print(json.dumps(body))


def get_parser():
    parser = argparse.ArgumentParser(description="eBPF TCP Send/Receive Time Analyzer.")
    parser.add_argument(
        "--cgroup-indicator-file", help="Filename with cgroup ID to filter"
    )
    parser.add_argument("--stop-indicator-file", help="Indicator file path to stop")
    parser.add_argument("--start-indicator-file", help="Indicator file path to start")
    parser.add_argument(
        "--include-pattern", default=None, action="append", help="Include comm patterns"
    )
    parser.add_argument(
        "--exclude-pattern", default=None, action="append", help="Exclude comm patterns"
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Print BPF debug events"
    )
    parser.add_argument(
        "-j", "--json", action="store_true", default=False, help="Print as JSON"
    )
    return parser


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def log(message, prefix="", exit_flag=False):
    if prefix:
        prefix = f"{prefix} "
    print(f"{prefix}{message}", file=sys.stderr)
    if exit_flag:
        sys.exit(1)


def collect_trace(
    start_indicator_file=None, stop_indicator_file=None, table=True, debug_flag=False
):
    global running
    global as_table
    global cgroup_indicator_file
    as_table = table

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    if cgroup_indicator_file is not None:
        log(f"\nCgroup Indicator file defined '{cgroup_indicator_file}'.")

    # Wait for the start indicator file to be present
    if start_indicator_file is not None:
        log(f"\nStart Indicator file defined '{start_indicator_file}'. Waiting.")
        while not os.path.exists(start_indicator_file):
            time.sleep(0.5)
        log("Start indicator found. Proceeding.")

    try:
        print("Initializing eBPF for CPU Scheduling monitoring...")
        b = BPF(text=bpf_c_text)
        print("BPF C code compiled and loaded.")

        # Explicitly attach tracepoints
        b.attach_tracepoint(tp="sched:sched_wakeup", fn_name="tp_sched_wakeup")
        b.attach_tracepoint(tp="sched:sched_wakeup_new", fn_name="tp_sched_wakeup_new")
        b.attach_tracepoint(
            tp="sched:sched_switch", fn_name="tp_sched_switch"
        )  # Use renamed C function

        print("Attached tracepoints.")

        # Correct way to open perf buffer in BCC:
        # 1. Get the table object for the perf output map defined in C ("events_out")
        # 2. Call open_perf_buffer on that table object.
        events_table = b.get_table("events_out")
        events_table.open_perf_buffer(print_event)
        print("Monitoring CPU scheduling events... Press Ctrl-C to stop.")

        # Keep going until we have a stop indicator file
        while True:
            try:
                b.perf_buffer_poll(timeout=100)
                if stop_indicator_file is not None and os.path.exists(
                    stop_indicator_file
                ):
                    log(f"\nIndicator file '{stop_indicator_file}' found. Stopping.")
                    running = False

            except KeyboardInterrupt:
                print("\nDetaching...")
                break
            except Exception as e_poll:
                print(f"Error polling perf buffer: {e_poll}")
                break
    except Exception as e:
        print(f"Error during BPF setup or execution: {e}")


def main():
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")
    parser = get_parser()
    args = parser.parse_args()

    if args.debug and args.json:
        log("Warning: Debug output is table. Forcing table output.")
        args.json = False

    include_patterns = args.include_pattern
    exclude_patterns = args.exclude_pattern
    cgroup_indicator_file = args.cgroup_indicator_file

    collect_trace(
        args.start_indicator_file, args.stop_indicator_file, not args.json, args.debug
    )


if __name__ == "__main__":
    main()
