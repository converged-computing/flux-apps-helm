#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import re
import os
import json
import signal
import time
import sys

# Global indicator to set to stop running
running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__))

# Python constants
TASK_COMM_LEN_PY = 16
FUTEX_OP_DISPLAY_WIDTH = 20  # Increased for "FUTEX_WAIT_PRIVATE"
DURATION_DISPLAY_WIDTH = 15


# Ctypes structure for futex events
class EventType(ct.c_int):
    EVENT_FUTEX_WAIT_COMPLETED = 0


class FutexEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("type", EventType),
        ("futex_op_full", ct.c_int),
        ("wait_duration_ns", ct.c_ulonglong),
    ]


# Ctypes structure for debug events
class DebugEventData(ct.Structure):
    _fields_ = [
        ("id_tid", ct.c_uint),  # Matched BPF struct field name and type
        ("stage", ct.c_int),
        ("val1_op", ct.c_long),
        ("val2_duration_or_misc", ct.c_long),
    ]


# Python-side FUTEX constants (must match BPF defines)
FUTEX_WAIT_PY = 0
FUTEX_PRIVATE_FLAG_PY = 128
FUTEX_WAIT_PRIVATE_PY = FUTEX_WAIT_PY | FUTEX_PRIVATE_FLAG_PY
# Add others if needed

# Python-side debug stage constants
DBG_FUTEX_ENTER_TRACKING_PY = 400
DBG_FUTEX_ENTER_NOT_TRACKING_PY = 401
DBG_FUTEX_EXIT_FOUND_START_PY = 402
DBG_FUTEX_EXIT_NO_START_PY = 403
DBG_FUTEX_SUBMITTED_PY = 404
DBG_FUTEX_RESERVE_FAIL_PY = 405


def get_futex_operation(op_full):
    """
    Get the futex operation. We are interested in deriving wait time
    """
    # Basic command part (ignoring FUTEX_CLOCK_REALTIME for this simple string conversion)
    # 256 is FUTEX_CLOCK_REALTIME
    op_cmd = op_full & ~(FUTEX_PRIVATE_FLAG_PY | 256)

    s = ""
    if op_cmd == FUTEX_WAIT_PY:
        s = "FUTEX_WAIT"
    else:
        s = f"OP_{op_cmd}"

    if op_full & FUTEX_PRIVATE_FLAG_PY:
        s += "_PRIVATE"
    if op_full & 256:
        s += "_REALTIME"
    return s


def format_duration(ns):
    if ns == 0:
        return "0ns"
    if ns < 1000:
        return f"{ns}ns"
    elif ns < 1000000:
        return f"{ns/1000.0:.2f}us"
    elif ns < 1000000000:
        return f"{ns/1000000.0:.2f}ms"
    else:
        return f"{ns/1000000000.0:.2f}s"


def print_event_ringbuf(ctx, data, size):
    global as_table
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file
    global cgroup_id_filter

    # if a cgroup filter is set
    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    event = ct.cast(data, ct.POINTER(FutexEventData)).contents

    try:
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    except:
        comm = "<comm_err>"

    if include_patterns and not any(re.search(p, comm) for p in include_patterns):
        return
    if exclude_patterns and any(re.search(p, comm) for p in exclude_patterns):
        return
    if cgroup_id_filter is not None and str(event.cgroup_id) != cgroup_id_filter:
        return

    timestamp_sec = event.timestamp_ns / 1e9
    futex_operation = get_futex_operation(event.futex_op_full)
    duration = format_duration(event.wait_duration_ns)

    if as_table:
        print_futex_table_row(event, comm, futex_operation, duration, timestamp_sec)
    else:
        print_futex_json(event, comm, futex_operation, duration, timestamp_sec)


def print_futex_json(event, comm, futex_op_str, duration_str, timestamp_sec):
    body = {
        "event_type": "FUTEX_WAIT_END",
        "timestamp_sec": timestamp_sec,
        "tgid": event.tgid,
        "tid": event.tid,
        "comm": comm,
        "cgroup_id": event.cgroup_id,
        "futex_op_full": event.futex_op_full,
        "futex_op_str": futex_op_str,
        "wait_duration_ns": event.wait_duration_ns,
        "wait_duration_human": duration_str,
    }
    print(json.dumps(body))


def print_futex_table_row(event, comm, futex_operation, duration, timestamp_sec):
    print(
        f"{timestamp_sec:<18.6f} {event.tgid:<7} {event.tid:<7} {comm:<{TASK_COMM_LEN_PY}} "
        f"{futex_operation:<{FUTEX_OP_DISPLAY_WIDTH}} {duration:>{DURATION_DISPLAY_WIDTH}}"
    )


def print_debug_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(DebugEventData)).contents
    stage = f"UNKNOWN_DBG({event.stage})"
    tid_val = event.id_tid
    val1_operation = event.val1_op
    val2_duration = event.val2_duration_or_misc

    if event.stage == DBG_FUTEX_ENTER_TRACKING_PY:
        stage = "FUTEX_ENTER_TRACKING"
    elif event.stage == DBG_FUTEX_ENTER_NOT_TRACKING_PY:
        stage = "FUTEX_ENTER_NOT_TRACKING"
    elif event.stage == DBG_FUTEX_EXIT_FOUND_START_PY:
        stage = "FUTEX_EXIT_FOUND_START"
    elif event.stage == DBG_FUTEX_EXIT_NO_START_PY:
        stage = "FUTEX_EXIT_NO_START"
    elif event.stage == DBG_FUTEX_SUBMITTED_PY:
        stage = "FUTEX_EVENT_SUBMITTED"
    elif event.stage == DBG_FUTEX_RESERVE_FAIL_PY:
        stage = "FUTEX_RESERVE_FAIL"

    operation = (
        get_futex_operation(val1_operation)
        if "ENTER" in stage or "SUBMITTED" in stage or "FOUND_START" in stage
        else str(val1_operation)
    )
    duration = (
        format_duration(val2_duration)
        if "FOUND_START" in stage or "SUBMITTED" in stage
        else str(val2_duration)
    )

    print(
        f"DEBUG: TID:{tid_val:<7} STAGE: {stage:<28} OP/Val1: {operation:<20} Duration/Val2: {duration:<15}"
    )


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def print_futex_table_header():
    print(
        f"{'TIMESTAMP':<18} {'TGID':<7} {'TID':<7} {'COMMAND':<{TASK_COMM_LEN_PY}} "
        f"{'FUTEX_OP':<{FUTEX_OP_DISPLAY_WIDTH}} {'DURATION':>{DURATION_DISPLAY_WIDTH}}"
    )
    header_len = (
        18
        + 1
        + 7
        + 1
        + 7
        + 1
        + TASK_COMM_LEN_PY
        + 1
        + FUTEX_OP_DISPLAY_WIDTH
        + 1
        + DURATION_DISPLAY_WIDTH
    )
    print("-" * header_len)


def collect_trace(
    start_indicator_file=None, stop_indicator_file=None, table=True, debug=False
):
    global running
    global as_table
    global cgroup_indicator_file

    as_table = table
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    helpers.log("Starting eBPF (Tracepoints for futex syscalls).")
    bpf_instance = None
    try:
        bpf_instance = BPF(text=bpf_text, debug=0)
        helpers.log("BPF program loaded and tracepoints automatically attached.")
    except Exception as e:
        helpers.log(f"Error initializing/attaching BPF: {e}", exit_flag=True)
        return

    # Wait to start until the application is going to run
    if start_indicator_file is not None:
        helpers.log(
            f"\nStart Indicator file defined '{start_indicator_file}'. Waiting."
        )
        while not os.path.exists(start_indicator_file):
            time.sleep(0.5)
        helpers.log("Start indicator found. Proceeding.")

    # Print header table to describe fields
    if table:
        print_futex_table_header()

    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf, ctx=None)
        if debug:
            bpf_instance["debug_events_rb"].open_ring_buffer(
                print_debug_event, ctx=None
            )
        helpers.log("Ring buffers opened. Polling for events...")
    except Exception as e:
        helpers.log(f"Failed to open ring buffer(s): {e}")
        if bpf_instance:
            bpf_instance.cleanup()
        sys.exit(1)

    try:
        while running:
            bpf_instance.ring_buffer_poll(timeout=100)

            # Does the user want to stop?
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False

            if not running:
                break
    except Exception as e:
        helpers.log(f"\nError or interrupt during polling: {e}")
        running = False
    finally:
        helpers.log("Cleaning up BPF resources...")
        if bpf_instance:
            bpf_instance.cleanup()


def main():
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = helpers.get_parser("eBPF Futex Wait Time Analyzer.")
    args, _ = parser.parse_known_args()

    if args.debug and args.json:
        helpers.log(
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
