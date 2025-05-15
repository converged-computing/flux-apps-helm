#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import re
import os
import json
import signal
import time
import sys

# Global state
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
SYSCALL_TYPE_DISPLAY_WIDTH = 10  # For "SEND" / "RECV"
DURATION_DISPLAY_WIDTH = 15
BYTES_DISPLAY_WIDTH = 10


# Ctypes structure for TCP events
class NetEventType(ct.c_int):
    EVENT_TCP_SEND = 0
    EVENT_TCP_RECV = 1


class NetEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("type", NetEventType),
        ("fd", ct.c_int),
        ("bytes_count", ct.c_longlong),  # s64 in BPF maps to c_longlong
        ("duration_ns", ct.c_ulonglong),
    ]


# Ctypes structure for debug events
class DebugEventData(ct.Structure):
    _fields_ = [
        ("id_tid", ct.c_uint),
        ("stage", ct.c_int),
        ("val1_fd_or_bytes", ct.c_long),
        ("val2_duration_or_ret", ct.c_long),
    ]


# Python-side debug stage constants
DBG_SEND_ENTER_PY = 500
DBG_SEND_EXIT_PY = 501
DBG_RECV_ENTER_PY = 502
DBG_RECV_EXIT_PY = 503
DBG_SUBMITTED_PY = 504
DBG_RESERVE_FAIL_PY = 505
DBG_NO_ENTRY_INFO_PY = 506


def format_duration(ns):
    """
    Format duration into human readable variant.
    """
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


def print_event_ringbuf_cb(ctx, data, size):
    global as_table
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file
    global cgroup_id_filter

    # if a cgroup filter is set
    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    event = ct.cast(data, ct.POINTER(NetEventData)).contents

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
    type_str = "SEND" if event.type == NetEventType.EVENT_TCP_SEND else "RECV"
    duration = format_duration(event.duration_ns)
    bytes_str = (
        str(event.bytes_count)
        if event.bytes_count >= 0
        else f"ERR({event.bytes_count})"
    )

    if as_table:
        print_net_table_row(event, comm, type_str, duration, bytes_str, timestamp_sec)
    else:
        print_net_json(event, comm, type_str, duration, bytes_str, timestamp_sec)


def print_net_json(event, comm, type_str, duration, bytes_str, timestamp_sec):
    body = {
        "event_type": type_str,
        "timestamp_sec": timestamp_sec,
        "tgid": event.tgid,
        "tid": event.tid,
        "comm": comm,
        "cgroup_id": event.cgroup_id,
        "fd": event.fd,
        "bytes": event.bytes_count,  # Raw byte count
        "bytes_human": bytes_str,  # Human-readable (includes error indication)
        "duration_ns": event.duration_ns,
        "duration_human": duration,
    }
    print(json.dumps(body))


def print_net_table_row(event, comm, type_str, duration_str, bytes_str, timestamp_sec):
    print(
        f"{timestamp_sec:<18.6f} {event.tgid:<7} {event.tid:<7} {comm:<{TASK_COMM_LEN_PY}} "
        f"{type_str:<{SYSCALL_TYPE_DISPLAY_WIDTH}} FD:{event.fd:<3} "
        f"{bytes_str:>{BYTES_DISPLAY_WIDTH}} {duration_str:>{DURATION_DISPLAY_WIDTH}}"
    )


def print_debug_event_cb(ctx, data, size):
    event = ct.cast(data, ct.POINTER(DebugEventData)).contents
    stage_str = f"UNKNOWN_DBG({event.stage})"
    tid_val = event.id_tid
    val1 = event.val1_fd_or_bytes
    val2 = event.val2_duration_or_ret

    if event.stage == DBG_SEND_ENTER_PY:
        stage_str = "SEND_ENTER"
    elif event.stage == DBG_SEND_EXIT_PY:
        stage_str = "SEND_EXIT"
    elif event.stage == DBG_RECV_ENTER_PY:
        stage_str = "RECV_ENTER"
    elif event.stage == DBG_RECV_EXIT_PY:
        stage_str = "RECV_EXIT"
    elif event.stage == DBG_SUBMITTED_PY:
        stage_str = "SUBMITTED"
    elif event.stage == DBG_RESERVE_FAIL_PY:
        stage_str = "RESERVE_FAIL"
    elif event.stage == DBG_NO_ENTRY_INFO_PY:
        stage_str = "NO_ENTRY_INFO"

    print(
        f"DEBUG: TID:{tid_val:<7} STAGE: {stage_str:<15} FD/Bytes:{val1:<7} Dur/Ret:{val2:<15}"
    )


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def print_net_table_header():
    print(
        f"{'TIMESTAMP':<18} {'TGID':<7} {'TID':<7} {'COMMAND':<{TASK_COMM_LEN_PY}} "
        f"{'TYPE':<{SYSCALL_TYPE_DISPLAY_WIDTH}} {'FD':<5} "  # FD needs some space e.g. "FD:123"
        f"{'BYTES':>{BYTES_DISPLAY_WIDTH}} {'DURATION':>{DURATION_DISPLAY_WIDTH}}"
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
        + SYSCALL_TYPE_DISPLAY_WIDTH
        + 1
        + 5
        + 1
        + BYTES_DISPLAY_WIDTH
        + 1
        + DURATION_DISPLAY_WIDTH
    )
    print("-" * header_len)


def collect_trace(
    start_indicator_file=None, stop_indicator_file=None, table=True, debug_flag=False
):
    global running
    global as_table
    global cgroup_indicator_file
    as_table = table

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    helpers.log("Starting eBPF (Tracepoints for sendto/recvfrom syscalls).")
    bpf_instance = None
    try:
        bpf_instance = BPF(text=bpf_text, debug=0)
        helpers.log("BPF program loaded and tracepoints automatically attached.")
    except Exception as e:
        helpers.log(f"Error initializing/attaching BPF: {e}", exit_flag=True)
        return

    if table:
        print_net_table_header()
    if cgroup_indicator_file is not None:
        helpers.log(f"\nCgroup Indicator file defined '{cgroup_indicator_file}'.")

    # Wait for the start indicator file to be present
    if start_indicator_file is not None:
        helpers.log(
            f"\nStart Indicator file defined '{start_indicator_file}'. Waiting."
        )
        while not os.path.exists(start_indicator_file):
            time.sleep(0.5)
        helpers.log("Start indicator found. Proceeding.")

    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf_cb, ctx=None)
        if debug_flag:
            bpf_instance["debug_events_rb"].open_ring_buffer(
                print_debug_event_cb, ctx=None
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
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False

    except Exception as e:
        helpers.log(f"\nError or interruption during polling: {e}")
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

    parser = helpers.get_parser("eBPF TCP Analyzer.")
    args, _ = parser.parse_known_args()

    if args.debug and args.json:
        helpers.log("Warning: Debug output is table. Forcing table output.")
        args.json = False

    include_patterns = args.include_pattern
    exclude_patterns = args.exclude_pattern
    cgroup_indicator_file = args.cgroup_indicator_file

    collect_trace(
        args.start_indicator_file, args.stop_indicator_file, not args.json, args.debug
    )


if __name__ == "__main__":
    main()
