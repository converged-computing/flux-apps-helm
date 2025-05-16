#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import re
import os
import json
import signal
import time
import sys
import traceback
import argparse

# Global state
running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

# --- bcchelper.py Import ---
# Assuming bcchelper.py is in the parent directory of this script's location
# or an alternative path handling is implemented in your actual bcchelper.

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__))

TASK_COMM_LEN_PY = 16
SYSCALL_TYPE_DISPLAY_WIDTH = 16
DURATION_DISPLAY_WIDTH = 15
BYTES_DISPLAY_WIDTH = 10


class NetEventTypePy(ct.c_int):  # Renamed to avoid conflict
    EVENT_TCP_SEND = 0
    EVENT_TCP_RECV = 1
    EVENT_WRITE_SOCKET = 2
    EVENT_READ_SOCKET = 3
    EVENT_CONNECT = 4
    EVENT_ACCEPT = 5
    EVENT_SOCKET_CREATE = 6  # Added to match C enum


class NetEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("type", NetEventTypePy),  # Use renamed ctype
        ("fd", ct.c_int),
        ("bytes_count", ct.c_longlong),  # s64 in C
        ("duration_ns", ct.c_ulonglong),
    ]


# --- PYTHON CONSTANTS for Event Types ---
EVENT_TCP_SEND_PY = 0
EVENT_TCP_RECV_PY = 1
EVENT_WRITE_SOCKET_PY = 2
EVENT_READ_SOCKET_PY = 3
EVENT_CONNECT_PY = 4
EVENT_ACCEPT_PY = 5
EVENT_SOCKET_CREATE_PY = 6  # Added


def format_duration(ns):  # Your function
    if ns == 0:
        return "0ns"
    if ns < 1000:
        return f"{ns}ns"
    if ns < 1000000:
        return f"{ns/1000.0:.2f}us"
    if ns < 1000000000:
        return f"{ns/1000000.0:.2f}ms"
    return f"{ns/1000000000.0:.2f}s"


def print_event_ringbuf_cb(ctx, data, size):
    global as_table
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file
    global cgroup_id_filter

    event = ct.cast(data, ct.POINTER(NetEventData)).contents
    try:
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    except UnicodeDecodeError:
        comm = "<comm_err>"

    if include_patterns and not any(p.search(comm) for p in include_patterns):
        return
    if exclude_patterns and any(p.search(comm) for p in exclude_patterns):
        return
    if cgroup_id_filter is not None and str(event.cgroup_id) != cgroup_id_filter:
        return

    timestamp_sec = event.timestamp_ns / 1e9

    event_type_val = event.type.value
    type_str = f"UNKNOWN_EVT_VAL({event_type_val})"
    if event_type_val == EVENT_TCP_SEND_PY:
        type_str = "TCP_SEND"
    elif event_type_val == EVENT_TCP_RECV_PY:
        type_str = "TCP_RECV"
    elif event_type_val == EVENT_WRITE_SOCKET_PY:
        type_str = "WRITE_SOCK"
    elif event_type_val == EVENT_READ_SOCKET_PY:
        type_str = "READ_SOCK"
    elif event_type_val == EVENT_CONNECT_PY:
        type_str = "CONNECT"
    elif event_type_val == EVENT_ACCEPT_PY:
        type_str = "ACCEPT"
    elif event_type_val == EVENT_SOCKET_CREATE_PY:
        type_str = "SOCKET_NEW"

    duration_str = format_duration(event.duration_ns)
    if event.type.value == EVENT_CONNECT_PY:  # Also use .value here for consistency
        bytes_val_str = f"ret({event.bytes_count})"
    elif event.type.value == EVENT_ACCEPT_PY:  # And here
        bytes_val_str = f"newfd({event.fd})"
    elif event.type.value == EVENT_SOCKET_CREATE_PY:  # And here
        bytes_val_str = f"newfd({event.fd})"
    else:  # SEND, RECV, WRITE, READ
        bytes_val_str = (
            str(event.bytes_count)
            if event.bytes_count >= 0
            else f"ERR({event.bytes_count})"
        )
    if as_table:
        print_net_table_row(
            event, comm, type_str, duration_str, bytes_val_str, timestamp_sec
        )
    else:
        print_net_json(
            event, comm, type_str, duration_str, bytes_val_str, timestamp_sec
        )


def print_net_json(event, comm, type_str, duration_str, bytes_val_str, timestamp_sec):
    body = {
        "event_type": type_str,
        "timestamp_sec": timestamp_sec,
        "tgid": event.tgid,
        "tid": event.tid,
        "comm": comm,
        "cgroup_id": event.cgroup_id,
        "fd": event.fd,
    }
    if type_str in ["CONNECT", "ACCEPT", "SOCKET_NEW"]:
        if type_str == "CONNECT":
            body["connect_ret_val"] = event.bytes_count  # ret val
        # For ACCEPT and SOCKET_NEW, the relevant info is already event.fd
        if event.duration_ns > 0:
            body["duration_ns_call"] = event.duration_ns  # For connect syscall duration
    else:  # Data transfer
        body["bytes_count"] = event.bytes_count
        body["bytes_human"] = bytes_val_str
        body["duration_ns"] = event.duration_ns
        body["duration_human"] = duration_str
    print(json.dumps(body))


def print_net_table_row(event, comm, type_str, duration_str, bytes_str, timestamp_sec):
    # Ensure bytes_str can fit if it's "ret(val)" or "newfd(val)"
    adjusted_bytes_width = max(BYTES_DISPLAY_WIDTH, len(bytes_str) + 1)
    print(
        f"{timestamp_sec:<18.6f} {event.tgid:<7} {event.tid:<7} {comm:<{TASK_COMM_LEN_PY}} "
        f"{type_str:<{SYSCALL_TYPE_DISPLAY_WIDTH}} FD:{event.fd:<3} "
        f"{bytes_str:>{adjusted_bytes_width}} {duration_str:>{DURATION_DISPLAY_WIDTH}}"
    )


def signal_stop_handler(signum, frame):
    global running
    helpers.log(f"\nSignal {signal.Signals(signum).name} received, stopping...")
    running = False


def print_net_table_header():
    # Adjust BYTES column header
    print(
        f"{'TIMESTAMP':<18} {'TGID':<7} {'TID':<7} {'COMMAND':<{TASK_COMM_LEN_PY}} "
        f"{'TYPE':<{SYSCALL_TYPE_DISPLAY_WIDTH}} {'FD':<5} "
        f"{'BYTES/RET/FD':>{BYTES_DISPLAY_WIDTH+2}} {'DURATION':>{DURATION_DISPLAY_WIDTH}}"  # Wider for clarity
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
        + 2
        + 1
        + DURATION_DISPLAY_WIDTH
    )
    print("-" * header_len)


def collect_trace(
    start_indicator_file=None,
    stop_indicator_file=None,
    output_as_table=True,
    debug=False,
):
    global running
    global as_table
    global cgroup_indicator_file
    global cgroup_id_filter

    as_table = output_as_table
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    if cgroup_indicator_file is not None and os.path.exists(cgroup_indicator_file):
        cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    if start_indicator_file is not None:
        helpers.log(f"Start Indicator file defined '{start_indicator_file}'. Waiting.")
        while running and not os.path.exists(
            start_indicator_file
        ):  # Check running flag
            time.sleep(0.2)
        helpers.log("Start indicator found. Proceeding.")

    helpers.log("Starting eBPF for TCP network monitoring.")
    bpf_instance = None
    try:
        bcc_debug_level = 0
        if debug:
            bcc_debug_level = (
                BPF.DEBUG_LLVM_IR | BPF.DEBUG_BPF_BY_LLVM
            )  # More detailed debug
            helpers.log(
                f"BCC debug level set to include LLVM IR and BPF by LLVM for BPF compilation."
            )

        bpf_instance = BPF(text=bpf_text, debug=bcc_debug_level)
        helpers.log(
            "BPF C code compilation attempt complete. Check output above for Clang errors."
        )

    except Exception as e:
        helpers.log(
            f"FATAL: Error initializing BPF object: {e}\n{traceback.format_exc()}",
            exit_flag=True,
        )
        return

    if output_as_table:
        print_net_table_header()

    helpers.log("Attempting to explicitly attach all BPF programs...")
    # These C function names MUST exist in your ebpf-collect-tcp.c
    tracepoints_to_attach = {
        "syscalls:sys_enter_socket": "tp_enter_socket",
        "syscalls:sys_exit_socket": "tp_exit_socket",
        "syscalls:sys_enter_connect": "tp_enter_connect",
        "syscalls:sys_exit_connect": "tp_exit_connect",
        "syscalls:sys_exit_accept4": "tp_exit_accept4",  # Assuming C has tp_exit_accept4
        "syscalls:sys_enter_close": "tp_enter_close",
        "syscalls:sys_enter_sendto": "tp_enter_sendto",
        "syscalls:sys_exit_sendto": "tp_exit_sendto",
        "syscalls:sys_enter_recvfrom": "tp_enter_recvfrom",
        "syscalls:sys_exit_recvfrom": "tp_exit_recvfrom",
        "syscalls:sys_enter_write": "tp_enter_write",
        "syscalls:sys_exit_write": "tp_exit_write",
        "syscalls:sys_enter_read": "tp_enter_read",
        "syscalls:sys_exit_read": "tp_exit_read",
    }

    successful_attachments = 0
    total_defined_probes = len(tracepoints_to_attach)  # Only tracepoints in this script

    for tp_name_str, fn_name_str in tracepoints_to_attach.items():
        try:
            bpf_instance.attach_tracepoint(tp=tp_name_str, fn_name=fn_name_str)
            helpers.log(
                f"  SUCCESS: Attached tracepoint {tp_name_str} to C func {fn_name_str}"
            )
            successful_attachments += 1
        except Exception as e:
            helpers.log(
                f"  WARNING: FAILED to attach tracepoint {tp_name_str} to {fn_name_str}: {e}"
            )

    if successful_attachments == 0 and total_defined_probes > 0:
        helpers.log(
            "FATAL: No BPF programs were successfully attached. Check Clang errors above. Exiting.",
            exit_flag=True,
        )
    elif successful_attachments < total_defined_probes:
        helpers.log(
            f"WARNING: Only {successful_attachments}/{total_defined_probes} BPF programs attached. Output might be incomplete."
        )

    helpers.log("Finished attachment attempts.")
    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf_cb, ctx=None)
        helpers.log("Ring buffer 'events' opened. Polling for events...")
        if debug:
            helpers.log(
                "BPF debug messages (bpf_trace_printk) will appear in: sudo cat /sys/kernel/debug/tracing/trace_pipe"
            )

    except Exception as e:
        helpers.log(
            f"Failed to open ring buffer(s): {e}\n{traceback.format_exc()}",
            exit_flag=True,
        )

    try:
        while running:
            bpf_instance.ring_buffer_poll(timeout=100)
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(f"Indicator file '{stop_indicator_file}' found. Stopping.")
                running = False
            if not running:
                break
    except Exception as e:
        helpers.log(
            f"Error or interruption during polling: {e}\n{traceback.format_exc()}"
        )
        running = False
    finally:
        helpers.log("Cleaning up BPF resources...")
        if bpf_instance:
            bpf_instance.cleanup()
        helpers.log("Cleanup complete.")


def main():
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = helpers.get_parser(
        "eBPF TCP Socket Send/Receive Time Analyzer."
    )  # Use your helper
    args, _ = parser.parse_known_args()

    if args.include_pattern:
        include_patterns = [re.compile(p) for p in args.include_pattern]
    if args.exclude_pattern:
        exclude_patterns = [re.compile(p) for p in args.exclude_pattern]

    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,
        args.debug,
    )


if __name__ == "__main__":
    main()
