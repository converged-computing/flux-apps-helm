#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import os
import json
import signal
import time
import sys
import traceback
from collections import defaultdict
import math  # For checking isnan

# --- RiverML Imports ---
from river import stats

# Global state
running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

# --- Byte Bucketing Definition ---
# Define byte size buckets (in bytes)
# Labels should be file-system friendly if used in keys directly
# I think the max size is 65535 bytes.
BYTE_BUCKETS = [
    (0, 1024, "0B-1KB"),
    (1025, 16 * 1024, "1KB-16KB"),
    (16 * 1024 + 1, 64 * 1024, "16KB-64KB"),
    (64 * 1024 + 1, 256 * 1024, "64KB-256KB"),
    (256 * 1024 + 1, 1024 * 1024, "256KB-1MB"),
]
# Catch-all for larger sizes
LARGE_BUCKET_THRESHOLD = 1024 * 1024
LARGE_BUCKET_LABEL = "GT_1MB"  # Greater than 1MB


def get_byte_bucket_label(bytes_count):
    if bytes_count < 0:  # Error or irrelevant
        return "INVALID"
    for lower, upper, label in BYTE_BUCKETS:
        if lower <= bytes_count <= upper:
            return label
    if bytes_count > LARGE_BUCKET_THRESHOLD:
        return LARGE_BUCKET_LABEL
    # This case should ideally be covered by the last bucket or threshold
    return "OTHER"


# --- RiverML Model Storage ---
# Key for duration_stats_by_bucket: (tgid, comm_str, event_type_str, byte_bucket_label)
# Value: A dictionary of duration stat trackers (create_duration_stats_set)
duration_stats_by_bucket = defaultdict(lambda: create_duration_stats_set())

# Key for overall_byte_stats: (tgid, comm_str, event_type_str)
# Value: A dictionary of byte stat trackers (create_feature_stats_set)
# This keeps track of general byte transfer characteristics irrespective of bucketing.
overall_byte_stats = defaultdict(lambda: create_feature_stats_set())

# Key for connect_event_stats: (tgid, comm_str, "CONNECT")
# Value: dict {'duration_stats': create_duration_stats_set(), 'ret_val_stats': create_feature_stats_set()}
connect_event_stats = defaultdict(
    lambda: {
        "duration_stats": create_duration_stats_set(),
        "ret_val_stats": create_feature_stats_set(),
    }
)


def create_feature_stats_set():
    """Creates a dictionary of stat trackers for a generic feature."""
    return {
        "count": stats.Count(),
        "mean": stats.Mean(),
        "var": stats.Var(),
        "max": stats.Max(),
        "min": stats.Min(),
    }


def create_duration_stats_set():
    """Creates a dictionary of stat trackers specifically for duration, including quantiles."""
    return {
        "count": stats.Count(),
        "mean": stats.Mean(),
        "var": stats.Var(),
        "max": stats.Max(),
        "min": stats.Min(),
        "p50": stats.Quantile(0.50),
        "p95": stats.Quantile(0.95),
        "p99": stats.Quantile(0.99),
    }


# --- bcchelper.py Import ---
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
if root not in sys.path:
    sys.path.insert(0, root)
import bcchelper as helpers  # Assuming bcchelper.py is in the parent directory

bpf_text = helpers.read_bpf_text(
    os.path.abspath(__file__)
)  # Assumes C file is co-located or path handled by helper


TASK_COMM_LEN_PY = 16
SYSCALL_TYPE_DISPLAY_WIDTH = 16
STATS_FIELD_DISPLAY_WIDTH = 12
BUCKET_DISPLAY_WIDTH = 12


class NetEventTypePy(ct.c_int):
    EVENT_TCP_SEND = 0
    EVENT_TCP_RECV = 1
    EVENT_WRITE_SOCKET = 2
    EVENT_READ_SOCKET = 3
    EVENT_CONNECT = 4
    EVENT_ACCEPT = 5
    EVENT_SOCKET_CREATE = 6


class NetEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("type", NetEventTypePy),
        ("fd", ct.c_int),
        ("bytes_count", ct.c_longlong),
        ("duration_ns", ct.c_ulonglong),
    ]


EVENT_TCP_SEND_PY = NetEventTypePy.EVENT_TCP_SEND
EVENT_TCP_RECV_PY = NetEventTypePy.EVENT_TCP_RECV
EVENT_WRITE_SOCKET_PY = NetEventTypePy.EVENT_WRITE_SOCKET
EVENT_READ_SOCKET_PY = NetEventTypePy.EVENT_READ_SOCKET
EVENT_CONNECT_PY = NetEventTypePy.EVENT_CONNECT
EVENT_ACCEPT_PY = NetEventTypePy.EVENT_ACCEPT
EVENT_SOCKET_CREATE_PY = NetEventTypePy.EVENT_SOCKET_CREATE


def format_duration_us(ns):
    if ns == 0:
        return "0.00us"
    return f"{ns/1000.0:.2f}us"


def signal_stop_handler(signum, frame):
    global running
    helpers.log(f"\nSignal {signal.Signals(signum).name} received, stopping...")
    running = False


def get_event_type_str(event_type_val):
    if event_type_val == EVENT_TCP_SEND_PY:
        return "TCP_SEND"
    if event_type_val == EVENT_TCP_RECV_PY:
        return "TCP_RECV"
    if event_type_val == EVENT_WRITE_SOCKET_PY:
        return "WRITE_SOCK"
    if event_type_val == EVENT_READ_SOCKET_PY:
        return "READ_SOCK"
    if event_type_val == EVENT_CONNECT_PY:
        return "CONNECT"
    if event_type_val == EVENT_ACCEPT_PY:
        return "ACCEPT"
    if event_type_val == EVENT_SOCKET_CREATE_PY:
        return "SOCKET_NEW"
    return f"UNKNOWN_EVT_VAL({event_type_val})"


def update_and_get_stats_dict(model_stat_set, value):
    """
    Updates all stats in a set and returns their current values as a dictionary.
    """
    if value is None:
        return {name: "N/A" for name in model_stat_set}
    current_stats = {}
    for stat_name, stat_model in model_stat_set.items():
        stat_model.update(value)
        val = stat_model.get()
        if isinstance(val, float) and math.isnan(val):
            val = "N/A"
        elif val is None:
            val = "N/A"
        current_stats[stat_name] = val
    return current_stats


def print_event_ringbuf_cb(ctx, data, size):
    global as_table, include_patterns, exclude_patterns, cgroup_id_filter
    global duration_stats_by_bucket, overall_byte_stats, connect_event_stats

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

    event_type_val = event.type.value
    type_str = get_event_type_str(event_type_val)

    # --- RiverML Stats Update ---
    current_byte_bucket_label = "N/A"

    if type_str in ["TCP_SEND", "TCP_RECV", "WRITE_SOCK", "READ_SOCK"]:
        if event.bytes_count >= 0:
            overall_byte_model_key = (event.tgid, comm, type_str)
            update_and_get_stats_dict(
                overall_byte_stats[overall_byte_model_key], float(event.bytes_count)
            )

            if event.duration_ns > 0:
                current_byte_bucket_label = get_byte_bucket_label(event.bytes_count)
                duration_model_key = (
                    event.tgid,
                    comm,
                    type_str,
                    current_byte_bucket_label,
                )
                update_and_get_stats_dict(
                    duration_stats_by_bucket[duration_model_key],
                    float(event.duration_ns),
                )

    elif type_str == "CONNECT":
        connect_model_key = (event.tgid, comm, type_str)  # Simplified key for connect
        current_connect_models = connect_event_stats[connect_model_key]

        # Stats for connect return value
        update_and_get_stats_dict(
            current_connect_models["ret_val_stats"],
            float(event.bytes_count),  # bytes_count is ret_val
        )

        if event.duration_ns > 0:  # Connect call duration
            update_and_get_stats_dict(
                current_connect_models["duration_stats"], float(event.duration_ns)
            )


def collect_trace(
    start_indicator_file=None,
    stop_indicator_file=None,
    cgroup_indicator=None,
    output_as_table=True,
    include_regex=None,
    exclude_regex=None,
    debug=False,  # This flag is unused in provided code
):
    global running
    global as_table
    global cgroup_indicator_file
    global cgroup_id_filter
    global aggregated_data_river
    global include_patterns
    global exclude_patterns
    as_table = output_as_table
    exclude_patterns = exclude_regex
    include_patterns = include_regex
    cgroup_indicator_file = cgroup_indicator
    # aggregated_data_river.clear() # Already a defaultdict, will be new on each script run

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    if cgroup_indicator_file is not None and os.path.exists(cgroup_indicator_file):
        cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    if start_indicator_file is not None:
        helpers.log(f"Start Indicator file defined '{start_indicator_file}'. Waiting.")
        while running and not os.path.exists(start_indicator_file):
            time.sleep(0.2)
        helpers.log("Start indicator found. Proceeding.")

    helpers.log(
        "Starting eBPF for TCP network monitoring with RiverML conditional statistics."
    )
    bpf_instance = None
    try:
        bcc_debug_level = 0
        if debug:
            bcc_debug_level = BPF.DEBUG_LLVM_IR | BPF.DEBUG_BPF_BY_LLVM
        custom_cflags = []
        possible_include_paths = ["/usr/include", "/usr/local/include"]
        found_bpf_helpers = False
        for path in possible_include_paths:
            if os.path.exists(os.path.join(path, "bpf/bpf_helpers.h")):
                custom_cflags.append(f"-I{path}")
                found_bpf_helpers = True
        if not found_bpf_helpers:
            helpers.log(
                "WARNING: bpf/bpf_helpers.h not found. Ensure libbpf-dev is installed."
            )

        bpf_instance = BPF(text=bpf_text, debug=bcc_debug_level, cflags=custom_cflags)
        helpers.log("BPF C code compilation attempt complete.")
    except Exception as e:
        helpers.log(
            f"FATAL: Error initializing BPF object: {e}\n{traceback.format_exc()}",
            exit_flag=True,
        )
        return

    helpers.log("Attempting to explicitly attach all BPF programs...")
    tracepoints_to_attach = {
        "syscalls:sys_enter_socket": "tp_enter_socket",
        "syscalls:sys_exit_socket": "tp_exit_socket",
        "syscalls:sys_enter_connect": "tp_enter_connect",
        "syscalls:sys_exit_connect": "tp_exit_connect",
        "syscalls:sys_exit_accept4": "tp_exit_accept4",
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
    successful_attachments, total_defined_probes = 0, len(tracepoints_to_attach)
    for tp_name_str, fn_name_str in tracepoints_to_attach.items():
        try:
            bpf_instance.attach_tracepoint(tp=tp_name_str, fn_name=fn_name_str)
            helpers.log(f"  SUCCESS: Attached {tp_name_str} to {fn_name_str}")
            successful_attachments += 1
        except Exception as e:
            helpers.log(
                f"  WARNING: FAILED to attach {tp_name_str} to {fn_name_str}: {e}"
            )

    if successful_attachments == 0 and total_defined_probes > 0:
        helpers.log("FATAL: No BPF programs attached. Exiting.", exit_flag=True)
    elif successful_attachments < total_defined_probes:
        helpers.log(
            f"WARNING: Only {successful_attachments}/{total_defined_probes} BPF programs attached."
        )

    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf_cb, ctx=None)
        helpers.log("Ring buffer 'events' opened. Polling for events...")
        if debug:
            helpers.log(
                "BPF debug (bpf_trace_printk) in: sudo cat /sys/kernel/debug/tracing/trace_pipe"
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

        # --- Final Statistics Dump ---
        final_stats_summary = {
            "duration_stats_by_bucket": {},
            "overall_byte_stats": {},
            "connect_event_stats": {},
        }

        for (
            tgid,
            comm,
            ev_type,
            bucket,
        ), model_set in duration_stats_by_bucket.items():
            key_str = f"TGID({tgid})_COMM({comm})_EVT({ev_type})_BUCKET({bucket})"
            final_stats_summary["duration_stats_by_bucket"][key_str] = {}
            for stat_name, model_instance in model_set.items():
                val = model_instance.get()
                if isinstance(val, float) and math.isnan(val):
                    val = "N/A"
                elif val is None:
                    val = "N/A"
                final_stats_summary["duration_stats_by_bucket"][key_str][
                    stat_name
                ] = val

        for (tgid, comm, ev_type), model_set in overall_byte_stats.items():
            key_str = f"TGID({tgid})_COMM({comm})_EVT({ev_type})"
            final_stats_summary["overall_byte_stats"][key_str] = {}
            for stat_name, model_instance in model_set.items():
                val = model_instance.get()
                if isinstance(val, float) and math.isnan(val):
                    val = "N/A"
                elif val is None:
                    val = "N/A"
                final_stats_summary["overall_byte_stats"][key_str][stat_name] = val

        for (
            tgid,
            comm,
            ev_type,
        ), model_sets_for_connect in (
            connect_event_stats.items()
        ):  # ev_type is "CONNECT"
            key_str = f"TGID({tgid})_COMM({comm})_EVT({ev_type})"
            final_stats_summary["connect_event_stats"][key_str] = {}
            for (
                model_type,
                stat_dict,
            ) in model_sets_for_connect.items():  # 'duration_stats' or 'ret_val_stats'
                final_stats_summary["connect_event_stats"][key_str][model_type] = {}
                for stat_name, model_instance in stat_dict.items():
                    val = model_instance.get()
                    if isinstance(val, float) and math.isnan(val):
                        val = "N/A"
                    elif val is None:
                        val = "N/A"
                    final_stats_summary["connect_event_stats"][key_str][model_type][
                        stat_name
                    ] = val

        helpers.log("\n--- FINAL AGGREGATED STATISTICS (JSON) ---")
        print(json.dumps(final_stats_summary, indent=2, sort_keys=True))
        helpers.log("--- END OF FINAL STATISTICS ---")
