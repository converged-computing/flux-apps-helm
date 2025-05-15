#!/usr/bin/python3

"""
Use eBPF (Extended Berkeley Packet Filter) to measure the duration of time threads spend waiting on futexes via FUTEX_WAIT operations.
... (your existing comments) ...
"""

from bcc import BPF
import ctypes as ct
import re
import os
import json
import signal
import traceback
import time
import sys
from collections import defaultdict
from river import stats

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

# --- RiverML Aggregation Dictionary ---
# Key: (tgid, comm_str), Value: dict of River stats objects for wait_duration_ns
aggregated_river_stats = defaultdict(
    lambda: {
        "wait_duration_var": stats.Var(),
        "wait_duration_min": stats.Min(),
        "wait_duration_max": stats.Max(),
        "wait_duration_median": stats.Quantile(0.50),
        "wait_duration_q1": stats.Quantile(0.25),
        "wait_duration_q3": stats.Quantile(0.75),
        "cgroup_id": 0,
        "futex_op_counts": defaultdict(int),
        "first_seen_ts_ns": 0,
        "last_seen_ts_ns": 0,
    }
)

# Python constants
TASK_COMM_LEN_PY = 16
FUTEX_OP_DISPLAY_WIDTH = 22
DURATION_DISPLAY_WIDTH = 15


# Ctypes structure for futex events (Your existing definition)
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


# Ctypes structure for debug events (Your existing definition)
class DebugEventData(ct.Structure):
    _fields_ = [
        ("id_tid", ct.c_uint),
        ("stage", ct.c_int),
        ("val1_op", ct.c_long),
        ("val2_duration_or_misc", ct.c_long),
    ]


# Python-side FUTEX constants (Your existing definitions)
FUTEX_WAIT_PY = 0
FUTEX_PRIVATE_FLAG_PY = 128
FUTEX_CLOCK_REALTIME_PY = 256
FUTEX_WAIT_PRIVATE_PY = FUTEX_WAIT_PY | FUTEX_PRIVATE_FLAG_PY

# Python-side debug stage constants (Your existing definitions)
DBG_FUTEX_ENTER_TRACKING_PY = 400
DBG_FUTEX_ENTER_NOT_TRACKING_PY = 401
DBG_FUTEX_EXIT_FOUND_START_PY = 402
DBG_FUTEX_EXIT_NO_START_PY = 403
DBG_FUTEX_SUBMITTED_PY = 404
DBG_FUTEX_RESERVE_FAIL_PY = 405


def get_futex_operation(op_full):  # Your existing function
    op_cmd = op_full & ~(FUTEX_PRIVATE_FLAG_PY | FUTEX_CLOCK_REALTIME_PY)
    s = ""
    if op_cmd == FUTEX_WAIT_PY:
        s = "FUTEX_WAIT"
    else:
        s = f"OP_{op_cmd}"
    if op_full & FUTEX_PRIVATE_FLAG_PY:
        s += "_PRIVATE"
    if op_full & FUTEX_CLOCK_REALTIME_PY:
        s += "_REALTIME"
    return s


def format_duration(ns):  # Your existing function
    if ns == 0:
        return "0ns"
    if ns < 1000:
        return f"{ns}ns"
    if ns < 1000000:
        return f"{ns/1000.0:.2f}us"
    if ns < 1000000000:
        return f"{ns/1000000.0:.2f}ms"
    return f"{ns/1000000000.0:.2f}s"


def print_event_ringbuf(ctx, data, size):
    global as_table, include_patterns, exclude_patterns, cgroup_indicator_file, cgroup_id_filter
    global aggregated_river_stats, args  # Need args for args.json to control per-event printing format

    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    event = ct.cast(data, ct.POINTER(FutexEventData)).contents
    try:
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    except:
        comm = "<comm_err>"

    # Apply filters before aggregation and per-event printing
    if include_patterns and not any(p.search(comm) for p in include_patterns):
        return
    if exclude_patterns and any(p.search(comm) for p in exclude_patterns):
        return
    if cgroup_id_filter is not None and str(event.cgroup_id) != cgroup_id_filter:
        return

    # --- Update River Stats ---
    if event.wait_duration_ns >= 0:
        agg_key = (event.tgid, comm)
        river_stats = aggregated_river_stats[agg_key]

        river_stats["cgroup_id"] = event.cgroup_id
        if river_stats["first_seen_ts_ns"] == 0:
            river_stats["first_seen_ts_ns"] = event.timestamp_ns
        river_stats["last_seen_ts_ns"] = event.timestamp_ns
        river_stats["wait_duration_var"].update(event.wait_duration_ns)
        river_stats["wait_duration_min"].update(event.wait_duration_ns)
        river_stats["wait_duration_max"].update(event.wait_duration_ns)
        river_stats["wait_duration_median"].update(event.wait_duration_ns)
        river_stats["wait_duration_q1"].update(event.wait_duration_ns)
        river_stats["wait_duration_q3"].update(event.wait_duration_ns)
        river_stats["futex_op_counts"][event.futex_op_full] += 1


def print_futex_json(
    event, comm, futex_op_str, duration_str, timestamp_sec
):  # Your function
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


def print_futex_table_row(
    event, comm, futex_operation, duration, timestamp_sec
):  # Your function
    print(
        f"{timestamp_sec:<18.6f} {event.tgid:<7} {event.tid:<7} {comm:<{TASK_COMM_LEN_PY}} "
        f"{futex_operation:<{FUTEX_OP_DISPLAY_WIDTH}} {duration:>{DURATION_DISPLAY_WIDTH}}"
    )


def print_debug_event(ctx, data, size):  # Your function
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


def ns_to_ms_str(ns_val):
    return (
        f"{ns_val / 1e6:.3f}"
        if ns_val is not None and isinstance(ns_val, (int, float))
        else "N/A"
    )


def print_final_river_summary():
    global aggregated_river_stats
    global as_table

    if not aggregated_river_stats:
        if as_table:
            print("No aggregated futex data (River) to display.")
        return
    summary_list_for_json = []

    if as_table:
        print("\n--- Aggregated Futex Wait Stats Summary (RiverML) ---")
        header = (
            f"{'TGID':<7} {'COMM':<15} {'CGROUP':<10} {'COUNT':>7} {'SUM_WAIT_s':>11} "
            f"{'MEAN_ms':>9} {'MED_ms':>8} {'MIN_ms':>8} {'MAX_ms':>8} "
            f"{'VAR_ms2':>9} {'IQR_ms':>8} {'OPS':<25}"
        )
        print(header)
        print("-" * len(header))

    sorted_summary = sorted(
        aggregated_river_stats.items(),
        key=lambda item: (
            (item[1]["wait_duration_var"].mean.get() * item[1]["wait_duration_var"].n)
            if item[1]["wait_duration_var"].n > 0
            and item[1]["wait_duration_var"].mean.get() is not None
            else 0
        ),
        reverse=True,
    )

    for (tgid, comm), river_stats_dict in sorted_summary:
        var_obj = river_stats_dict["wait_duration_var"]
        min_obj = river_stats_dict["wait_duration_min"]
        max_obj = river_stats_dict["wait_duration_max"]
        med_obj = river_stats_dict["wait_duration_median"]
        q1_obj = river_stats_dict["wait_duration_q1"]
        q3_obj = river_stats_dict["wait_duration_q3"]

        count = var_obj.n
        mean_ns = var_obj.mean.get() if count > 0 else None
        sum_ns = (mean_ns * count) if mean_ns is not None and count > 0 else 0
        median_ns = med_obj.get() if count > 0 else None
        min_ns = min_obj.get() if count > 0 else None
        max_ns = max_obj.get() if count > 0 else None
        variance_ns2 = var_obj.get() if count > 1 else None  # Var needs >1 point
        q1_val_ns = q1_obj.get() if count > 0 else None
        q3_val_ns = q3_obj.get() if count > 0 else None
        iqr_ns = (
            (q3_val_ns - q1_val_ns)
            if q1_val_ns is not None and q3_val_ns is not None
            else None
        )

        cgroup_disp = str(river_stats_dict["cgroup_id"])[:10]
        op_counts_summary = ", ".join(
            [
                f"{get_futex_operation(op)}({c})"
                for op, c in sorted(river_stats_dict["futex_op_counts"].items())
            ][:2]
        )
        if len(river_stats_dict["futex_op_counts"]) > 2:
            op_counts_summary += "..."

        if as_table:
            variance_display_ms2 = (
                (variance_ns2 / (1e6 * 1e6)) if variance_ns2 is not None else None
            )
            print(
                f"{tgid:<7} {comm:<15} {cgroup_disp:<10} {count:>7} {sum_ns / 1e9:>11.3f} "
                f"{ns_to_ms_str(mean_ns):>9} {ns_to_ms_str(median_ns):>8} {ns_to_ms_str(min_ns):>8} {ns_to_ms_str(max_ns):>8} "
                f"{f'{variance_display_ms2:.3f}' if variance_display_ms2 is not None else 'N/A':>9} {ns_to_ms_str(iqr_ns):>8} {op_counts_summary:<25}"
            )
        else:  # JSON for summary
            summary_list_for_json.append(
                {
                    "tgid": tgid,
                    "comm": comm,
                    "cgroup_id": river_stats_dict["cgroup_id"],
                    "wait_duration_stats_ns": {
                        "count": count,
                        "sum": sum_ns,
                        "mean": mean_ns,
                        "median": median_ns,
                        "min": min_ns,
                        "max": max_ns,
                        "variance_ns2": variance_ns2,
                        "iqr_ns": iqr_ns,
                        "q1_ns": q1_val_ns,
                        "q3_ns": q3_val_ns,
                    },
                    "futex_op_counts": dict(river_stats_dict["futex_op_counts"]),
                    "first_seen_ts_ns": river_stats_dict["first_seen_ts_ns"],
                    "last_seen_ts_ns": river_stats_dict["last_seen_ts_ns"],
                }
            )
    if not as_table and summary_list_for_json:
        print(
            json.dumps(
                {"final_aggregated_futex_summary_river": summary_list_for_json},
                indent=2,
            )
        )


def signal_stop_handler(signum, frame):  # Your function
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def print_futex_table_header():  # Your function
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
    global cgroup_id_filter
    global aggregated_river_stats
    as_table = table

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    helpers.log("Starting eBPF (Tracepoints for futex syscalls).")
    bpf_instance = None
    try:
        bpf_instance = BPF(text=bpf_text, debug=0)  # bpf_text is global
        helpers.log("BPF program loaded and tracepoints automatically attached.")
    except Exception as e:
        helpers.log(f"Error initializing/attaching BPF: {e}", exit_flag=True)

    # Initial read of cgroup filter from file if cgroup_indicator_file (global) is set
    if cgroup_indicator_file and os.path.exists(cgroup_indicator_file):
        helpers.get_cgroup_filter(cgroup_indicator_file)

    if start_indicator_file is not None:
        helpers.log(f"Start Indicator file defined '{start_indicator_file}'. Waiting.")
        while running and not os.path.exists(start_indicator_file):
            time.sleep(0.2)
        helpers.log("Start indicator found. Proceeding.")

    # Print per-event table header if table output is chosen for events
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
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False

            if not running:
                break
    except Exception as e:
        helpers.log(f"Error or interrupt during polling: {e}\n{traceback.format_exc()}")
        running = False
    finally:
        helpers.log("Cleaning up BPF resources...")
        if aggregated_river_stats:
            print_final_river_summary()
        if bpf_instance:
            bpf_instance.cleanup()
        helpers.log("Cleanup complete.")


def main():
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = helpers.get_parser("eBPF Futex Wait Time Analyzer.")
    args, _ = parser.parse_known_args()

    # Compile regex patterns from args and store in globals
    if args.include_pattern:
        include_patterns = [re.compile(p) for p in args.include_pattern]
    if args.exclude_pattern:
        exclude_patterns = [re.compile(p) for p in args.exclude_pattern]

    cgroup_indicator_file = args.cgroup_indicator_file  # Set global path

    # Call collect_trace with its original signature
    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,  # as_table
        args.debug,
    )


if __name__ == "__main__":
    main()
