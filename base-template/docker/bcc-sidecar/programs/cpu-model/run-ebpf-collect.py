#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import time
import os
import re
import sys
import json
import signal
import traceback
from collections import defaultdict
from river import stats

# Global state
running = True
as_table = True
include_patterns = None
excude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__))

# Key: (tgid, comm_str),
# Value: dict of River stats models
aggregated_data_river = defaultdict(
    lambda: {
        # For Mean, Var, Count, Sum (derived)
        "on_cpu_ns_var": stats.Var(),
        "on_cpu_ns_min": stats.Min(),
        "on_cpu_ns_max": stats.Max(),
        "on_cpu_ns_median": stats.Quantile(0.50),  # Median
        "on_cpu_ns_q1": stats.Quantile(0.25),  # 1st Quartile
        "on_cpu_ns_q3": stats.Quantile(0.75),  # 3rd Quartile
        # For Mean, Var, Count, Sum (derived)
        "runq_latency_ns_var": stats.Var(),
        "runq_latency_ns_min": stats.Min(),
        "runq_latency_ns_max": stats.Max(),
        "runq_latency_ns_median": stats.Quantile(0.50),
        "runq_latency_ns_q1": stats.Quantile(0.25),
        "runq_latency_ns_q3": stats.Quantile(0.75),
        # Store last seen cgroup_id
        "cgroup_id": 0,
        # Timestamp of first event for this group
        "first_seen_ts_ns": 0,
        # Timestamp of last event for this group
        "last_seen_ts_ns": 0,
    }
)

# From the C code
TASK_COMM_LEN_PY = 16


class SchedEventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("on_cpu_ns", ct.c_ulonglong),
        ("runq_latency_ns", ct.c_ulonglong),
        ("event_type", ct.c_ubyte),
        ("prev_state_task_switched_out", ct.c_ubyte),
    ]


def aggregate_event_data_river_callback(cpu, data, size):
    """
    Aggregation Callback using RiverML ---
    """
    global aggregated_data_river
    global include_patterns
    global excude_patterns
    global cgroup_id_filter

    event = ct.cast(data, ct.POINTER(SchedEventData)).contents
    comm = event.comm.decode("utf-8", "replace").strip("\\x00").strip()

    if include_patterns and not any(p.search(comm) for p in include_patterns):
        return
    if excude_patterns and any(p.search(comm) for p in excude_patterns):
        return
    if cgroup_id_filter is not None and str(event.cgroup_id) != cgroup_id_filter:
        return

    agg_key = (event.tgid, comm)
    river_stats = aggregated_data_river[agg_key]

    river_stats["cgroup_id"] = event.cgroup_id
    if river_stats["first_seen_ts_ns"] == 0:  # First event for this group
        river_stats["first_seen_ts_ns"] = event.timestamp_ns
    river_stats["last_seen_ts_ns"] = event.timestamp_ns

    if event.on_cpu_ns > 0:
        river_stats["on_cpu_ns_var"].update(event.on_cpu_ns)
        river_stats["on_cpu_ns_min"].update(event.on_cpu_ns)
        river_stats["on_cpu_ns_max"].update(event.on_cpu_ns)
        river_stats["on_cpu_ns_median"].update(event.on_cpu_ns)
        river_stats["on_cpu_ns_q1"].update(event.on_cpu_ns)
        river_stats["on_cpu_ns_q3"].update(event.on_cpu_ns)

    if event.runq_latency_ns > 0:
        river_stats["runq_latency_ns_var"].update(event.runq_latency_ns)
        river_stats["runq_latency_ns_min"].update(event.runq_latency_ns)
        river_stats["runq_latency_ns_max"].update(event.runq_latency_ns)
        river_stats["runq_latency_ns_median"].update(event.runq_latency_ns)
        river_stats["runq_latency_ns_q1"].update(event.runq_latency_ns)
        river_stats["runq_latency_ns_q3"].update(event.runq_latency_ns)


def ns_to_ms_str(ns_val):
    return f"{ns_val / 1e6:.3f}" if ns_val is not None else "N/A"


def ns_to_s_str(ns_val):
    return f"{ns_val / 1e9:.3f}" if ns_val is not None else "N/A"


def print_final_summary_river():
    global aggregated_data_river
    global as_table

    if not aggregated_data_river:
        if as_table:
            print("No aggregated data (River) to display.")
        return

    summary_list_for_json = []

    if as_table:
        print("\n--- Aggregated CPU Scheduler Stats Summary (RiverML) ---")
        header1 = f"{'TGID':<7} {'COMM':<15} {'CGROUP':<10} | {'COUNT':>7} {'SUM_CPU_s':>10} {'MEAN_CPU_ms':>11} {'MED_CPU_ms':>10} {'MIN_CPU_ms':>10} {'MAX_CPU_ms':>10} {'VAR_CPU_ms2':>11} {'IQR_CPU_ms':>10} |"
        header2 = f"{'':<35} | {'COUNT':>7} {'SUM_RUNQ_s':>11} {'MEAN_RUNQ_ms':>12} {'MED_RUNQ_ms':>11} {'MIN_RUNQ_ms':>11} {'MAX_RUNQ_ms':>11} {'VAR_RUNQ_ms2':>12} {'IQR_RUNQ_ms':>11} |"
        print(header1)
        print(header2)
        print("-" * (len(header1) + len(header2) - 35 + 2))

    # Sort by total on-CPU time. We need to calculate sum for sorting.
    # Sum = Mean * N
    sorted_summary = sorted(
        aggregated_data_river.items(),
        key=lambda item: (
            (item[1]["on_cpu_ns_var"].mean.get() * item[1]["on_cpu_ns_var"].n)
            if item[1]["on_cpu_ns_var"].n > 0
            and item[1]["on_cpu_ns_var"].mean.get() is not None
            else 0
        ),
        reverse=True,
    )

    for (tgid, comm), river_stats_dict in sorted_summary:

        # On CPU Stats
        oc_var_obj = river_stats_dict["on_cpu_ns_var"]
        oc_min_obj = river_stats_dict["on_cpu_ns_min"]
        oc_max_obj = river_stats_dict["on_cpu_ns_max"]
        oc_med_obj = river_stats_dict["on_cpu_ns_median"]
        oc_q1_obj = river_stats_dict["on_cpu_ns_q1"]
        oc_q3_obj = river_stats_dict["on_cpu_ns_q3"]

        oc_count = oc_var_obj.n
        oc_mean_ns = oc_var_obj.mean.get() if oc_count > 0 else None
        oc_sum_ns = (
            (oc_mean_ns * oc_count) if oc_mean_ns is not None and oc_count > 0 else 0
        )
        oc_median_ns = oc_med_obj.get() if oc_count > 0 else None
        oc_min_ns = oc_min_obj.get() if oc_count > 0 else None
        oc_max_ns = oc_max_obj.get() if oc_count > 0 else None
        oc_variance_ns2 = oc_var_obj.get() if oc_count > 1 else None
        oc_q1_val = oc_q1_obj.get() if oc_count > 0 else None
        oc_q3_val = oc_q3_obj.get() if oc_count > 0 else None
        oc_iqr_ns = (
            (oc_q3_val - oc_q1_val)
            if oc_q1_val is not None and oc_q3_val is not None
            else None
        )

        # Runq Latency Stats
        rq_var_obj = river_stats_dict["runq_latency_ns_var"]
        rq_min_obj = river_stats_dict["runq_latency_ns_min"]
        rq_max_obj = river_stats_dict["runq_latency_ns_max"]
        rq_med_obj = river_stats_dict["runq_latency_ns_median"]
        rq_q1_obj = river_stats_dict["runq_latency_ns_q1"]
        rq_q3_obj = river_stats_dict["runq_latency_ns_q3"]

        rq_count = rq_var_obj.n
        rq_mean_ns = rq_var_obj.mean.get() if rq_count > 0 else None
        rq_sum_ns = (
            (rq_mean_ns * rq_count) if rq_mean_ns is not None and rq_count > 0 else 0
        )
        rq_median_ns = rq_med_obj.get() if rq_count > 0 else None
        rq_min_ns = rq_min_obj.get() if rq_count > 0 else None
        rq_max_ns = rq_max_obj.get() if rq_count > 0 else None
        rq_variance_ns2 = rq_var_obj.get() if rq_count > 1 else None
        rq_q1_val = rq_q1_obj.get() if rq_count > 0 else None
        rq_q3_val = rq_q3_obj.get() if rq_count > 0 else None
        rq_iqr_ns = (
            (rq_q3_val - rq_q1_val)
            if rq_q1_val is not None and rq_q3_val is not None
            else None
        )

        cgroup_disp = str(river_stats_dict["cgroup_id"])[:10]
        if as_table:
            # Note: Variance is in (ns^2), converting to (ms^2) might be confusing.
            # For display, it might be better to show variance in (ns^2) or its sqrt (std dev) in ns/ms.
            # Let's display variance in (ms_value)^2 if we convert the value, or keep it raw.
            # For simplicity, I'll convert the value to ms and then square it, but label it ms2.
            # This is not strictly (ms)^2 in unit terms but rather (value_in_ms)^2.
            # A better way would be var_ns2 / (1e6 * 1e6) for units of ms^2.
            oc_variance_display = (
                (oc_variance_ns2 / (1e6 * 1e6)) if oc_variance_ns2 is not None else None
            )
            rq_variance_display = (
                (rq_variance_ns2 / (1e6 * 1e6)) if rq_variance_ns2 is not None else None
            )

            row1 = f"{tgid:<7} {comm:<15} {cgroup_disp:<10} | {oc_count:>7} {ns_to_s_str(oc_sum_ns):>10} {ns_to_ms_str(oc_mean_ns):>11} {ns_to_ms_str(oc_median_ns):>10} {ns_to_ms_str(oc_min_ns):>10} {ns_to_ms_str(oc_max_ns):>10} {f'{oc_variance_display:.3f}' if oc_variance_display is not None else 'N/A':>11} {ns_to_ms_str(oc_iqr_ns):>10} |"
            row2 = f"{'':<35} | {rq_count:>7} {ns_to_s_str(rq_sum_ns):>11} {ns_to_ms_str(rq_mean_ns):>12} {ns_to_ms_str(rq_median_ns):>11} {ns_to_ms_str(rq_min_ns):>11} {ns_to_ms_str(rq_max_ns):>11} {f'{rq_variance_display:.3f}' if rq_variance_display is not None else 'N/A':>12} {ns_to_ms_str(rq_iqr_ns):>11} |"
            print(row1)
            print(row2)

        # This is probably the best way to print
        else:
            summary_list_for_json.append(
                {
                    "tgid": tgid,
                    "comm": comm,
                    "cgroup_id": river_stats_dict["cgroup_id"],
                    "on_cpu_stats_ns": {
                        "count": oc_count,
                        "sum": oc_sum_ns,
                        "mean": oc_mean_ns,
                        "median": oc_median_ns,
                        "min": oc_min_ns,
                        "max": oc_max_ns,
                        "variance_ns2": oc_variance_ns2,
                        "iqr_ns": oc_iqr_ns,
                        "q1_ns": oc_q1_val,
                        "q3_ns": oc_q3_val,
                    },
                    "runq_latency_stats_ns": {
                        "count": rq_count,
                        "sum": rq_sum_ns,
                        "mean": rq_mean_ns,
                        "median": rq_median_ns,
                        "min": rq_min_ns,
                        "max": rq_max_ns,
                        "variance_ns2": rq_variance_ns2,
                        "iqr_ns": rq_iqr_ns,
                        "q1_ns": rq_q1_val,
                        "q3_ns": rq_q3_val,
                    },
                    "first_seen_ts_ns": river_stats_dict["first_seen_ts_ns"],
                    "last_seen_ts_ns": river_stats_dict["last_seen_ts_ns"],
                    "duration_active_s": (
                        (
                            river_stats_dict["last_seen_ts_ns"]
                            - river_stats_dict["first_seen_ts_ns"]
                        )
                        / 1e9
                        if river_stats_dict["first_seen_ts_ns"] > 0
                        else 0
                    ),
                }
            )

    if not as_table and summary_list_for_json:
        # Use indent for pretty printing JSON
        print(
            json.dumps(
                {"final_aggregated_summary_river": summary_list_for_json}, indent=2
            )
        )


def signal_stop_handler(signum, frame):
    global running
    helpers.log(
        f"Signal {signal.Signals(signum).name} received, stopping...", file=sys.stderr
    )
    running = False


def collect_trace(
    start_indicator_file_arg=None,
    stop_indicator_file_arg=None,
    output_as_table_arg=True,
    enable_debug_flag_arg=False,
):
    global running
    global as_table
    global cgroup_indicator_file
    global cgroup_id_filter
    global aggregated_data_river

    as_table = output_as_table_arg

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    # if a cgroup filter is set
    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    bpf_instance = None
    try:
        helpers.log("Initializing eBPF for CPU Scheduling monitoring...")
        bpf_instance = BPF(text=bpf_text)
        helpers.log("BPF C code compiled and loaded.")

        bpf_instance.attach_tracepoint(
            tp="sched:sched_wakeup", fn_name="tp_sched_wakeup"
        )
        bpf_instance.attach_tracepoint(
            tp="sched:sched_wakeup_new", fn_name="tp_sched_wakeup_new"
        )
        bpf_instance.attach_tracepoint(
            tp="sched:sched_switch", fn_name="tp_sched_switch"
        )
        helpers.log("Attached tracepoints.")

        events_table = bpf_instance.get_table("events_out")
        events_table.open_perf_buffer(aggregate_event_data_river_callback)
        helpers.log("Perf buffer 'events_out' opened.")

        # if enable_debug_flag_arg and hasattr(bpf_instance, 'get_table') and "debug_events_out" in bpf_instance.tables:
        #     debug_table = bpf_instance.get_table("debug_events_out")
        #     debug_table.open_perf_buffer(print_debug_callback_function) # You'd need this callback
        #     helpers.log("Debug perf buffer opened.")

        if start_indicator_file_arg is not None:
            helpers.log(
                f"Waiting for start indicator file: '{start_indicator_file_arg}'."
            )
            while running and not os.path.exists(start_indicator_file_arg):
                time.sleep(0.2)
            if not running:
                helpers.log("Stopped while waiting for start.")
                return
            helpers.log("Start indicator found. Proceeding with monitoring.")

        if as_table:
            print(  # Per-event table header
                f"{'TIMESTAMP':<18} {'COMM':<15} {'TID':<7} {'TGID':<7} "
                f"{'CGROUP':<10} {'ON_CPU_MS':>10} {'RUNQ_LAT_MS':>12} {'PREV_STATE':>10}"
            )
            print("-" * 100)

        helpers.log("Monitoring CPU scheduling events... Press Ctrl+C to stop.")
        while running:
            try:
                bpf_instance.perf_buffer_poll(timeout=100)
                if stop_indicator_file_arg is not None and os.path.exists(
                    stop_indicator_file_arg
                ):
                    helpers.log(
                        f"Stop indicator file '{stop_indicator_file_arg}' found. Stopping."
                    )
                    running = False

                if not running:
                    break
            except Exception as e_poll:
                helpers.log(f"Error during perf_buffer_poll: {e_poll}")
                time.sleep(0.1)

    except Exception as e:
        helpers.log(f"Error or interrupt during BPF setup or main loop: {e}")
        traceback.print_exc()
        running = False
    finally:
        helpers.log("Initiating cleanup sequence...")
        print_final_summary_river()

        if bpf_instance:
            helpers.log("Cleaning up BPF instance...")
            bpf_instance.cleanup()
        helpers.log("Cleanup complete. Exiting.")


def main():
    global include_patterns
    global excude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        helpers.log("This script must be run as root.", exit_flag=True)

    parser = helpers.get_parser("eBPF CPU Scheduler Analyzer with RiverML full stats.")
    args, _ = parser.parse_known_args()

    if args.include_pattern:
        include_patterns = [re.compile(p) for p in args.include_pattern]
    if args.exclude_pattern:
        excude_patterns = [re.compile(p) for p in args.exclude_pattern]

    cgroup_indicator_file = args.cgroup_indicator_file

    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,  # as_table
        args.debug,
    )


if __name__ == "__main__":
    main()
