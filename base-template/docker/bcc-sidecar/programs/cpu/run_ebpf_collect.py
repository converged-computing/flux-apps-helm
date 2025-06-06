#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import time
import os
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
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

# Ensure you pass the correct path to your NEW BPF C code
bpf_text = helpers.read_bpf_text(os.path.join(here, "ebpf-collect.c"))

# Key: (tgid, comm_str),
# Value: dict of River stats models
aggregated_data_river = defaultdict(
    lambda: {
        "on_cpu_ns_var": stats.Var(),
        "on_cpu_ns_min": stats.Min(),
        "on_cpu_ns_max": stats.Max(),
        "on_cpu_ns_median": stats.Quantile(0.50),
        "on_cpu_ns_q1": stats.Quantile(0.25),
        "on_cpu_ns_q3": stats.Quantile(0.75),
        "runq_latency_ns_var": stats.Var(),
        "runq_latency_ns_min": stats.Min(),
        "runq_latency_ns_max": stats.Max(),
        "runq_latency_ns_median": stats.Quantile(0.50),
        "runq_latency_ns_q1": stats.Quantile(0.25),
        "runq_latency_ns_q3": stats.Quantile(0.75),
        "cgroup_id": 0,
        "first_seen_ts_ns": 0,
        "last_seen_ts_ns": 0,
    }
)

# From the C code (remains for compatibility, though SchedEventData is not directly used)
TASK_COMM_LEN_PY = 16
CGROUP_FS_ROOT = "/sys/fs/cgroup"  # Standard for cgroup v2 unified hierarchy

# Process info cache to reduce /proc lookups
_process_info_cache = {}
_CACHE_EXPIRY_TIME_SEC = 2  # How long to keep a cache entry valid
_TID_NOT_FOUND_CACHE_EXPIRY_SEC = (
    10  # Longer cache for TIDs that were not found (likely exited)
)
_tid_not_found_cache = {}


class SchedEventData(ct.Structure):  # Unused by new BPF code, kept for "minimal change"
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


def get_process_info(tid_int):
    """
    Get process info from /proc

    We get this in user space because it helps the c code be more efficient.
    """
    current_time_monotonic = time.monotonic()

    if (
        tid_int in _tid_not_found_cache
        and (current_time_monotonic - _tid_not_found_cache[tid_int])
        < _TID_NOT_FOUND_CACHE_EXPIRY_SEC
    ):
        return None  # Still in not-found cache

    cached_info = _process_info_cache.get(tid_int)
    if (
        cached_info
        and (current_time_monotonic - cached_info["timestamp_mono"])
        < _CACHE_EXPIRY_TIME_SEC
    ):
        return cached_info

    try:
        comm_str = "N/A"
        tgid_int = tid_int  # Default tgid to tid if not found
        cgroup_id_val = 0
        proc_tid_path = f"/proc/{tid_int}"

        with open(f"{proc_tid_path}/comm", "r") as f:
            comm_str = f.read().strip()

        with open(f"{proc_tid_path}/status", "r") as f:
            for line in f:
                if line.startswith("Tgid:"):
                    tgid_int = int(line.split(":", 1)[1].strip())
                    break

        # Get cgroup ID (inode of the cgroup directory)
        with open(f"{proc_tid_path}/cgroup", "r") as f_cgroup:
            for line_cg in f_cgroup:
                parts = line_cg.strip().split(":")
                if len(parts) >= 3:
                    cgroup_path_suffix = parts[-1]
                    if cgroup_path_suffix.startswith("/"):
                        full_cgroup_path = os.path.join(
                            CGROUP_FS_ROOT, cgroup_path_suffix.lstrip("/")
                        )
                        if os.path.exists(full_cgroup_path):
                            cgroup_id_val = os.stat(full_cgroup_path).st_ino
                            break
                        # Attempt fallback for common Docker cgroupfs (e.g., with 'cpu' controller)
                        # This can be environment-specific
                        for controller_subdir in [
                            "cpu",
                            "cpuacct",
                            "cpuset",
                            "",
                        ]:  # common controller names or unified path
                            alt_path_parts = [CGROUP_FS_ROOT]
                            if controller_subdir:
                                alt_path_parts.append(controller_subdir)
                            alt_path_parts.append(cgroup_path_suffix.lstrip("/"))
                            alt_path = os.path.join(*alt_path_parts)
                            if os.path.exists(alt_path):
                                cgroup_id_val = os.stat(alt_path).st_ino
                                break
                        # This means we found it
                        if cgroup_id_val != 0:
                            break
            # If still 0, means cgroup path resolution failed or not found.

        info = {
            "comm": comm_str,
            "tgid": tgid_int,
            "cgroup_id": cgroup_id_val,
            "timestamp_mono": current_time_monotonic,
        }
        _process_info_cache[tid_int] = info

        # Remove from not-found if now found
        if tid_int in _tid_not_found_cache:
            del _tid_not_found_cache[tid_int]
        return info

    # Add to not-found cache
    except FileNotFoundError:
        _tid_not_found_cache[tid_int] = current_time_monotonic
        return None

    # Other errors (e.g., permission, process racingly exited mid-read)
    except Exception:
        # helpers.log(f"Error fetching info for tid {tid_int}: {e_proc}", "DEBUG")
        return None


def ns_to_ms_str(ns_val):
    return f"{ns_val / 1e6:.3f}" if ns_val is not None else "N/A"


def ns_to_s_str(ns_val):
    return f"{ns_val / 1e9:.3f}" if ns_val is not None else "N/A"


def print_final_summary_river():
    """
    Print the final summary of river models.
    """
    global aggregated_data_river
    global as_table

    if not aggregated_data_river:
        if as_table:
            print("No aggregated data (River) to display.")
        # Also print for JSON if empty (it should not be empty!)
        else:
            print(json.dumps({"final_aggregated_summary_river": []}, indent=2))
        return

    summary_list_for_json = []

    if as_table:
        print("\n--- Aggregated CPU Scheduler Stats Summary (RiverML) ---")
        header1 = f"{'TGID':<7} {'COMM':<15} {'CGROUP':<10} | {'COUNT':>7} {'SUM_CPU_s':>10} {'MEAN_CPU_ms':>11} {'MED_CPU_ms':>10} {'MIN_CPU_ms':>10} {'MAX_CPU_ms':>10} {'VAR_CPU_ms2':>11} {'IQR_CPU_ms':>10} |"
        header2 = f"{'':<35} | {'COUNT':>7} {'SUM_RUNQ_s':>11} {'MEAN_RUNQ_ms':>12} {'MED_RUNQ_ms':>11} {'MIN_RUNQ_ms':>11} {'MAX_RUNQ_ms':>11} {'VAR_RUNQ_ms2':>12} {'IQR_RUNQ_ms':>11} |"
        print(header1)
        print(header2)
        print("-" * (len(header1) + len(header2) - 35 + 2))

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
        cgroup_disp = str(river_stats_dict["cgroup_id"])[:10]  # For table display

        if as_table:
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
        else:
            summary_item = {
                "tgid": tgid,
                "comm": comm,
                "cgroup_id": river_stats_dict["cgroup_id"],  # Use the full cgroup_id
                "on_cpu_stats_ns": {
                    "count": oc_count,
                    "sum_ns": oc_sum_ns,
                    "mean_ns": oc_mean_ns,
                    "median_ns": oc_median_ns,
                    "min_ns": oc_min_ns,
                    "max_ns": oc_max_ns,
                    "variance_ns2": oc_variance_ns2,
                    "iqr_ns": oc_iqr_ns,
                    "q1_ns": oc_q1_val,
                    "q3_ns": oc_q3_val,
                },
                "runq_latency_stats_ns": {
                    "count": rq_count,
                    "sum_ns": rq_sum_ns,
                    "mean_ns": rq_mean_ns,
                    "median_ns": rq_median_ns,
                    "min_ns": rq_min_ns,
                    "max_ns": rq_max_ns,
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
                    and river_stats_dict["last_seen_ts_ns"]
                    > river_stats_dict["first_seen_ts_ns"]
                    else 0
                ),
            }
            summary_list_for_json.append(summary_item)

    if not as_table and summary_list_for_json:
        print(
            json.dumps(
                {"final_aggregated_summary_river": summary_list_for_json}, indent=2
            )
        )
    elif not as_table and not summary_list_for_json:
        print(json.dumps({"final_aggregated_summary_river": []}, indent=2))


def signal_stop_handler(signum, frame):
    global running
    helpers.log(f"Signal {signal.Signals(signum).name} received, stopping...")
    running = False


def collect_trace(
    start_indicator_file=None,
    stop_indicator_file=None,
    cgroup_indicator=None,
    output_as_table=True,
    include_regex=None,
    exclude_regex=None,
    interval=100,
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

    if cgroup_indicator_file is not None and cgroup_id_filter is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)
            helpers.log(f"Applied cgroup ID filter: {cgroup_id_filter}")

    if start_indicator_file is not None:
        helpers.log(f"Waiting for start indicator file: '{start_indicator_file}'.")
        while running and not os.path.exists(start_indicator_file):
            time.sleep(0.2)
        if not running:
            return
        helpers.log("Start indicator found. Proceeding with monitoring.")

    bpf_instance = None
    polling_interval_seconds = interval / 1000

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

        # Get the BPF map for aggregated stats
        agg_stats_map = bpf_instance.get_table("aggregated_task_stats")

        helpers.log(
            "Monitoring CPU scheduling events (polling aggregated map)... Press Ctrl+C to stop."
        )

        while running:

            # Polling interval
            time.sleep(polling_interval_seconds)

            # Timestamp for this polling batch
            current_loop_ts_ns = time.time_ns()

            # Iterate over aggregated_task_stats map
            # For PERCPU_HASH, items() returns a list of values (one per CPU) for each key
            for tid_bpf, stats_per_cpu_list in agg_stats_map.items():
                tid_val = tid_bpf.value  # This is the Thread ID (kernel PID)

                # Aggregate stats from all CPUs for this TID for this interval
                interval_total_on_cpu_ns = 0
                interval_total_runq_latency_ns = 0
                interval_on_cpu_count = 0
                interval_runq_count = 0

                for (
                    cpu_stat
                ) in stats_per_cpu_list:  # cpu_stat is 'struct task_aggr_stats'
                    interval_total_on_cpu_ns += cpu_stat.total_on_cpu_ns
                    interval_total_runq_latency_ns += cpu_stat.total_runq_latency_ns
                    interval_on_cpu_count += cpu_stat.on_cpu_count
                    interval_runq_count += cpu_stat.runq_count

                if interval_on_cpu_count == 0 and interval_runq_count == 0:
                    continue  # No activity for this TID in this interval

                # Get process info (comm, tgid, cgroup_id) from /proc
                proc_info = get_process_info(tid_val)
                if not proc_info:
                    # helpers.log(f"Skipping TID {tid_val}, process info not found (likely exited).", "DEBUG")
                    continue

                comm_str = proc_info["comm"]
                tgid_val = proc_info["tgid"]
                fetched_cgroup_id = proc_info["cgroup_id"]

                # Apply filters
                if include_patterns and not any(
                    p.search(comm_str) for p in include_patterns
                ):
                    continue
                if exclude_patterns and any(
                    p.search(comm_str) for p in exclude_patterns
                ):
                    continue
                if (
                    cgroup_id_filter is not None
                    and str(fetched_cgroup_id) != cgroup_id_filter
                ):
                    continue

                # Update aggregated_data_river
                agg_key = (tgid_val, comm_str)
                river_stats = aggregated_data_river[agg_key]

                river_stats["cgroup_id"] = (
                    fetched_cgroup_id  # Update with most recently fetched cgroup_id
                )
                if river_stats["first_seen_ts_ns"] == 0:
                    river_stats["first_seen_ts_ns"] = current_loop_ts_ns
                river_stats["last_seen_ts_ns"] = current_loop_ts_ns

                # Update River stats objects with data from this interval
                # Note: This feeds interval averages. Min/Max/Quantiles will be of these averages.
                if interval_on_cpu_count > 0:
                    avg_on_cpu_ns_interval = (
                        interval_total_on_cpu_ns / interval_on_cpu_count
                    )
                    river_stats["on_cpu_ns_var"].update(avg_on_cpu_ns_interval)
                    river_stats["on_cpu_ns_min"].update(avg_on_cpu_ns_interval)
                    river_stats["on_cpu_ns_max"].update(avg_on_cpu_ns_interval)
                    river_stats["on_cpu_ns_median"].update(avg_on_cpu_ns_interval)
                    river_stats["on_cpu_ns_q1"].update(avg_on_cpu_ns_interval)
                    river_stats["on_cpu_ns_q3"].update(avg_on_cpu_ns_interval)

                if interval_runq_count > 0:
                    avg_runq_latency_ns_interval = (
                        interval_total_runq_latency_ns / interval_runq_count
                    )
                    river_stats["runq_latency_ns_var"].update(
                        avg_runq_latency_ns_interval
                    )
                    river_stats["runq_latency_ns_min"].update(
                        avg_runq_latency_ns_interval
                    )
                    river_stats["runq_latency_ns_max"].update(
                        avg_runq_latency_ns_interval
                    )
                    river_stats["runq_latency_ns_median"].update(
                        avg_runq_latency_ns_interval
                    )
                    river_stats["runq_latency_ns_q1"].update(
                        avg_runq_latency_ns_interval
                    )
                    river_stats["runq_latency_ns_q3"].update(
                        avg_runq_latency_ns_interval
                    )

            # Clear the BPF map after processing its contents for this interval
            # This gets fresh aggregates for the next interval.
            agg_stats_map.clear()

            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"Stop indicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False

            # Check running flag again, in case signal handled during sleep or processing
            if not running:
                break

    except Exception as e:
        helpers.log(f"Error or interrupt during BPF setup or main loop: {e}")
        traceback.print_exc()
        running = False
    finally:
        helpers.log("Initiating cleanup sequence...")
        print_final_summary_river()

        if bpf_instance:
            helpers.log("Cleaning up BPF instance...")

            # Detaches tracepoints, closes FDs
            bpf_instance.cleanup()

        # Clear cache on exit
        _process_info_cache.clear()
        _tid_not_found_cache.clear()
        helpers.log("Cleanup complete. Exiting.")
