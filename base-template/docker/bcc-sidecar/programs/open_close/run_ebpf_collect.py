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
as_table_summary = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

BPF_C_PROGRAM_FILENAME = "ebpf-collect.c"
bpf_text = helpers.read_bpf_text(os.path.join(here, BPF_C_PROGRAM_FILENAME))

# Python constants and ctypes
MAX_FILENAME_LEN_PY = 256
TASK_COMM_LEN_PY = 16
FILENAME_DISPLAY_WIDTH = 50


# CTypes for BPF map structures (must match C code)
class FileKeyData(ct.Structure):
    _fields_ = [
        ("filename", ct.c_char * MAX_FILENAME_LEN_PY),
    ]


class FileSummaryData(ct.Structure):
    _fields_ = [
        ("open_count", ct.c_ulonglong),
        ("close_count", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("cgroup_id", ct.c_ulonglong),
    ]


# Debug Event CTypes (must match C code)
class DebugEventData(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("stage", ct.c_int),
        ("val1", ct.c_long),
        ("val2", ct.c_long),
        ("SDBGa", ct.c_char * 16),  # Matches C struct
        ("SDBGb", ct.c_char * 16),  # Matches C struct
    ]


# Debug Enum values (must match C code for debug_events_rb)
DBG_OPEN_ENTRY_START = 100
DBG_OPEN_ENTRY_READ_DONE = 101
DBG_OPEN_ENTRY_UPDATE_FAIL = 102
DBG_OPEN_RETURN_START = 200
DBG_OPEN_RETURN_LOOKUP_FAIL = 201  # Placeholder if used
DBG_OPEN_RETURN_NO_KEY = 202
DBG_OPEN_RETURN_ACTIVE_FD_UPDATE_FAIL = 203
DBG_OPEN_RETURN_STATS_UPDATE_FAIL = 204
DBG_CLOSE_ENTRY_START = 300
DBG_CLOSE_ACTIVE_FD_LOOKUP_FAIL = 301
DBG_CLOSE_STATS_LOOKUP_FAIL = 302
DBG_CLOSE_STATS_UPDATE_FAIL = 303


def print_summary_table_header():
    header = (
        f"{'FILENAME':<{FILENAME_DISPLAY_WIDTH}} | "
        f"{'COMM':<{TASK_COMM_LEN_PY}} | "
        f"{'TGID':<7} | "
        f"{'CGROUP_ID':<10} | "
        f"{'OPENS':<7} | "
        f"{'CLOSES':<7}"
    )
    print(header)
    print("-" * len(header))


def print_summary_table_row(file_key_obj, summary_data_obj):
    global include_patterns, exclude_patterns, cgroup_id_filter
    try:
        # file_key_obj is FileKeyData instance
        filename = file_key_obj.filename.decode("utf-8", "replace").rstrip("\x00")
    except Exception:
        filename = "<fn_err>"

    try:
        # summary_data_obj is FileSummaryData instance
        comm = summary_data_obj.comm.decode("utf-8", "replace").rstrip("\x00")
    except Exception:
        comm = "<comm_err>"

    # Apply Python-side filtering on display
    if include_patterns:
        ipatterns = "(%s)" % "|".join(include_patterns)
        if not re.search(ipatterns, comm):
            return False  # Indicates row should not be printed
    if exclude_patterns:
        epatterns = "(%s)" % "|".join(exclude_patterns)
        if re.search(epatterns, comm):
            return False
    if (
        cgroup_id_filter is not None
        and str(summary_data_obj.cgroup_id) != cgroup_id_filter
    ):
        return False

    display_filename = filename
    if len(display_filename) > FILENAME_DISPLAY_WIDTH:
        display_filename = display_filename[: FILENAME_DISPLAY_WIDTH - 3] + "..."

    print(
        f"{display_filename:<{FILENAME_DISPLAY_WIDTH}} | "
        f"{comm:<{TASK_COMM_LEN_PY}} | "
        f"{summary_data_obj.tgid:<7} | "
        f"{summary_data_obj.cgroup_id:<10} | "
        f"{summary_data_obj.open_count:<7} | "
        f"{summary_data_obj.close_count:<7}"
    )
    return True  # Indicates row was printed


def print_summary_json_entry(file_key_obj, summary_data_obj, timestamp):
    global include_patterns, exclude_patterns, cgroup_id_filter
    try:
        filename = file_key_obj.filename.decode("utf-8", "replace").rstrip("\x00")
    except Exception:
        filename = "<fn_err>"

    try:
        comm = summary_data_obj.comm.decode("utf-8", "replace").rstrip("\x00")
    except Exception:
        comm = "<comm_err>"

    # Apply Python-side filtering
    if include_patterns:
        ipatterns = "(%s)" % "|".join(include_patterns)
        if not re.search(ipatterns, comm):
            return None
    if exclude_patterns:
        epatterns = "(%s)" % "|".join(exclude_patterns)
        if re.search(epatterns, comm):
            return None
    if (
        cgroup_id_filter is not None
        and str(summary_data_obj.cgroup_id) != cgroup_id_filter
    ):
        return None

    entry = {
        "filename": filename,
        "command": comm,
        "tgid": summary_data_obj.tgid,
        "cgroup_id": summary_data_obj.cgroup_id,
        "open_count": summary_data_obj.open_count,
        "close_count": summary_data_obj.close_count,
        "summary_timestamp": timestamp,  # Timestamp of when Python generated this summary
    }
    if "/proc" in filename and "cgroup_id" in entry:
        del entry["cgroup_id"]
    return entry


def print_final_summary_from_map(bpf_instance):
    global as_table_summary, cgroup_indicator_file, cgroup_id_filter

    helpers.log("DEBUG: Entered print_final_summary_from_map function.")

    if bpf_instance is None:
        print(
            "ERROR: Python print_final_summary_from_map: bpf_instance is None!",
            file=sys.stderr,
        )
        return

    summary_map = None
    try:
        summary_map = bpf_instance.get_table("file_stats_map")
        helpers.log(
            "DEBUG: Python print_final_summary_from_map: Successfully got 'file_stats_map'."
        )
    except Exception as e_get_table:
        print(
            f"ERROR: Python print_final_summary_from_map: Exception when calling get_table('file_stats_map'): {e_get_table}",
            file=sys.stderr,
        )
        return

    if not summary_map:
        print(
            "ERROR: Python print_final_summary_from_map: Could not get 'file_stats_map' (it's None after get_table).",
            file=sys.stderr,
        )
        return

    items = []
    try:
        items = list(summary_map.items())
        helpers.log(
            f"DEBUG: Python print_final_summary_from_map: summary_map.items() call returned {len(items)} items."
        )
    except Exception as e_items:
        print(
            f"ERROR: Python print_final_summary_from_map: Exception when calling summary_map.items(): {e_items}",
            file=sys.stderr,
        )
        return

    if len(items) == 0:
        print(
            "INFO: Python print_final_summary_from_map: 'file_stats_map' is empty or all items were filtered out by BPF-side logic.",
            file=sys.stderr,
        )
        if include_patterns or exclude_patterns or cgroup_id_filter:
            print(
                f"INFO: Python print_final_summary_from_map: Current Python filters: include={include_patterns}, exclude={exclude_patterns}, cgroup_filter={cgroup_id_filter}",
                file=sys.stderr,
            )
        return

    helpers.log(
        "DEBUG: Python print_final_summary_from_map: Map is not empty, proceeding to print."
    )

    # Update cgroup_id_filter if indicator file is present
    if (
        cgroup_indicator_file is not None and cgroup_id_filter is None
    ):  # Check only if not already set
        if os.path.exists(cgroup_indicator_file):
            globals()["cgroup_id_filter"] = helpers.read_file(
                cgroup_indicator_file
            ).strip()
            helpers.log(f"SUMMARY: Scoping to cgroup {cgroup_id_filter}")

    if as_table_summary:
        print("\n--- Final File Access Summary ---")
        print_summary_table_header()
        printed_rows = 0
        for file_key, summary_data in items:
            if print_summary_table_row(file_key, summary_data):
                printed_rows += 1
        if printed_rows == 0 and len(items) > 0:
            print(
                "INFO: All items from BPF map were filtered out by Python-side display filters.",
                file=sys.stderr,
            )

    else:  # JSON output
        json_output_list = []
        summary_ts = time.time()
        for file_key, summary_data in items:
            entry = print_summary_json_entry(file_key, summary_data, summary_ts)
            if entry:
                json_output_list.append(entry)

        if not json_output_list and len(items) > 0:
            print(
                "INFO: All items from BPF map were filtered out by Python-side display filters.",
                file=sys.stderr,
            )
        elif json_output_list:
            print(json.dumps(json_output_list, indent=2))

    # For kernel-side aggregation, map clearing is usually not done by the reader unless specifically designed for delta views.
    # summary_map.clear() # If you wanted to clear it for some reason.


def print_debug_event_cb(ctx, data, size):
    event = ct.cast(data, ct.POINTER(DebugEventData)).contents
    stage_name = "UNKNOWN_DBG"
    # Map enum int to string name - can be made more elegant with a dict
    if event.stage == DBG_OPEN_ENTRY_START:
        stage_name = "OPEN_ENTRY_START"
    elif event.stage == DBG_OPEN_ENTRY_READ_DONE:
        stage_name = "OPEN_ENTRY_READ_DONE"
    elif event.stage == DBG_OPEN_ENTRY_UPDATE_FAIL:
        stage_name = "OPEN_ENTRY_UPDATE_FAIL"
    elif event.stage == DBG_OPEN_RETURN_START:
        stage_name = "OPEN_RETURN_START"
    elif event.stage == DBG_OPEN_RETURN_NO_KEY:
        stage_name = "OPEN_RETURN_NO_KEY"
    elif event.stage == DBG_OPEN_RETURN_ACTIVE_FD_UPDATE_FAIL:
        stage_name = "OPEN_RETURN_ACTIVE_FD_UPDATE_FAIL"
    elif event.stage == DBG_OPEN_RETURN_STATS_UPDATE_FAIL:
        stage_name = "OPEN_RETURN_STATS_UPDATE_FAIL"
    elif event.stage == DBG_CLOSE_ENTRY_START:
        stage_name = "CLOSE_ENTRY_START"
    elif event.stage == DBG_CLOSE_ACTIVE_FD_LOOKUP_FAIL:
        stage_name = "CLOSE_ACTIVE_FD_LOOKUP_FAIL"
    elif event.stage == DBG_CLOSE_STATS_LOOKUP_FAIL:
        stage_name = "CLOSE_STATS_LOOKUP_FAIL"
    elif event.stage == DBG_CLOSE_STATS_UPDATE_FAIL:
        stage_name = "CLOSE_STATS_UPDATE_FAIL"

    sdbga = event.SDBGa.decode("utf-8", "replace").rstrip("\x00")
    sdbgb = event.SDBGb.decode("utf-8", "replace").rstrip("\x00")

    print(
        f"BPF_DBG: ID:{event.id:<10} STAGE:{event.stage}({stage_name:<30}) V1:{event.val1:<7} V2:{event.val2:<5} S1:'{sdbga}' S2:'{sdbgb}'"
    )


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def collect_trace(
    start_indicator_file=None,
    stop_indicator_file=None,
    cgroup_indicator=None,
    output_as_table_summary=True,
    include_regex_list=None,
    exclude_regex_list=None,
    interval=100,
    debug=False,
):
    global running
    global as_table_summary
    global cgroup_indicator_file
    global cgroup_id_filter
    global include_patterns
    global exclude_patterns

    as_table_summary = output_as_table_summary
    include_patterns = include_regex_list
    exclude_patterns = exclude_regex_list
    cgroup_indicator_file = cgroup_indicator
    # cgroup_id_filter will be set if cgroup_indicator is found

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    helpers.log(
        f"Starting eBPF with C code: {BPF_C_PROGRAM_FILENAME} (Kernel-Side Aggregation)"
    )

    if start_indicator_file is not None:
        helpers.log(f"Start Indicator file defined '{start_indicator_file}'. Waiting.")
        while running and not os.path.exists(start_indicator_file):
            time.sleep(0.2)
        helpers.log("Start indicator found. Proceeding.")

    try:
        bpf_instance = BPF(text=bpf_text)

        bpf_instance.attach_kretprobe(
            event=bpf_instance.get_syscall_fnname("openat"),
            fn_name="trace_openat_return_kretprobe",
        )
        bpf_instance.attach_kprobe(
            event=bpf_instance.get_syscall_fnname("close"),
            fn_name="trace_close_entry_kprobe",
        )

    except Exception as e:
        print(
            f"PYTHON CRITICAL ERROR during BPF init/attach: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc()
        print(
            "PYTHON CRITICAL ERROR: Exiting due to BPF load/attach failure.",
            file=sys.stderr,
        )
        sys.exit(1)

    if bpf_instance is None:
        print(
            "PYTHON CRITICAL ERROR: BPF loading/attachment failed silently or bpf_instance is None. Exiting.",
            file=sys.stderr,
        )
        sys.exit(1)  # Force exit

    helpers.log("eBPF program started. Aggregating file access summaries in kernel...")
    polling_interval_seconds = interval / 1000
    try:
        while running:
            time.sleep(polling_interval_seconds)
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False
    except Exception as e:
        helpers.log(f"\nError or interrupt during main loop: {e}")
        running = False
    finally:
        if bpf_instance is not None:
            try:
                print_final_summary_from_map(bpf_instance)
            except Exception as e_summary:
                print(f"Error printing summary: {e_summary}", file=sys.stderr)
            try:
                bpf_instance.cleanup()
            except Exception as e_cleanup:
                print(
                    f"Exception during bpf_instance.cleanup(): {e_cleanup}",
                    file=sys.stderr,
                )
        else:
            print(
                "bpf_instance is None in finally block. BPF program likely failed to load.",
                file=sys.stderr,
            )
