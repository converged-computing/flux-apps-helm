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
cgroup_id = None

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import bcchelper as helpers

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__))

# Python constants and ctypes (same as before)
MAX_FILENAME_LEN_PY = 256
TASK_COMM_LEN_PY = 16
FILENAME_DISPLAY_WIDTH = 50
EVENT_OPEN_PY = 0
EVENT_CLOSE_PY = 1


class EventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN_PY),
        ("type", ct.c_int),
        ("filename", ct.c_char * MAX_FILENAME_LEN_PY),
        ("fd", ct.c_int),
        ("ret_val", ct.c_int),
    ]


class DebugEventData(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("stage", ct.c_int),
        ("val1", ct.c_long),
        ("val2", ct.c_long),
    ]


DBG_OPEN_ENTRY_START = 100
DBG_OPEN_ENTRY_READ_DONE = 101
DBG_OPEN_RETURN_START = 200
DBG_OPEN_RETURN_LOOKUP_DONE = 201

DBG_CLOSE_ENTRY_START = 300
DBG_CLOSE_ENTRY_SUBMITTING = 301
DBG_CLOSE_RETURN_DONE = 302


def print_event_ringbuf_cb(ctx, data, size):
    """
    Print output from the ring buffer, either as a table or json
    """
    global as_table
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file
    global cgroup_id

    # Do we have a cgroup indicator file written?
    if cgroup_indicator_file is not None and cgroup_id is None:
        if os.path.exists(cgroup_indicator_file):
            cgroup_id = helpers.read_file(cgroup_indicator_file).strip()
            print(f"Scoping to cgroup {cgroup_id}")

    event = ct.cast(data, ct.POINTER(EventData)).contents
    epatterns = "(%s)" % "|".join(exclude_patterns or [])
    ipatterns = "(%s)" % "|".join(include_patterns or [])

    # Convert to seconds from nanoseconds
    timestamp = event.timestamp_ns / 1e9

    # Get the command, in the event it is called "comm"
    try:
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    except:
        comm = "<comm_err>"
    if include_patterns and not re.search(ipatterns, comm):
        return
    if exclude_patterns and re.search(epatterns, comm):
        return

    # Cut out early if not the right cgroup
    if cgroup_id is not None and str(event.cgroup_id) != cgroup_id:
        return

    # Event type (open or close) and filename
    # Let's just keep the opens for now, we aren't timing anything
    filename = ""
    if event.type == EVENT_OPEN_PY:
        event_type = "OPEN"
        try:
            filename = event.filename.decode("utf-8", "replace").rstrip("\x00")
        except:
            filename = "<error>"
    elif event.type == EVENT_CLOSE_PY:
        event_type = "CLOSE"
    else:
        raise ValueError("EVENT TYPE NOT KNOWN {event.type}")

    # Don't bother if no filename - we aren't timing things for now
    if as_table:
        print_table(event, comm, event_type, filename, timestamp)
    else:
        print_json(event, comm, event_type, filename, timestamp)


def print_json(event, comm, event_type, filename, timestamp):
    """
    Print the event as json
    """
    body = {
        "event": event_type,
        "command": comm,
        "retval": event.ret_val,
        "ts_sec": timestamp,
        "tgid": event.tgid,
        "tid": event.tid,
        "ppid": event.ppid,
        "cgroup_id": event.cgroup_id,
    }
    # I can't get close to have them
    if filename:
        body["filename"] = filename
    # I don't think we can get cgroups for things in proc
    if "/proc" in filename:
        del body["cgroup_id"]
    print(json.dumps(body))


def print_table(event, comm, event_type, filename, timestamp):
    """
    Print the event as a table
    """
    # Ensure we don't go over the terminal width
    if len(filename) > FILENAME_DISPLAY_WIDTH:
        filename = filename[: FILENAME_DISPLAY_WIDTH - 3] + "..."
    event_type_field = f"TYPE({event_type})"
    details = f' RET:{event.ret_val:<3} FILE: "{filename}"'
    print(
        f"EVENT: {timestamp:<18.6f} {event.tgid:<7} {comm:<{TASK_COMM_LEN_PY}} {event_type_field:<6} {details}"
    )


def print_debug_event_cb(ctx, data, size):
    """
    Print debug info. This is important because I stopped seeing opens, and it was
    because I was getting a -14 response, meaning the open failed.
    """
    event = ct.cast(data, ct.POINTER(DebugEventData)).contents
    stage = "UNKNOWN_DBG"
    pid_tgid = event.id
    val1 = event.val1
    val2 = event.val2

    if event.stage == DBG_OPEN_ENTRY_START:
        stage = "OPEN_ENTRY_START"
    elif event.stage == DBG_OPEN_ENTRY_READ_DONE:
        stage = "OPEN_ENTRY_READ_DONE"
    elif event.stage == DBG_OPEN_RETURN_START:
        stage = "OPEN_RETURN_START"
    elif event.stage == DBG_OPEN_RETURN_LOOKUP_DONE:
        stage = "OPEN_RETURN_LOOKUP_DONE"
    elif event.stage == DBG_CLOSE_ENTRY_START:
        stage = "CLOSE_ENTRY_START"
    elif event.stage == DBG_CLOSE_ENTRY_SUBMITTING:
        stage = "CLOSE_ENTRY_SUBMITTING"
    elif event.stage == DBG_CLOSE_RETURN_DONE:
        stage = "CLOSE_RETURN_DONE"
    print(f"DEBUG: ID:{pid_tgid:<12} STAGE: {stage:<25} VAL1:{val1:<7} VAL2:{val2:<7}")


def signal_stop_handler(signum, frame):
    """
    Set running to False if we get a signal to do so.

    This would trigger if we had a success completion policy on the Flux
    Operator, but instead we are just looking for a file indicator.
    """
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def print_table_header():
    """
    Print a header for the table (human friendly variant to json)
    """
    print(
        f"{'TYPE':<6} {'TIMESTAMP':<18} {'TGID':<7} {'COMMAND':<{TASK_COMM_LEN_PY}} {'EVENT':<6} {'DETAILS'}"
    )
    header_line_len = (
        6 + 19 + 8 + TASK_COMM_LEN_PY + 7 + 6 + FILENAME_DISPLAY_WIDTH + 25
    )
    print("-" * header_line_len)


def collect_trace(
    start_indicator_file=None, stop_indicator_file=None, table=True, debug=False
):
    """
    Collect a trace until we receive a signal from the global indicator.
    """
    global running

    # Are we printing as a table, or json?
    global as_table
    as_table = table

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    helpers.log("Starting eBPF (Tracepoint for open entry).")
    try:
        # Create the bpf program (I think this compiles)
        bpf_instance = BPF(text=bpf_text)

        # These are kprobes for opens and closes
        bpf_instance.attach_kretprobe(
            event=bpf_instance.get_syscall_fnname("openat"),
            fn_name="trace_openat_return_kretprobe",
        )
        bpf_instance.attach_kprobe(
            event=bpf_instance.get_syscall_fnname("close"),
            fn_name="trace_close_entry_kprobe",
        )

    except Exception as e:
        helpers.log(f"Error initializing/attaching BPF: {e}", exit=True)

    # Only print a header if it's a table...
    if table:
        print_table_header()

    # Are we filtering to a cgroup?
    if cgroup_indicator_file is not None:
        helpers.log(f"\nCgroup Indicator file defined '{cgroup_indicator_file}'.")

    # Wait to start, if applicable
    if start_indicator_file is not None:
        helpers.log(
            f"\nStart Indicator file defined '{start_indicator_file}'. Waiting."
        )
        while not os.path.exists(start_indicator_file):
            time.sleep(1)

    # We are going to open ring buffers
    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf_cb, ctx=None)
        # Debug printing, if needed
        if debug:
            bpf_instance["debug_events_rb"].open_ring_buffer(
                print_debug_event_cb, ctx=None
            )

    except Exception as e:
        helpers.log(f"Failed to open ring buffer(s): {e}")
        if bpf_instance:
            bpf_instance.cleanup()
            sys.exit(1)

    # As this is running, poll the ring buffer to get output
    try:
        while running:
            bpf_instance.ring_buffer_poll(timeout=100)

            # If the indicator file is present, we are done.
            # The Flux Operator has finished running the app and generated it.
            if stop_indicator_file is not None and os.path.exists(stop_indicator_file):
                helpers.log(
                    f"\nIndicator file '{stop_indicator_file}' found. Stopping."
                )
                running = False

    # Stop due to exception or other
    except Exception as e:
        helpers.log(f"\nError during polling: {e}")
        running = False
    finally:
        helpers.log("Cleaning up BPF resources...")
        if bpf_instance:
            bpf_instance.cleanup()


def main():
    """
    Main execution to run trace.
    """
    global include_patterns
    global exclude_patterns
    global cgroup_indicator_file

    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = helpers.get_parser("File Open/Close Analyzer.")
    args, _ = parser.parse_known_args()

    # If debug is set, we print a table
    if args.debug:
        args.json = False

    include_patterns = args.include_pattern
    exclude_patterns = args.exclude_pattern
    cgroup_indicator_file = args.cgroup_indicator_file
    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        not args.json,
        args.debug,
    )


if __name__ == "__main__":
    main()
