#!/usr/bin/python3

from bcc import BPF, libbcc
import ctypes as ct
import time
import os
import signal
import argparse
import sys

# Global indicator to set to stop running
running = True

filename = "ebpf-collect.c"
if not os.path.exists(filename):
    sys.exit(f"Missing c code {filename}")


def read_file(filename):
    with open(filename, "r") as fd:
        content = fd.read()
    return content


# Define the C code for the eBPF program
bpf_text = read_file(filename)

# Python constants and ctypes (same as before)
MAX_FILENAME_LEN_PY = 256
TASK_COMM_LEN_PY = 16
FILENAME_DISPLAY_WIDTH = 50
EVENT_OPEN_PY = 0
EVENT_CLOSE_PY = 1


class EventData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
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


def print_event_ringbuf_cb(ctx, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    ts_sec = event.timestamp_ns / 1e9
    pid = event.pid
    try:
        comm = event.comm.decode("utf-8", "replace").rstrip("\x00")
    except:
        comm = "<comm_err>"
    event_type_str = f"TYPE({event.type})"
    details_str = f"FD:{event.fd:<3}"
    if event.type == EVENT_OPEN_PY:
        event_type_str = "OPEN"
        filename_str = ""
        try:
            filename_str = event.filename.decode("utf-8", "replace").rstrip("\x00")
            if len(filename_str) > FILENAME_DISPLAY_WIDTH:
                filename_str = filename_str[: FILENAME_DISPLAY_WIDTH - 3] + "..."
        except:
            filename_str = "<file_err>"
        details_str += f' RET:{event.ret_val:<3} FILE: "{filename_str}"'
    elif event.type == EVENT_CLOSE_PY:
        event_type_str = "CLOSE"
    print(
        f"EVENT: {ts_sec:<18.6f} {pid:<7} {comm:<{TASK_COMM_LEN_PY}} {event_type_str:<6} {details_str}"
    )


def print_debug_event_cb(ctx, data, size):
    event = ct.cast(data, ct.POINTER(DebugEventData)).contents
    stage_str = "UNKNOWN_DBG"
    pid_tgid = event.id
    val1 = event.val1
    val2 = event.val2
    if event.stage == DBG_OPEN_ENTRY_START:
        stage_str = "OPEN_ENTRY_START"
    elif event.stage == DBG_OPEN_ENTRY_READ_DONE:
        stage_str = "OPEN_ENTRY_READ_DONE"
    elif event.stage == DBG_OPEN_RETURN_START:
        stage_str = "OPEN_RETURN_START"
    elif event.stage == DBG_OPEN_RETURN_LOOKUP_DONE:
        stage_str = "OPEN_RETURN_LOOKUP_DONE"
    print(
        f"DEBUG: ID:{pid_tgid:<12} STAGE: {stage_str:<25} VAL1:{val1:<7} VAL2:{val2:<7}"
    )


def signal_stop_handler(signum, frame):
    global running
    print("\nSignal received, stopping...", file=sys.stderr)
    running = False


def collect_trace(indicator_file):
    global running
    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)
    print(
        f"Starting eBPF (Tracepoint for open entry). Indicator: '{indicator_file}'",
        file=sys.stderr,
    )
    bpf_instance = None
    try:
        bpf_instance = BPF(text=bpf_text)

        # Attach the TRACEPOINT_PROBE: BPF C code for TRACEPOINT_PROBE(syscalls, sys_enter_openat)
        # For the kretprobe, we still need the syscall function name.
        openat_syscall_fn_name = bpf_instance.get_syscall_fnname("openat")
        close_syscall_fn_name = bpf_instance.get_syscall_fnname("close")
        bpf_instance.attach_kretprobe(
            event=openat_syscall_fn_name, fn_name="trace_openat_return_kretprobe"
        )
        bpf_instance.attach_kprobe(
            event=close_syscall_fn_name, fn_name="trace_close_entry_kprobe"
        )

    except Exception as e:
        print(f"Error initializing/attaching BPF: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"{'TYPE':<6} {'TIMESTAMP':<18} {'PID':<7} {'COMMAND':<{TASK_COMM_LEN_PY}} {'EVENT':<6} {'DETAILS'}"
    )
    header_line_len = (
        6 + 19 + 8 + TASK_COMM_LEN_PY + 7 + 6 + FILENAME_DISPLAY_WIDTH + 25
    )
    print("-" * header_line_len)
    try:
        bpf_instance["events"].open_ring_buffer(print_event_ringbuf_cb, ctx=None)
        # Disable debug printing for now
        # bpf_instance["debug_events_rb"].open_ring_buffer(print_debug_event_cb, ctx=None)
    except Exception as e:
        print(f"Failed to open ring buffer(s): {e}", file=sys.stderr)
        if bpf_instance:
            bpf_instance.cleanup()
            sys.exit(1)
    try:
        while running:
            bpf_instance.ring_buffer_poll(timeout=100)
            if indicator_file and os.path.exists(indicator_file):
                print(
                    f"\nIndicator file '{indicator_file}' found. Stopping.",
                    file=sys.stderr,
                )
                running = False
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt, stopping...", file=sys.stderr)
        running = False
    except Exception as e:
        print(f"\nError during polling: {e}", file=sys.stderr)
        running = False
    finally:
        print("Cleaning up BPF resources...", file=sys.stderr)
        if bpf_instance:
            bpf_instance.cleanup()
        print("Script finished.", file=sys.stderr)


def get_parser():
    parser = argparse.ArgumentParser(
        description="DEBUG eBPF file open/close with Tracepoint."
    )
    parser.add_argument(
        "-i",
        "--indicator-file",
        default="/tmp/stop_ebpf_collection",
        help="Indicator file path.",
    )
    return parser


def main():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")
    parser = get_parser()
    args, extra = parser.parse_known_args()
    collect_trace(args.indicator_file)


if __name__ == "__main__":
    main()
