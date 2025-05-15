# Helper functions shared across programs

import argparse
import os
import sys
import time


def log(message, prefix="", exit_flag=False):
    ts = time.strftime("%H:%M:%S", time.localtime())
    if prefix:
        prefix = f"{prefix} "
    print(f"[{ts}] {prefix}{message}", file=sys.stderr)
    if exit_flag:
        sys.exit(1)


def read_file(filepath):
    """
    Read a text file
    """
    with open(filepath, "r") as fd:
        content = fd.read()
    return content


def read_bpf_text(dirname, c_filename="ebpf-collect.c"):
    """
    Find the c program alongside the python program
    """
    # Ensure we get the c program alongside
    script_dir_path = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(script_dir_path, c_filename)
    print(f"Looking for {filename}")
    if not os.path.exists(filename):
        sys.exit(f"Missing BPF C code file: {filename}")
    return read_file(filename)


def get_cgroup_filter(cgroup_indicator_file):
    """
    Filtering to a cgroup id can scope the results to one container.
    """
    try:
        with open(cgroup_indicator_file, "r") as f:
            cgroup_id_filter = f.read().strip()
            if cgroup_id_filter:
                log(f"Scoping to cgroup {cgroup_id_filter}")
            else:
                log(
                    f"Warning: Cgroup indicator file '{cgroup_indicator_file}' is empty."
                )
                cgroup_id_filter = None
    except Exception as e:
        log(
            f"Warning: Could not read cgroup indicator file '{cgroup_indicator_file}': {e}"
        )
        cgroup_id_filter = None  # Treat as no filter
    return cgroup_id_filter


def get_parser(description):
    """
    Get the argument parser.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--cgroup-indicator-file",
        help="Filename with a cgroup to filter to",
    )
    parser.add_argument(
        "--stop-indicator-file",
        help="Indicator file path to stop",
    )
    parser.add_argument(
        "--start-indicator-file",
        help="Indicator file path to start",
    )
    parser.add_argument(
        "--include-pattern",
        default=None,
        action="append",
        help="Include these patterns only",
    )
    parser.add_argument(
        "--exclude-pattern",
        default=None,
        action="append",
        help="Exclude these patterns in commands",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print debug calls for open",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        default=False,
        help="Print records as json instead of in table",
    )
    return parser
