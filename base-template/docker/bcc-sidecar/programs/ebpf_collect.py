# Helper functions shared across programs

import argparse
import random
import os
import re
import sys


here = os.path.dirname(__file__)
known_programs = [x for x in os.listdir(here) if os.path.isdir(x)]

sys.path.insert(0, here)


def get_parser(description):
    """
    Get the argument parser.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-p",
        "--program",
        help="ebpf programs to run across nodes. If > 1, we will distribute across nodes (count required)",
        action="append",
        choices=known_programs,
        default=None,
    )
    parser.add_argument(
        "--nodes",
        help="Total nodes in the study. If not provided, the analysis is randomly selected.",
        default=None,
    )
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


def select_program(nodes, programs):
    """
    Determine the program to run based on a number of total nodes
    """
    start = 0
    # 0 index
    end = nodes - 1
    count = len(programs)

    # If we have more programs than nodes, select randomly
    if count > nodes:
        print("More programs than nodes - will randomly select.")
        return random.select(programs)

    interval_size = (end - start) / count
    index = int((count - start) / interval_size)
    return programs[index]


def main():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")

    parser = get_parser("eBPF Performance Analyzer with RiverML")
    args, _ = parser.parse_known_args()

    if args.include_pattern:
        include_patterns = [re.compile(p) for p in args.include_pattern]
    if args.exclude_pattern:
        exclude_patterns = [re.compile(p) for p in args.exclude_pattern]

    # If no analyses selected, choose randomly from known set.
    if not args.program:
        args.program = [random.choice(known_programs)]

    # If we don't have a number of nodes, random selection from analyses
    if not args.nodes:
        print("Number of nodes not known, selecting randomly.")
        args.program = random.choice(args.program)

    # Only one program provided, all nodes will run it
    elif len(args.program) == 1:
        args.program = args.program[0]

    # More than one program, and we know nodes
    # We get the job's completion index to determine the program
    else:
        index = os.environ.get("JOB_COMPLETION_INDEX")
        if index is None:
            raise ValueError(
                "More than one program selected in multi node environment. Set JOB_COMPLETION_INDEX to select."
            )
        args.program = select_program(args.nodes, args.program)

    print(f"PROGRAM: {args.program}")

    # Insert the path to import, and import main function
    sys.path.insert(0, os.path.join(here, args.program))
    from run_ebpf_collect import collect_trace

    # If we have a number of nodes
    collect_trace(
        args.start_indicator_file,
        args.stop_indicator_file,
        args.cgroup_indicator_file,
        not args.json,
        include_patterns,
        exclude_patterns,
        args.debug,  # We aren't using this now, passing for consistency.
    )


if __name__ == "__main__":
    main()
