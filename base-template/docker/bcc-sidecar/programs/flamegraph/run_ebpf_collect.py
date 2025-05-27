#!/usr/bin/python3


from bcc import BPF, PerfType, PerfSWConfig
import ctypes as ct
import os
import json
import signal
import time
import sys
import traceback
from collections import defaultdict

# Global state
running = True
as_table = True
include_patterns = None
exclude_patterns = None
cgroup_indicator_file = None
cgroup_id_filter = None

# --- bcchelper.py Import ---
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
if root not in sys.path:
    sys.path.insert(0, root)
import bcchelper as helpers  # Assuming bcchelper.py is in the parent directory

# Path to flamegraph.pl
flamegraph_binary = os.path.join(here, "flamegraph.pl")
if not os.path.exists(flamegraph_binary):
    raise ValueError("Cannot find flamegraph.pl to generate svg files")

bpf_text = helpers.read_bpf_text(os.path.abspath(__file__)) 

def signal_stop_handler(signum, frame):
    global running
    helpers.log(f"\nSignal {signal.Signals(signum).name} received, stopping...")
    running = False


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
    global bpf_text
    as_table = output_as_table
    exclude_patterns = exclude_regex
    include_patterns = include_regex
    cgroup_indicator_file = cgroup_indicator

    signal.signal(signal.SIGINT, signal_stop_handler)
    signal.signal(signal.SIGTERM, signal_stop_handler)

    if cgroup_indicator_file is not None and os.path.exists(cgroup_indicator_file):
        cgroup_id_filter = helpers.get_cgroup_filter(cgroup_indicator_file)

    command = os.environ.get("EBPF_FLAMEGRAPH_COMMAND")
    if not command:
        raise ValueError("This program requires EBPF_FLAMEGRAPH_COMMAND in the environment.")
    cflags = []
    # Prepare comm for C define: needs to be a string literal
    # Max comm length in BPF is TASK_COMM_LEN (usually 16). Truncate if longer.
    # Ensure it's properly escaped for C string literal.
    comm_to_filter = command[:15] # Max 15 chars + null
    comm_len = len(comm_to_filter)
    
    # Add defines for comm filtering to BPF text
    # The string needs to be in quotes for the C preprocessor
    insert_text = f'#define FILTER_COMM_NAME "{comm_to_filter}"\n'
    insert_text += f'#define FILTER_COMM_LEN {comm_len}\n'
    bpf_text = bpf_text.replace('INSERT_COMMAND_HERE', insert_text)    
    print(f"eBPF: Filtering for command name: '{comm_to_filter}' (len: {comm_len})")

    # This would be user or kernel stacks only
    # cflags.append("-DUSER_ONLY")
    # cflags.append("-DKERNEL_ONLY")

    # Warning suppression 
    cflags.append("-Wno-duplicate-decl-specifier")
    cflags.append("-Wno-address-of-packed-member") # Another common benign warning
    cflags.append("-Wno-unknown-attributes")      # Can also appear

    helpers.log("Starting eBPF for flamegraph generation.")
    bpf_instance = None
    try:
        bcc_debug_level = 0
        if debug:
            bcc_debug_level = BPF.DEBUG_LLVM_IR | BPF.DEBUG_BPF_BY_LLVM
        bpf_instance = BPF(text=bpf_text, debug=bcc_debug_level, cflags=cflags)
        helpers.log("BPF C code compilation attempt complete.")
    except Exception as e:
        helpers.log(
            f"FATAL: Error initializing BPF object: {e}\n{traceback.format_exc()}",
            exit_flag=True,
        )
        return

    if start_indicator_file is not None:
        helpers.log(f"Start Indicator file defined '{start_indicator_file}'. Waiting.")
        while running and not os.path.exists(start_indicator_file):
            time.sleep(0.2)
        helpers.log("Start indicator found. Proceeding.")

    try:
        bpf_instance.attach_perf_event(
            ev_type=PerfType.SOFTWARE,
            ev_config=PerfSWConfig.CPU_CLOCK,
            fn_name="do_perf_event",
            sample_freq=99, # Sampling frequency 99Hz
        )
    except Exception as e:
        print(f"Error attaching perf event: {e}")
        sys.exit(1)

    try:
        while running:
            time.sleep(0.2)
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

    try:
        bpf_instance.detach_perf_event(ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK)
    except Exception:
        pass

    # Data Processing and Output (largely same as before, but now data is pre-filtered if --comm or --pid used)
    stack_traces_map = bpf_instance.get_table("stack_traces")
    counts_map = bpf_instance.get_table("counts_ext")

    folded_stacks_by_tgid = defaultdict(list)
    all_folded_stacks = [] # For the --pid case or "profile all" case

    total_samples_processed = 0
    missing_symbols_count = 0

    for key, count_leaf in counts_map.items():
        count = count_leaf.value
        total_samples_processed += count
        comm_str = key.comm.decode('utf-8', 'replace').strip('\x00') # Remove null bytes for cleaner name
        tgid = key.tgid

        # eBPF should be already filtered. We trust key.comm.
        kstack_syms, ustack_syms = [], []
        if key.kstack_id >= 0:
            trace = stack_traces_map.walk(key.kstack_id)
            for addr in trace:
                sym = bpf_instance.ksym(addr, show_offset=True).decode('utf-8', 'replace')
                if "0x" in sym and "?" in sym: missing_symbols_count +=1
                kstack_syms.append(sym)
        if key.ustack_id >= 0:
            trace = stack_traces_map.walk(key.ustack_id)
            for addr in trace:
                try: 
                    sym = bpf_instance.sym(addr, tgid, show_module=True, show_offset=True).decode('utf-8', 'replace')
                except Exception: 
                    sym = f"0x{addr:x} [u?tgid:{tgid}]"
                if "0x" in sym and "?" in sym: 
                    missing_symbols_count +=1
                ustack_syms.append(sym)
    
        combined_stack_frames = []
        if ustack_syms: combined_stack_frames.extend(reversed(ustack_syms))
        if kstack_syms: combined_stack_frames.extend(reversed(kstack_syms))
        if not combined_stack_frames: combined_stack_frames.append("[Unknown Stack]")

        line_prefix = f"{comm_str}-{tgid}" # Always use comm from key and tgid
        folded_line = f"{line_prefix};" + ";".join(combined_stack_frames)

        # Group by TGID for --comm case
        folded_stacks_by_tgid[tgid].append((folded_line, count))

    # Write output files
    if not folded_stacks_by_tgid:
        print(f"No samples found matching eBPF filter for command: '{command}'. No output files generated.")

    outdir = os.path.join(here, "flamegraphs")
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    print(f"Generating output raw and svg files in {outdir}")

    # Generate the folded files, one per rank tgid
    for tgid, stacks in folded_stacks_by_tgid.items():
        filename_command = command.replace("/", "_") # Sanitize / in comm name
        output_filename = f"flamegraph_{filename_command}_rank_{tgid}.folded"
        outfile = os.path.join(outdir, output_filename)
        with open(outfile, "w") as f:
            for line, num in stacks: 
                f.write(f"{line} {num}\n")        
        print(f"Wrote data for TGID {tgid} (comm: {command}) to {output_filename}")

        # Now write to svg file using janky os.system        
        svg_name = os.path.splitext(outfile)[0] + ".svg"
        os.system(f"{flamegraph_binary} {outfile} > {svg_name}")

    # Summary and flamegraph generation instructions (same as before)
    print(f"\nProcessed {total_samples_processed} total samples (after eBPF filtering).")
    if missing_symbols_count > 0: 
        print(f"WARNING: Encountered ~{missing_symbols_count} instances of unresolved symbols...")
