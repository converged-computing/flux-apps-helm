#!/bin/bash

# This is set for testing only
NPROC=${1:-4}
mpirun --allow-run-as-root -np $NPROC /opt/hpcg/xhpcg
cat hpcg*.txt
