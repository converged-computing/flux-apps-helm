#!/bin/bash

# This script builds a 2D matrix of Docker images for the HPCG benchmark.
# Each image is tagged with its micro-architecture and optimization level.

set -e

# --- Configuration ---
IMAGE_NAME="ghcr.io/converged-computing/hpcg-matrix"

# Dimension 1: Optimization Levels
OPTIMIZATIONS=(
  "O0"    # No optimization (baseline)
  "O1"    # Basic optimizations
  "O2"    # Standard optimization
  "O3"    # Aggressive optimization
  "Ofast" # Aggressive, non-compliant math
  "Os"    # Optimize for size
  "Og"    # Optimize for debugging
)

ARCHITECTURES=(
  "native"
  "neoverse-n1"      # AWS Graviton2, Ampere Altra
  "neoverse-v1"      # AWS Graviton3 (SVE support)
  "neoverse-n2"      # Successor to N1 (SVE2 support)
  "neoverse-v2"      # Successor to V1 (SVE2 support)
  "ampere1"          # Alias for neoverse-n1, used for Ampere eMAG
  "a64fx"            # Fujitsu A64FX (as used in Fugaku supercomputer, SVE support)  
  "cortex-a72"     # Raspberry Pi 4
  "cortex-a53"       # Very common, older 64-bit low-power core
  "cortex-a57"       # Older 64-bit high-performance core (paired with A53)
  "cortex-a76"       # High-performance core from 2018
  "cortex-x1"        # High-performance "custom" core

  # --- F. Generic CPU Models ---
  "generic"          # A generic ARMv8-A CPU model
)

# --- Build Loop ---
echo "Starting 2D HPCG build matrix..."

for arch in "${ARCHITECTURES[@]}"; do
  for opt in "${OPTIMIZATIONS[@]}"; do
    # Construct the full optimization flag (e.g., "-O3")
    FULL_OPT_FLAG="-$opt"
    
    # The -march flag is the architecture name
    FULL_MARCH_FLAG="-mcpu=${arch}"

    # Construct the unique Docker tag (e.g., "hpcg-benchmark:skylake-avx512-O3")
    TAG="${IMAGE_NAME}:${arch}-${opt}-arm"

    echo "------------------------------------------------------------"
    echo "Building for:"
    echo "  Architecture: ${FULL_MARCH_FLAG}"
    echo "  Optimization: ${FULL_OPT_FLAG}"
    echo "Image will be tagged as: ${TAG}"
    echo "------------------------------------------------------------"

    cmd="docker buildx build . \
        --platform linux/arm64 \
        --build-arg "OPTIMIZATION_FLAGS=-${opt}" \
        --build-arg "MARCH_FLAG=${FULL_MARCH_FLAG}" \
        -t "${TAG}" \
        --load"
    echo $cmd
    $cmd
  done
done

echo "============================================================"
echo "Build matrix complete. The following images were created:"
echo "============================================================"
docker images | grep "${IMAGE_NAME}"
