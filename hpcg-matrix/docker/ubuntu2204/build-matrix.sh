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

# Dimension 2: Micro-architectures (see notes below for more options)
ARCHITECTURES=(
  # Special 'native' flag
  "native"

  # A. Generic, Portable Architectures (based on instruction set levels)
  "x86-64-v2"
  "x86-64-v3"
  "x86-64-v4"

  # B. Intel-Specific Architectures
  "sandybridge"
  "ivybridge"
  "haswell"
  "broadwell"
  "skylake"
  "skylake-avx512"
  "icelake-server"
  "sapphirerapids"

  # C. AMD-Specific Architectures
  "btver2"          # Piledriver
  "bdver4"          # Excavator
  "znver1"          # Zen 1
  "znver2"          # Zen 2
  "znver3"          # Zen 3
)

# --- Build Loop ---
echo "Starting 2D HPCG build matrix..."

for arch in "${ARCHITECTURES[@]}"; do
  for opt in "${OPTIMIZATIONS[@]}"; do
    # Construct the full optimization flag (e.g., "-O3")
    FULL_OPT_FLAG="-$opt"
    
    # The -march flag is the architecture name
    FULL_MARCH_FLAG="$arch"

    # Construct the unique Docker tag (e.g., "hpcg-benchmark:skylake-avx512-O3")
    TAG="${IMAGE_NAME}:${arch}-${opt}"

    echo "------------------------------------------------------------"
    echo "Building for:"
    echo "  Architecture: ${FULL_MARCH_FLAG}"
    echo "  Optimization: ${FULL_OPT_FLAG}"
    echo "Image will be tagged as: ${TAG}"
    echo "------------------------------------------------------------"

    docker build . \
      --build-arg "OPTIMIZATION_FLAGS=${FULL_OPT_FLAG}" \
      --build-arg "MARCH_FLAG=${FULL_MARCH_FLAG}" \
      -t "${TAG}"
  done
done

echo "============================================================"
echo "Build matrix complete. The following images were created:"
echo "============================================================"
docker images | grep "${IMAGE_NAME}"
