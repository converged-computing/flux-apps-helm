#!/bin/bash

# This script builds a 2D matrix of Docker images for the HPCG benchmark.
# Each image is tagged with its micro-architecture and optimization level.

set -e

# --- Configuration ---
IMAGE_BASE_NAME="ghcr.io/converged-computing/hpcg-matrix"

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

total_builds=$(( ${#OPTIMIZATIONS[@]} * ${#ARCHITECTURES[@]} ))
current_build=0

for opt_input in "${OPTIMIZATIONS[@]}"; do
  # Parse the optimization level for the Docker build argument
  # The Dockerfile's OPTIMIZATION_LEVEL ARG expects "0", "1", "fast", "s", "g" etc.
  parsed_opt_level=""
  opt_tag="" # For the image tag, e.g., o3, ofast

  case "$opt_input" in
    O0)    parsed_opt_level="0";    opt_tag="o0" ;;
    O1)    parsed_opt_level="1";    opt_tag="o1" ;;
    O2)    parsed_opt_level="2";    opt_tag="o2" ;;
    O3)    parsed_opt_level="3";    opt_tag="o3" ;;
    Ofast) parsed_opt_level="fast"; opt_tag="ofast" ;;
    Os)    parsed_opt_level="s";    opt_tag="os" ;;
    Og)    parsed_opt_level="g";    opt_tag="og" ;;
    *)
      echo "ERROR: Unknown optimization level format: $opt_input" >&2
      exit 1
      ;;
  esac

  for arch in "${ARCHITECTURES[@]}"; do
    current_build=$((current_build + 1))
    echo
    echo "--- Building ${current_build}/${total_builds}: Optimization=${opt_input}, Arch=${arch} ---"

    # For generic x86-64-vX, -mtune is not typically set to the same value.
    # We'll set mtune_val to "generic" or leave it for the compiler to decide based on march.
    # An empty MTUNE_ARG in Dockerfile could mean "don't add -mtune".
    # Or, for simplicity here, let's use "generic" for these.
    if [[ "${march_val}" == "x86-64-v2" || "${march_val}" == "x86-64-v3" || "${march_val}" == "x86-64-v4" ]]; then
      mtune_val="generic" # GCC will pick a reasonable tuning for this ISA level
                          # Alternatively, you could leave mtune_val empty and adjust Dockerfile.
    fi
    full_image_tag="${IMAGE_BASE_NAME}:${arch}-${opt_input}-gpu"

    echo "Target Image Tag: ${full_image_tag}"
    echo "Build Args:"
    echo "  OPTIMIZATION_LEVEL=${parsed_opt_level}"
    echo "  MARCH=${arch}"
    echo "  MTUNE=${mtune_val}"
    echo

    # Construct the docker build command
    # Consider adding --no-cache if you want to ensure args are always picked up freshly
    # during iterative development. For production builds, removing --no-cache is fine.
    docker_build_cmd=(
      docker build
      --progress plain
      --build-arg "OPTIMIZATION_LEVEL=${parsed_opt_level}"
      --build-arg "MARCH=${arch}"
      --build-arg "MTUNE=${mtune_val}"
      -t "${full_image_tag}"
      -f "${DOCKERFILE_NAME}"
      .
    )

    echo "Executing: ${docker_build_cmd[*]}"
    "${docker_build_cmd[@]}"

    echo "--- Successfully built ${full_image_tag} ---"
  done
done

echo
echo "-------------------------------------"
echo "All HPCG Docker builds completed successfully!"
echo "Total images built: ${total_builds}"
echo "-------------------------------------"
