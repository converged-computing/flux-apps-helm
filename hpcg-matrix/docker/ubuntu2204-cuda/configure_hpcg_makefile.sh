#!/bin/sh
#
# This script configures the HPCG Makefile (setup/Make.Custom_GPU_CUDA)
# for a CUDA + MPI + OpenMP build using nvcc as the primary compiler/linker.
# It relies on several environment variables being pre-defined by sourcing
# files created in earlier Dockerfile steps. These include:
#   - CUDA_GENCODE_FLAGS_ENV (from /cuda_gencode_env.sh)
#   - MPI_COMPILE_FLAGS_ENV (from /mpi_compile_flags.sh)
#   - MPI_LINK_FLAGS_ENV (from /mpi_link_flags.sh)
#   - HOST_OPT_FLAGS_FOR_SED (from /host_opt_flags_for_sed.sh)
#   - NVCC_OPT_LEVEL_FOR_SED (from /nvcc_opt_level.sh)
#
# It also uses environment variables set directly in the Dockerfile:
#   - HOST_OMP_FLAG (e.g., "-fopenmp")
#   - LINK_OMP_LIB (e.g., "-lgomp")

set -e # Exit immediately if a command exits with a non-zero status.
# set -u # Treat unset variables as an error (optional, but good for debugging)
# set -x # Print commands and their arguments as they are executed (for debugging)

# --- Source Environment Variable Files ---
# These files should contain 'export VAR_NAME="value"' lines

ENV_FILES_TO_SOURCE="/cuda_gencode_env.sh /mpi_compile_flags.sh /mpi_link_flags.sh /host_opt_flags_for_sed.sh /nvcc_opt_level.sh"

for env_file in $ENV_FILES_TO_SOURCE; do
    if [ -f "$env_file" ]; then
        # shellcheck source=/dev/null
        . "$env_file"
    else
        echo "Error: Environment file $env_file not found. This script cannot proceed." >&2
        exit 1
    fi
done

# --- Script Variables ---
MAKEFILE_PATH="setup/Make.Custom_GPU_CUDA" # Path relative to HPCG source root

# --- Sanity Checks for Sourced Variables (Optional but Recommended) ---
# Ensure critical variables are set (add more as needed)
: "${CUDA_GENCODE_FLAGS_ENV?"Error: CUDA_GENCODE_FLAGS_ENV is not set. Check /cuda_gencode_env.sh."}"
# MPI_COMPILE_FLAGS_ENV can be empty if mpicxx --showme:compile outputs nothing, so don't fail on empty
# MPI_LINK_FLAGS_ENV can also be empty if the processing script outputs nothing, so don't fail on empty
: "${HOST_OPT_FLAGS_FOR_SED?"Error: HOST_OPT_FLAGS_FOR_SED is not set. Check /host_opt_flags_for_sed.sh."}"
: "${NVCC_OPT_LEVEL_FOR_SED?"Error: NVCC_OPT_LEVEL_FOR_SED is not set. Check /nvcc_opt_level.sh."}"
: "${HOST_OMP_FLAG?"Error: HOST_OMP_FLAG environment variable must be set (e.g., by Dockerfile ENV)."}"
: "${LINK_OMP_LIB?"Error: LINK_OMP_LIB environment variable must be set (e.g., by Dockerfile ENV)."}"


# --- Debug Output ---
echo "--- Starting HPCG Makefile Configuration (${MAKEFILE_PATH}) ---"
echo "Sourced Variables:"
echo "  CUDA_GENCODE_FLAGS_ENV:      [${CUDA_GENCODE_FLAGS_ENV}]"
echo "  MPI_COMPILE_FLAGS_ENV:       [${MPI_COMPILE_FLAGS_ENV}]"
echo "  MPI_LINK_FLAGS_ENV:          [${MPI_LINK_FLAGS_ENV}]" # <<< CRITICAL: Check this output carefully
echo "  HOST_OPT_FLAGS_FOR_SED:      [${HOST_OPT_FLAGS_FOR_SED}]"
echo "  NVCC_OPT_LEVEL_FOR_SED:      [${NVCC_OPT_LEVEL_FOR_SED}]"
echo "Dockerfile ENV Variables Used:"
echo "  HOST_OMP_FLAG:               [${HOST_OMP_FLAG}]"
echo "  LINK_OMP_LIB:                [${LINK_OMP_LIB}]"
echo "----------------------------------------------------------"

# --- Ensure Makefile Exists ---
if [ ! -f "$MAKEFILE_PATH" ]; then
    echo "Error: Makefile ${MAKEFILE_PATH} not found. Make sure it was copied from a template (e.g., Make.Linux_MPI)." >&2
    exit 1
fi

# --- Define Makefile Content Lines ---
# Using variables for the lines makes the sed commands cleaner and quoting easier to manage.
# \$(VARIABLE) is used to write literal $(VARIABLE) for 'make' to expand later.

# Compiler and Linker
CXX_LINE="CXX         = /usr/local/cuda/bin/nvcc"
LINKER_LINE="LINKER      = /usr/local/cuda/bin/nvcc" # Using nvcc as the linker

# HPCG Definitions
# Original Make.Linux_MPI often has: HPCG_DEFS = -DUSING_MPI $(CPPFLAGS)
# We add -DHPCG_WITH_CUDA and -DUSING_OMP, and ensure $(CPPFLAGS) is still included for any user/system defines.
HPCG_DEFS_LINE="HPCG_DEFS = -DUSING_MPI -DHPCG_WITH_CUDA -DUSING_OMP \\\$(CPPFLAGS)"

# CXXFLAGS for nvcc
# Includes:
#   - nvcc's own optimization level (-O<num>)
#   - CUDA gencode flags
#   - MPI compile flags (typically -I paths, -D defines; nvcc passes these to host compiler)
#   - -Xcompiler flags for host-specific optimizations and OpenMP
#   - HPCG definitions (which includes $(CPPFLAGS))
#   - C++ standard
CXXFLAGS_LINE="CXXFLAGS    = -O${NVCC_OPT_LEVEL_FOR_SED} ${CUDA_GENCODE_FLAGS_ENV} ${MPI_COMPILE_FLAGS_ENV} -Xcompiler \"${HOST_OPT_FLAGS_FOR_SED}\" -Xcompiler \"${HOST_OMP_FLAG}\" \\\$(HPCG_DEFS) -std=c++11"

# LINKFLAGS for nvcc (when acting as the linker)
# Includes:
#   - nvcc's own optimization level (-O<num>)
#   - -Xcompiler flags for host-specific optimizations (passed to host linker phase by nvcc)
LINKFLAGS_LINE="LINKFLAGS   = -O${NVCC_OPT_LEVEL_FOR_SED} -Xcompiler \"${HOST_OPT_FLAGS_FOR_SED}\""

# HPCG_LIBS (Linker Libraries)
# Includes:
#   - OpenBLAS (using $(OPENBLAS_HOME) for make to expand)
#   - Standard libraries (pthread, math)
#   - CUDA runtime library
#   - MPI link flags (from MPI_LINK_FLAGS_ENV, which should have -Xlinker for -Wl, flags)
#   - OpenMP link library (LINK_OMP_LIB, e.g., -lgomp)
# IMPORTANT: The MPI_LINK_FLAGS_ENV must be correctly processed to have -Xlinker for -Wl, flags.
HPCG_LIBS_LINE="HPCG_LIBS   = -L\\\$(OPENBLAS_HOME)/lib -lopenblas -lpthread -lm -lcudart ${MPI_LINK_FLAGS_ENV} ${LINK_OMP_LIB}"


# --- Apply Modifications using sed ---
echo "Applying modifications to ${MAKEFILE_PATH}..."

sed -i "s|^CXX\s*=.*|${CXX_LINE}|" "${MAKEFILE_PATH}"
sed -i "s|^LINKER\s*=.*|${LINKER_LINE}|" "${MAKEFILE_PATH}"
sed -i "s|^HPCG_DEFS\s*=.*|${HPCG_DEFS_LINE}|" "${MAKEFILE_PATH}"
sed -i "s|^CXXFLAGS\s*=.*|${CXXFLAGS_LINE}|" "${MAKEFILE_PATH}"
sed -i "s|^LINKFLAGS\s*=.*|${LINKFLAGS_LINE}|" "${MAKEFILE_PATH}"
sed -i "s|^HPCG_LIBS\s*=.*|${HPCG_LIBS_LINE}|" "${MAKEFILE_PATH}"

# Remove original MPI-specific variable definitions from Make.Linux_MPI template that might conflict
# (e.g., MPICXX, MPILIBS, MPIFLAGS). Using || true to prevent exit if pattern not found.
echo "Removing potentially conflicting MPI variables from Makefile..."
sed -i '/^MPICXX\s*=/d' "${MAKEFILE_PATH}" || true
sed -i '/^MPICC\s*=/d' "${MAKEFILE_PATH}" || true
sed -i '/^MPIFC\s*=/d' "${MAKEFILE_PATH}" || true
sed -i '/^MPIFLAGS\s*=/d' "${MAKEFILE_PATH}" || true
sed -i '/^MPILIBS\s*=/d' "${MAKEFILE_PATH}" || true
sed -i '/^MPILD\s*=/d' "${MAKEFILE_PATH}" || true # Often used for MPI linker

# Add/Ensure definitions for CUDA_HOME and OPENBLAS_HOME are in the Makefile
# These are referenced by \$(OPENBLAS_HOME) and potentially by CUDA gencode logic if not in PATH
echo "Ensuring CUDA_HOME and OPENBLAS_HOME are defined in Makefile..."
if ! grep -q "^CUDA_HOME\s*=" "${MAKEFILE_PATH}"; then
    echo "" >> "${MAKEFILE_PATH}" # Add a blank line for separation if needed
    echo "CUDA_HOME = /usr/local/cuda" >> "${MAKEFILE_PATH}"
fi
if ! grep -q "^OPENBLAS_HOME\s*=" "${MAKEFILE_PATH}"; then
    echo "" >> "${MAKEFILE_PATH}" # Add a blank line for separation if needed
    echo "OPENBLAS_HOME = /usr" >> "${MAKEFILE_PATH}"
fi

echo "--- Makefile modification complete. Final checks: ---"
echo "Final CXXFLAGS line in ${MAKEFILE_PATH}:"
grep "^CXXFLAGS\s*=" "${MAKEFILE_PATH}" || echo "CXXFLAGS line not found!"
echo "Final HPCG_LIBS line in ${MAKEFILE_PATH}:"
grep "^HPCG_LIBS\s*=" "${MAKEFILE_PATH}" || echo "HPCG_LIBS line not found!"
echo "-----------------------------------------------------"

# --- Clean up Sourced Environment Files ---
# These files are temporary and created by previous Dockerfile RUN steps.
echo "Cleaning up temporary environment files..."
rm -f $ENV_FILES_TO_SOURCE # Use the variable defined at the top

echo "HPCG Makefile configuration script finished successfully."
