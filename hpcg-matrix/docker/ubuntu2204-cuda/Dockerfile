ARG CUDA_VERSION_TAG_DEVEL=12.3.2-devel-ubuntu22.04
FROM nvidia/cuda:${CUDA_VERSION_TAG_DEVEL} AS openmpi_builder

ARG OPENMPI_VERSION=4.1.6
ENV OMPI_INSTALL_PREFIX=/opt/openmpi-gpu-aware

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget make g++ gfortran \
    libhwloc-dev libevent-dev \
    ca-certificates autoconf automake libtool flex bison \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN wget --no-check-certificate https://download.open-mpi.org/release/open-mpi/v${OPENMPI_VERSION%.*}/openmpi-${OPENMPI_VERSION}.tar.gz -O openmpi.tar.gz && \
    tar -xzf openmpi.tar.gz && \
    cd openmpi-${OPENMPI_VERSION} && \
    ./configure --prefix=${OMPI_INSTALL_PREFIX} \
                --with-cuda=${CUDA_HOME} \
                --enable-mpi-cxx \
                --enable-mpi-thread-multiple \
                --with-hwloc=internal \
                --with-libevent=internal \
    && \
    make -j$(nproc) all && \
    make install && \
    cd / && rm -rf /tmp/*


# --- Stage 2: HPCG Builder ---
ARG CUDA_VERSION_TAG_DEVEL=12.3.2-devel-ubuntu22.04
FROM nvidia/cuda:${CUDA_VERSION_TAG_DEVEL} AS builder

ENV OMPI_INSTALL_PREFIX=/opt/openmpi-gpu-aware
COPY --from=openmpi_builder ${OMPI_INSTALL_PREFIX} ${OMPI_INSTALL_PREFIX}
ENV PATH=${OMPI_INSTALL_PREFIX}/bin:${PATH}
ENV LD_LIBRARY_PATH=${OMPI_INSTALL_PREFIX}/lib:${LD_LIBRARY_PATH}
ENV MANPATH=${OMPI_INSTALL_PREFIX}/share/man:${MANPATH}
ENV PKG_CONFIG_PATH=${OMPI_INSTALL_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}

# COPY the Makefile configuration script
COPY configure_hpcg_makefile.sh /usr/local/bin/configure_hpcg_makefile.sh
RUN chmod +x /usr/local/bin/configure_hpcg_makefile.sh

ARG HPCG_VERSION=3.1
ARG OPTIMIZATION_LEVEL=3
ARG MARCH=native
ARG MTUNE
ARG CUDA_ARCHITECTURES="80"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    make \
    g++ \
    gfortran \
    libopenblas-dev \
    ca-certificates \
    patch \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

ENV HOST_OMP_FLAG="-fopenmp"
ENV LINK_OMP_LIB="-lgomp"

# Get MPI compile flags and HARDCODE processed MPI link flags
# In Stage 2: HPCG Builder
# ... after ENV LINK_OMP_LIB ...

# Get MPI compile flags and HARDCODE simplified MPI link flags for debugging
RUN echo "--- Which mpicxx? ---" && which mpicxx && \
    mpicxx --version && \
    RAW_MPI_COMPILE_FLAGS="$(mpicxx --showme:compile 2>/dev/null)" && \
    RAW_MPI_LINK_FLAGS_FROM_MPICXX="$(mpicxx --showme:link 2>/dev/null)" && \ 
    echo "RAW_MPI_COMPILE_FLAGS: [${RAW_MPI_COMPILE_FLAGS}]" && \
    echo "RAW_MPI_LINK_FLAGS_FROM_MPICXX (for verification): [${RAW_MPI_LINK_FLAGS_FROM_MPICXX}]" && \
    \
    _OMPI_LIB_DIR_SCRIPT="${OMPI_INSTALL_PREFIX}/lib" && \
    # SIMPLIFIED: Only -L and -l flags for MPI
    PROCESSED_MPI_LINK_FLAGS="-L${_OMPI_LIB_DIR_SCRIPT}" && \
    PROCESSED_MPI_LINK_FLAGS="${PROCESSED_MPI_LINK_FLAGS} -lmpi_cxx" && \
    PROCESSED_MPI_LINK_FLAGS="${PROCESSED_MPI_LINK_FLAGS} -lmpi" && \
    echo "SIMPLIFIED & PROCESSED MPI_LINK_FLAGS: [${PROCESSED_MPI_LINK_FLAGS}]" && \
    \
    echo "export MPI_COMPILE_FLAGS_ENV=\"${RAW_MPI_COMPILE_FLAGS}\"" > /mpi_compile_flags.sh && \
    echo "export MPI_LINK_FLAGS_ENV=\"${PROCESSED_MPI_LINK_FLAGS}\"" > /mpi_link_flags.sh

WORKDIR /opt

RUN wget --no-check-certificate https://www.hpcg-benchmark.org/downloads/hpcg-${HPCG_VERSION}.tar.gz -O hpcg.tar.gz && \
    tar -xzf hpcg.tar.gz && \
    rm hpcg.tar.gz

WORKDIR /opt/hpcg-${HPCG_VERSION}

# Apply source patches
RUN \
    echo "Patching src/ComputeResidual.cpp..." && \
    sed -i 's/#pragma omp parallel default(none) shared(\s*local_residual\s*,\s*v1v\s*,\s*v2v\s*)/#pragma omp parallel default(none) shared(local_residual, v1v, v2v, n)/' src/ComputeResidual.cpp && \
    grep "#pragma omp parallel default(none) shared(local_residual, v1v, v2v, n)" src/ComputeResidual.cpp > /dev/null || \
        (echo "ERROR: Patching ComputeResidual.cpp FAILED..." ; cat src/ComputeResidual.cpp; exit 1) && \
    echo "src/ComputeResidual.cpp patched." && \
    \
    echo "Patching src/ComputeSYMGS.cpp..." && \
    sed -i -E 's/(#pragma omp parallel default\(none\) shared\([^)]*)\)/\1, numberOfRows)/' src/ComputeSYMGS.cpp && \
    grep "shared([^)]*numberOfRows[^)]*)" src/ComputeSYMGS.cpp > /dev/null || \
        (echo "WARNING: Patching ComputeSYMGS.cpp might have FAILED..." ; cat src/ComputeSYMGS.cpp) && \
    echo "src/ComputeSYMGS.cpp patch attempted." && \
    \
    echo "Patching src/ComputeSPMV.cpp..." && \
    sed -i -E 's/(#pragma omp parallel default\(none\) shared\([^)]*)\)( private|\s*$)/\1, nrow)\2/' src/ComputeSPMV.cpp && \
    grep "shared([^)]*nrow[^)]*)" src/ComputeSPMV.cpp > /dev/null || \
        (echo "WARNING: Patching ComputeSPMV.cpp might have FAILED..." ; cat src/ComputeSPMV.cpp) && \
    echo "src/ComputeSPMV.cpp patch attempted." && \
    \
    echo "Patching src/GenerateProblem.cpp..." && \
    sed -i -E 's/(\#pragma omp parallel default\(none\) shared\([^)]*)(\) private\(i,sum,currentNonZeroIndex\))/\1, nx, ny, nz, gnx, gny, gnz, npx, npy, npz, ipx, ipy, ipz, iz_bound_details, iy_bound_details, ix_bound_details\2/' src/GenerateProblem.cpp && \
    grep "iz_bound_details) private(i,sum,currentNonZeroIndex)" src/GenerateProblem.cpp > /dev/null || \
        (echo "WARNING: Patching GenerateProblem.cpp might have FAILED..." ; cat src/GenerateProblem.cpp) && \
    echo "src/GenerateProblem.cpp patch attempted." && \
    echo "All OpenMP source patches attempted."

RUN cp setup/Make.Linux_MPI setup/Make.Custom_GPU_CUDA

# Generate CUDA gencode flags
RUN TEMP_CUDA_GENCODE_FLAGS=$(echo "${CUDA_ARCHITECTURES}" | \
    awk -F';' '{ \
        for(i=1; i<=NF; i++) { \
            if ($i != "") { printf "-gencode arch=compute_%s,code=sm_%s ", $i, $i; } \
        } \
    }'); \
    echo "export CUDA_GENCODE_FLAGS_ENV=\"${TEMP_CUDA_GENCODE_FLAGS}\"" > /cuda_gencode_env.sh

# Generate NVCC opt level and Host opt flags
RUN _NVCC_OPT_LEVEL_NUMERIC="${OPTIMIZATION_LEVEL}"; \
    _HOST_COMPILER_OPT_FLAG_STRING=""; \
    if [ "${OPTIMIZATION_LEVEL}" = "fast" ]; then \
        _NVCC_OPT_LEVEL_NUMERIC="3"; \
        _HOST_COMPILER_OPT_FLAG_STRING="-Ofast"; \
    elif [ "${OPTIMIZATION_LEVEL}" = "s" ]; then \
        _NVCC_OPT_LEVEL_NUMERIC="2"; \
        _HOST_COMPILER_OPT_FLAG_STRING="-Os"; \
    elif [ "${OPTIMIZATION_LEVEL}" = "g" ]; then \
        _NVCC_OPT_LEVEL_NUMERIC="0"; \
        _HOST_COMPILER_OPT_FLAG_STRING="-Og"; \
    else \
        _NVCC_OPT_LEVEL_NUMERIC="${OPTIMIZATION_LEVEL}"; \
        _HOST_COMPILER_OPT_FLAG_STRING="-O${OPTIMIZATION_LEVEL}"; \
    fi; \
    echo "export NVCC_OPT_LEVEL_FOR_SED=\"${_NVCC_OPT_LEVEL_NUMERIC}\"" > /nvcc_opt_level.sh; \
    \
    _HOST_OPT_FLAGS_BASE_NO_O="-march=${MARCH} -Wno-format-overflow -Wno-unused-result"; \
    _HOST_OPT_FLAGS_CONSTRUCTED="${_HOST_COMPILER_OPT_FLAG_STRING} ${_HOST_OPT_FLAGS_BASE_NO_O}"; \
    if [ -n "${MTUNE}" ] && [ "${MTUNE}" != "none" ]; then \
        _HOST_OPT_FLAGS_SED="${_HOST_OPT_FLAGS_CONSTRUCTED} -mtune=${MTUNE}"; \
    else \
        _HOST_OPT_FLAGS_SED="${_HOST_OPT_FLAGS_CONSTRUCTED}"; \
    fi; \
    echo "export HOST_OPT_FLAGS_FOR_SED=\"${_HOST_OPT_FLAGS_SED}\"" > /host_opt_flags_for_sed.sh

# Execute the script to modify the Makefile
RUN /usr/local/bin/configure_hpcg_makefile.sh

RUN make arch=Custom_GPU_CUDA -j$(nproc)

FROM nvidia/cuda:12.3.2-runtime-ubuntu22.04
ARG HPCG_VERSION=3.1

ENV OMPI_INSTALL_PREFIX=/opt/openmpi-gpu-aware
COPY --from=openmpi_builder ${OMPI_INSTALL_PREFIX}/lib ${OMPI_INSTALL_PREFIX}/lib
COPY --from=openmpi_builder ${OMPI_INSTALL_PREFIX}/bin ${OMPI_INSTALL_PREFIX}/bin

ENV LD_LIBRARY_PATH=${OMPI_INSTALL_PREFIX}/lib:${LD_LIBRARY_PATH}
ENV PATH=${OMPI_INSTALL_PREFIX}/bin:${PATH}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libopenblas-base \
    libgomp1 \
    libhwloc15 \
    libevent-core-2.1-7 \
    libevent-pthreads-2.1-7 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/hpcg-${HPCG_VERSION}/bin/xhpcg /usr/local/bin/xhpcg
COPY --from=builder /opt/hpcg-${HPCG_VERSION}/bin/hpcg.dat /opt/hpcg/hpcg.dat

WORKDIR /opt/hpcg

ENV OMPI_ALLOW_RUN_AS_ROOT=1
ENV OMPI_ALLOW_RUN_AS_ROOT_CONFIRM=1

ENTRYPOINT ["/usr/local/bin/xhpcg"]
CMD ["--nx=104", "--ny=104", "--nz=104"]
