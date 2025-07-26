ARG CUDA_VERSION_TAG_DEVEL=12.4.1-cudnn-devel-ubuntu22.04
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


ARG CUDA_VERSION_TAG_DEVEL=12.4.1-cudnn-devel-ubuntu22.04
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
ARG CUDA_ARCHITECTURES="70"

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

FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04
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

# Utilities
RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        apt-utils \
        locales \
        ca-certificates \
        wget \
        man \
        git \
        flex \
        ssh \
        sudo \
        vim \
        luarocks \
        munge \
        lcov \
        ccache \
        lua5.2 \
        python3-dev \
        python3-pip \
        valgrind \
        jq && \
    rm -rf /var/lib/apt/lists/*

# Compilers, autotools
RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        build-essential \
        pkg-config \
        autotools-dev \
        libtool \
        libffi-dev \
        autoconf \
        automake \
        make \
        clang \
        clang-tidy \
        gcc \
        g++ && \
    rm -rf /var/lib/apt/lists/*

# Now install Flux
RUN pip install --upgrade --ignore-installed \
        "markupsafe==2.0.0" \
        coverage cffi ply six pyyaml "jsonschema>=2.6,<4.0" \
        sphinx sphinx-rtd-theme sphinxcontrib-spelling 
        
RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        libsodium-dev \
        libzmq3-dev \
        libczmq-dev \
        libjansson-dev \
        libmunge-dev \
        libncursesw5-dev \
        liblua5.2-dev \
        liblz4-dev \
        libsqlite3-dev \
        uuid-dev \
        libhwloc-dev \
        libs3-dev \
        libevent-dev \
        libarchive-dev \
        libpam-dev && \
    rm -rf /var/lib/apt/lists/*

# Testing utils and libs
RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        faketime \
        libfaketime \
        pylint \
        cppcheck \
        enchant-2 \
        aspell \
        aspell-en && \
    rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8

# NOTE: luaposix installed by rocks due to Ubuntu bug: #1752082 https://bugs.launchpad.net/ubuntu/+source/lua-posix/+bug/1752082
RUN luarocks install luaposix

# Install openpmix, prrte
WORKDIR /opt/prrte
RUN git clone https://github.com/openpmix/openpmix.git && \
    git clone https://github.com/openpmix/prrte.git && \
    ls -l && \
    set -x && \
    cd openpmix && \
    git checkout fefaed568f33bf86f28afb6e45237f1ec5e4de93 && \
    ./autogen.pl && \
    ./configure --prefix=/usr --disable-static && make -j 4 install && \
    ldconfig && \
    cd .. && \
    cd prrte && \
    git checkout 477894f4720d822b15cab56eee7665107832921c && \
    ./autogen.pl && \
    ./configure --prefix=/usr && make -j 4 install && \
    cd ../.. && \
    rm -rf prrte

ENV LANG=C.UTF-8

ARG FLUX_SECURITY_VERSION=0.11.0

WORKDIR /opt
RUN CCACHE_DISABLE=1 && \
    V=$FLUX_SECURITY_VERSION && \
    PKG=flux-security-$V && \
    URL=https://github.com/flux-framework/flux-security/releases/download && \
    wget ${URL}/v${V}/${PKG}.tar.gz && \
    tar xvfz ${PKG}.tar.gz && \
    cd ${PKG} && \
    ./configure --prefix=/usr --sysconfdir=/etc || cat config.log && \
    make -j 4 && \
    make install && \
    cd .. && \
    rm -rf flux-security-*


# Setup MUNGE directories & key
RUN mkdir -p /var/run/munge && \
    dd if=/dev/urandom bs=1 count=1024 > /etc/munge/munge.key && \
    chown -R munge /etc/munge/munge.key /var/run/munge && \
    chmod 600 /etc/munge/munge.key

RUN wget https://github.com/flux-framework/flux-core/releases/download/v0.61.2/flux-core-0.61.2.tar.gz && \
    tar xzvf flux-core-0.61.2.tar.gz && \
    cd flux-core-0.61.2 && \
    ./configure --prefix=/usr --sysconfdir=/etc && \
    make clean && \
    make && \
    sudo make install

RUN sudo apt-get update
RUN sudo apt-get -qq install -y --no-install-recommends \
        libboost-graph-dev \
        libboost-system-dev \
        libboost-filesystem-dev \
        libboost-regex-dev \
        libyaml-cpp-dev \
        libedit-dev \
        libboost-dev \
        libyaml-cpp-dev \
        curl \
        cmake
    
RUN wget https://github.com/flux-framework/flux-sched/releases/download/v0.33.1/flux-sched-0.33.1.tar.gz && \
    tar -xzvf flux-sched-0.33.1.tar.gz && \
    cd flux-sched-0.33.1 && \
    ./configure --prefix=/usr --sysconfdir=/etc && \
    make && \
    sudo make install && \
    ldconfig

RUN apt-get update && \
    apt-get install -y fftw3-dev fftw3 pdsh libfabric-dev libfabric1 \
        openssh-client openssh-server \
        dnsutils telnet strace git g++ \
        unzip bzip2

# Finally, install oras for saving artifacts
RUN export VERSION="1.2.0" && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v${VERSION}/oras_${VERSION}_linux_amd64.tar.gz" && \
    mkdir -p oras-install/ && \
    tar -zxf oras_${VERSION}_*.tar.gz -C oras-install/ && \
    mv oras-install/oras /usr/local/bin/ && \
    rm -rf oras_${VERSION}_*.tar.gz oras-install/
