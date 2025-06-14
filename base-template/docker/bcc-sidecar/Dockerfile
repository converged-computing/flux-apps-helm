FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        software-properties-common \
        git \
        bison \
        build-essential \
        cmake \
        flex \
        libedit-dev \
        libllvm-18-ocaml-dev libpolly-18-dev libllvm18 llvm-18-dev llvm-18-tools \
        libclang-18-dev clang-18 \        
        zlib1g-dev \
        libelf-dev \
        libfl-dev \
        pkg-config \
        python3 \
        python3-pip \
        python3-setuptools \
        netcat-openbsd \
        iperf3 \
        netperf \
        arping \
        curl \
        vim \
        iproute2 \
        wget \
        net-tools \
        tcpdump \
        zip \
        libbpf-dev \
        linux-tools-common \
        linux-tools-generic \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 -b v0.34.0 https://github.com/iovisor/bcc /usr/src/bcc && \
    mkdir -p /usr/src/bcc/build && \
    cd /usr/src/bcc/build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DPYTHON_CMD=python3 && \
    make -j 4 && \
    make install && \
    ln -s $(which python3) /usr/bin/python && \
    cd / && \
    rm -rf /usr/src/bcc

ENV BCC_PROBE_LIMIT=1048576

# Additional packages
RUN apt-get update && apt-get install -y ibverbs-utils libibverbs-dev libibverbs1 && apt-get clean

# Set up environment for Python BCC tools (if needed)
ENV PYTHONPATH=/usr/lib/python3/dist-packages
RUN python3 -m pip install river --break-system-packages
COPY ./programs /opt/programs
# Command to keep the container running
CMD ["tail", "-f", "/dev/null"]
