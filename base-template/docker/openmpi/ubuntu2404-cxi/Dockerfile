FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

# docker build -t ghcr.io/converged-computing/flux-slingshot:ubuntu2404 .
# docker push ghcr.io/converged-computing/flux-slingshot:ubuntu2404

RUN apt-get update && apt-get install -y build-essential \
    tar \
    autoconf \
    automake \
    make \
    wget \
    git \
    gcc \
    g++ \
    zip \
    libblas-dev \
    liblapack-dev \
    libfftw3-dev libfftw3-bin \
    libxml2 \
    libxml2-dev \
    hdf5-tools \
    libhdf5-dev \
    cmake \
    libboost-all-dev \
    && apt-get clean

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

# Python - instead of a system python we install anaconda
# https://docs.conda.io/en/latest/miniconda.html#linux-installers
RUN pip install --upgrade --ignore-installed --break-system-packages \
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

# Install openpmix, prrte. Openpmix (pmix2) seems to be installed by hwloc, v5.x
RUN git clone --recurse-submodules https://github.com/openpmix/prrte.git && \
    cd prrte && \
    git checkout v3.0.1 && \
    ./autogen.pl && \
    ./configure --prefix=/opt/prrte && \
    # This installs OK but the exit code is off.
    make -j all install || true
 
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

ENV FLUX_CORE_VERSION=0.76.0
RUN wget https://github.com/flux-framework/flux-core/releases/download/v${FLUX_CORE_VERSION}/flux-core-${FLUX_CORE_VERSION}.tar.gz && \
    tar xzvf flux-core-${FLUX_CORE_VERSION}.tar.gz && \
    cd flux-core-${FLUX_CORE_VERSION} && \
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
	curl

ENV LD_LIBRARY_PATH=/opt/miniconda/lib

ENV FLUX_SCHED_VERSION=0.45.0
RUN wget https://github.com/flux-framework/flux-sched/releases/download/v${FLUX_SCHED_VERSION}/flux-sched-${FLUX_SCHED_VERSION}.tar.gz && \
    tar -xzvf flux-sched-${FLUX_SCHED_VERSION}.tar.gz && \
    cd flux-sched-${FLUX_SCHED_VERSION} && \
    ./configure --prefix=/usr --sysconfdir=/etc && \
    make && \
    sudo make install && \
    ldconfig

RUN apt-get update && \
    apt-get install -y libfftw3-dev libfftw3-bin pdsh libfabric-dev libfabric1 \
        openssh-client openssh-server \
        dnsutils telnet strace git g++ \
        unzip bzip2

# Additional debugging
RUN apt-get update && \
    apt-get install -y pdsh \
        openssh-client openssh-server \
        dnsutils telnet strace libconfig-dev \
        unzip bzip2

WORKDIR /opt

# Additional packages
RUN apt-get update && apt-get install -y ibverbs-utils libibverbs-dev libibverbs1 && apt-get clean
    
WORKDIR /opt    
ENV FI_PROVIDER=cxi

RUN apt-get install -y libuv1-dev fuse3 libyaml-dev libsensors-dev dkms linux-headers-$(uname -r) libfuse3-dev libfuse-dev libjson-c-dev

RUN git clone https://github.com/HewlettPackard/shs-cassini-headers && \
   mv shs-cassini-headers/include/* /usr/include/ && \
   mv shs-cassini-headers/share/* /usr/share/

RUN git clone https://github.com/HewlettPackard/shs-cxi-driver.git && \
    cp -R shs-cxi-driver/include/* /usr/include/

RUN git clone https://github.com/HewlettPackard/shs-libcxi && \
   cd shs-libcxi && \
   ./autogen.sh && ./configure --prefix=/usr && make && make install 

RUN git clone -b v2.2.0 https://github.com/ofiwg/libfabric.git /opt/libfabric && \
    cd /opt/libfabric && ./autogen.sh && \ 
     ./configure --enable-tcp=yes --enable-udp=yes --enable-sockets=yes --enable-verbs=no --enable-shm=yes --enable-mrail=yes --enable-rxd=yes --enable-rxm=yes --enable-cxi=yes && \
    make -j 4 && make install

RUN wget https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.2.tar.gz && \
    tar -xzvf openmpi-4.1.2.tar.gz && \
    cd openmpi-4.1.2 && \
    ./configure --with-ofi=/usr/local && \
    make -j 4 && make install && ldconfig

# Clean up
RUN rm -rf /opt/*.tar.gz && \
    cd /opt && rm -rf libfabric/ prrte/ flux-sched-0.45.0/ flux-core-0.76.0/ 

# Install oras for saving artifacts
RUN export VERSION="1.2.0" && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v${VERSION}/oras_${VERSION}_linux_amd64.tar.gz" && \
    mkdir -p oras-install/ && \
    tar -zxf oras_${VERSION}_*.tar.gz -C oras-install/ && \
    mv oras-install/oras /usr/local/bin/ && \
    rm -rf oras_${VERSION}_*.tar.gz oras-install/
   
