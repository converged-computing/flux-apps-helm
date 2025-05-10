FROM rockylinux:8

RUN dnf update -y && dnf clean all && \
    dnf group install -y "Development Tools" && \
    dnf config-manager --set-enabled powertools && \
    dnf install -y epel-release

RUN dnf install -y \
    cmake \
    munge \
    munge-devel \
    hwloc \
    hwloc-devel \
    pmix \
    pmix-devel \
    lua \
    lua-devel \
    lua-posix \
    libevent-devel \
    czmq-devel \
    jansson-devel \
    lz4-devel \
    sqlite-devel \
    ncurses-devel \
    libarchive-devel \
    libxml2-devel \
    yaml-cpp-devel \
    boost-devel \
    libedit-devel \
    nfs-utils \
    python3-devel \
    python3-cffi \
    python3-yaml \
    python3-jsonschema \
    python3-sphinx \
    python3-docutils \
    aspell \
    aspell-en \
    valgrind-devel \
    wget \
    jq

RUN groupadd -g 1004 flux && \
    useradd -u 1004 -g 1004 -M -r -s /bin/false -c "flux-framework identity" flux
RUN dnf install -y grubby && \
    grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"

RUN yum install -y gcc-toolset-13
WORKDIR /opt

# Install openpmix, prrte
WORKDIR /opt/prrte
RUN . /opt/rh/gcc-toolset-13/enable && \
    git clone https://github.com/openpmix/openpmix.git && \
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
    rm -rf prrte && set +x

RUN . /opt/rh/gcc-toolset-13/enable && \
    wget https://github.com/flux-framework/flux-security/releases/download/v0.13.0/flux-security-0.13.0.tar.gz && \
    tar -xzvf flux-security-0.13.0.tar.gz && \
    mv flux-security-0.13.0 /opt/flux-security && \
    cd /opt/flux-security && \
    ./configure --prefix=/usr --sysconfdir=/etc && \
    make -j && make install

# The VMs will share the same munge key
RUN mkdir -p /var/run/munge && \
    dd if=/dev/urandom bs=1 count=1024 > munge.key && \
    mv munge.key /etc/munge/munge.key && \
    chown -R munge /etc/munge/munge.key /var/run/munge && \
    chmod 600 /etc/munge/munge.key

# Flux core
RUN . /opt/rh/gcc-toolset-13/enable && \
    wget https://github.com/flux-framework/flux-core/releases/download/v0.73.0/flux-core-0.73.0.tar.gz && \
    tar -xzvf flux-core-0.73.0.tar.gz && \
    mv flux-core-0.73.0 /opt/flux-core && \
    cd /opt/flux-core && \
    ./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/home/flux/run --with-flux-security && \
    make clean && \
    make -j && make install

# Flux pmix (must be installed after flux core)
RUN . /opt/rh/gcc-toolset-13/enable && \
    wget https://github.com/flux-framework/flux-pmix/releases/download/v0.6.0/flux-pmix-0.6.0.tar.gz && \
    tar -xzvf flux-pmix-0.6.0.tar.gz && \
    mv flux-pmix-0.6.0 /opt/flux-pmix && \
    cd /opt/flux-pmix && \
    ./configure --prefix=/usr && \
    make -j && \
    make install

# Flux sched
WORKDIR /opt
RUN . /opt/rh/gcc-toolset-13/enable && \
    wget https://github.com/flux-framework/flux-sched/releases/download/v0.41.0/flux-sched-0.41.0.tar.gz && \
    tar -xzvf flux-sched-0.41.0.tar.gz && \
    cd flux-sched-0.41.0 && \
    ln $(which python3) /usr/bin/python && \
    mkdir build && \
    cd build && \
    cmake -DPython_EXECUTABLE=/usr/bin/python3 -DPython_LIBRARIES=/usr/lib64 ../ && \
    make && make install

RUN . /opt/rh/gcc-toolset-13/enable && \
    wget https://www.mpich.org/static/downloads/4.3.0/mpich-4.3.0.tar.gz && \
    tar -xzvf mpich-4.3.0.tar.gz && \
    cd mpich-4.3.0 && \
    ./configure --prefix=/usr && \
    make -j 4 && make install
    
# IMPORANT: the above installs to /usr/lib64 but you will get a flux_open error if it's
# not found in /usr/lib. So we put in both places :)
RUN cp -R /usr/lib64/flux /usr/lib/flux && cp -R /usr/lib64/libflux-* /usr/lib/
