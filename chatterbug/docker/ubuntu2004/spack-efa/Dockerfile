FROM ubuntu:20.04 as builder
ARG spack_cpu_arch=x86_64

# docker build -t cb .
# docker run -it cb bash
# cd /root/chatterbug
#   pairs
#   ping-pong
#   spread
#   stencil3d
#   stencil4d
#   subcom2d-coll
#   subcom2d-a2a
#   unstr-mesh

ENV DEBIAN_FRONTEND=nonintercative
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
    libevent-core-2.1-7 \
    libevent-pthreads-2.1-7 \
    hwloc \
    openssh-server \
    openssh-client \
    libblas-dev \
    liblapack-dev \
    fftw3-dev fftw3 \
    libxml2 \
    libxml2-dev \
    hdf5-tools \
    libhdf5-dev \
    libboost-all-dev \
    pciutils \
    tcl \
    environment-modules \
    ethtool \
    dmidecode \
    iproute2 \
    udev \
    software-properties-common

RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update && apt-get -y upgrade \
    && apt-get -y install build-essential gcc-11 g++-11 gfortran-11 \
    && apt-get clean \
    && apt-get autoremove \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir /opt/spack-environment \
    &&  (echo "spack:" \
    &&   echo "  specs:" \
    &&   echo "  - otf2@2.3 target=x86_64" \
    &&   echo "  concretizer:" \ 
    &&   echo "    unify: true" \
    &&   echo "  config:" \
    &&   echo "    install_tree: /opt/software" \
    &&   echo "  view: /opt/view") > /opt/spack-environment/spack.yaml

RUN cd /opt/spack-environment \
    && git clone https://github.com/spack/spack.git \
    && . ./spack/share/spack/setup-env.sh \
    && spack env activate . \
    && spack clean -m \
    && spack install --reuse --fail-fast \
    && spack gc -y

RUN cd /opt/spack-environment &&  . ./spack/share/spack/setup-env.sh \
    && spack env activate --sh -d . >> /etc/profile.d/z10_spack_environment.sh

RUN echo "export PATH=/opt/openmpi/bin:\$PATH" >>  /etc/profile.d/z10_spack_environment.sh \
    && echo "export LD_LIBRARY_PATH=/opt/view/lib:/opt/openmpi/lib:\$LD_LIBRARY_PATH" >> /etc/profile.d/z10_spack_environment.sh

RUN wget https://perftools.pages.jsc.fz-juelich.de/cicd/scorep/tags/scorep-7.1/scorep-7.1.tar.gz \
    && tar -zxvf scorep-7.1.tar.gz \
    && cd scorep-7.1 \
    && . /etc/profile \
    && mkdir -p _build \
    && cd _build \
    && ../configure --prefix=/opt/scorep/ --with-otf2=/opt/view/bin/ --with-mpi=openmpi \
    && make -j 8 \
    && make install

RUN echo "export PATH=/opt/scorep/bin:\$PATH" >> /etc/profile.d/z10_spack_environment.sh \
    && echo "export LD_LIBRARY_PATH=/opt/scorep/lib:\$LD_LIBRARY_PATH" >> /etc/profile.d/z10_spack_environment.sh

RUN cd /root \
    && . /etc/profile \
    && git clone https://github.com/hpcgroup/chatterbug.git \
    && cd chatterbug/  \
    && make all;

RUN find -L /opt/view/* -type f -exec readlink -f '{}' \; | \
    xargs file -i | \
    grep 'charset=binary' | \
    grep 'x-executable\|x-archive\|x-sharedlib' | \
    awk -F: '{print $1}' | xargs strip -s

#Now we build the final image
FROM ubuntu:20.04

COPY --from=builder /opt/spack-environment /opt/spack-environment
COPY --from=builder /opt/software /opt/software
COPY --from=builder /opt/view /opt/view
COPY --from=builder /opt/scorep /opt/scorep/
COPY --from=builder /etc/profile.d/z10_spack_environment.sh /etc/profile.d/z10_spack_environment.sh

ENV DEBIAN_FRONTEND="nonintercative"
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    zip \
    libnuma-dev \
    libatomic1 \
    binutils \
    libgomp1 \
    libevent-core-2.1-7 \
    libevent-pthreads-2.1-7 \
    hwloc \
    libgomp1 \
    openssh-server \
    openssh-client \
    libblas-dev \
    libibverbs1 \
    liblapack-dev \
    fftw3 \
    hdf5-tools \
    libboost-all-dev \
    pciutils \
    tcl \
    environment-modules \
    ethtool \
    dmidecode \
    iproute2 \
    udev \
    dnsutils \
    pdsh \
    software-properties-common

RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y \
    && apt-get update && apt-get -y upgrade \
    && apt-get -y install libstdc++6 \
    && apt-get clean \
    && apt-get autoremove \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add priviledge separation directoy to run sshd as root.
RUN wget -q --timeout=20 https://s3-us-west-2.amazonaws.com/aws-efa-installer/aws-efa-installer-latest.tar.gz -O /tmp/aws-efa-installer-latest.tar.gz \
    && tar -xf /tmp/aws-efa-installer-latest.tar.gz -C /tmp \
    && cd /tmp/aws-efa-installer \
    && ./efa_installer.sh -y -d --skip-kmod --skip-limit-conf --no-verify \
    && rm -f /tmp/aws-efa-installer-latest.tar.gz
RUN mkdir -p /var/run/sshd

# Allow OpenSSH to talk to containers without asking for confirmation
# by disabling StrictHostKeyChecking.
EXPOSE 22
ARG port=22
RUN sed -i "s/[ #]\(.*StrictHostKeyChecking \).*/ \1no/g" /etc/ssh/ssh_config \
    && echo "    UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config \
    && sed -i "s/[ #]\(.*Port \).*/ \1$port/g" /etc/ssh/ssh_config \
    && sed -i "s/#\(StrictModes \).*/\1no/g" /etc/ssh/sshd_config \
    && sed -i "s/#\(Port \).*/\1$port/g" /etc/ssh/sshd_config

RUN mkdir -p /root/chatterbug/
COPY --from=builder /root/chatterbug /root/chatterbug

WORKDIR /root/chatterbug/
