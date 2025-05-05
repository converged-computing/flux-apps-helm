FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

#  docker build -f Dockerfile -t ghcr.io/converged-computing/metric-snap .

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install \
    autotools-dev \
    autoconf \
    automake \
    cmake \
    git \
    python3 \
    dnsutils \
    libatomic1 \
    libnuma-dev \
    libgomp1 \
    openssh-server \
    openssh-client \
    apt-utils \
    gcc \
    unzip \
    gfortran \
    g++ \
    build-essential \
    software-properties-common

WORKDIR /opt
RUN git clone --depth 1 --branch v0.23.1 https://github.com/spack/spack.git && \
    cd ./spack && \
    . ./share/spack/setup-env.sh && \
   spack install --reuse --fail-fast gamess-ri-mp2-miniapp && \
   spack gc -y
    
# Finally, install oras for saving artifacts
RUN export VERSION="1.1.0" && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v${VERSION}/oras_${VERSION}_linux_amd64.tar.gz" && \
    mkdir -p oras-install/ && \
    tar -zxf oras_${VERSION}_*.tar.gz -C oras-install/ && \
    mv oras-install/oras /usr/local/bin/ && \
    rm -rf oras_${VERSION}_*.tar.gz oras-install/
