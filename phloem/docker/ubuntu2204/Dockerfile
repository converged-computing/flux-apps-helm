ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt

RUN git clone https://github.com/LLNL/phloem && \
    cd phloem && mkdir -p /usr/include/sys && \
    ln -s /usr/include/x86_64-linux-gnu/sys/resource.h /usr/include/sys/resource.h && \
    make && cp ./mpigraph-1.6/mpiGraph/mpiGraph /usr/bin/ && \
    cp ./mpigraph-1.6/mpiBench/mpiBench /usr/bin/ && \
    cp presta-1.3.0/latency.message.sizes /usr/bin/ && \
    cp presta-1.3.0/com /usr/bin/ && \
    cp presta-1.3.0/bw.message.sizes /usr/bin/ && \
    cp sqmr-1.1.0/sqmr /usr/bin/   

# Finally, install oras for saving artifacts
RUN export VERSION="1.2.0" && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v${VERSION}/oras_${VERSION}_linux_amd64.tar.gz" && \
    mkdir -p oras-install/ && \
    tar -zxf oras_${VERSION}_*.tar.gz -C oras-install/ && \
    mv oras-install/oras /usr/local/bin/ && \
    rm -rf oras_${VERSION}_*.tar.gz oras-install/

WORKDIR /opt/phloem