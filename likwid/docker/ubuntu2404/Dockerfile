ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN VERSION=stable && wget http://ftp.fau.de/pub/likwid/likwid-$VERSION.tar.gz && \
    tar -xaf likwid-$VERSION.tar.gz && rm likwid-$VERSION.tar.gz && \
    cd likwid-* && make && make install