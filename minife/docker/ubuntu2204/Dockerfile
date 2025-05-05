ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN mkdir minife && \
    cd minife && \
    git init && \
    git remote add origin https://github.com/Mantevo/minife && \
    git fetch --depth 1 origin abe328816d84afc319c482d6bc8df414b8f90d79 && \
    git checkout FETCH_HEAD

RUN cd /opt/minife/openmp/src && make && cp miniFE.x /usr/local/bin/miniFE.x
WORKDIR /opt/minife