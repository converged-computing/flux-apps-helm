ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}
WORKDIR /opt
RUN git clone https://github.com/tudasc/cfdSCOPE && \
    cd /opt/cfdSCOPE && \
    mkdir build; cd build; cmake .. && \
    make && cp cfdscope /usr/bin/cfdscope