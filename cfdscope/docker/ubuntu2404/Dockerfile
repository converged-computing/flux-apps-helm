ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base} AS builder
WORKDIR /opt

# The optimized code is private.
# RUN git clone https://github.com/tudasc/cfdSCOPE && \
COPY ./cfdSCOPE-nonpublic /opt/cfdSCOPE
RUN cd /opt/cfdSCOPE && \
    mkdir build; cd build; cmake .. && \
    make && cp cfdscope /usr/bin/cfdscope

ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}
COPY --from=builder /usr/bin/cfdscope /usr/bin/cfdscope

