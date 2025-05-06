ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}
WORKDIR /opt

RUN git clone https://github.com/Mantevo/miniAMR && \
    cd miniAMR/openmp && \
    make    
ENV PATH=/opt/miniAMR/openmp:$PATH
