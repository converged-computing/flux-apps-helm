ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2404-cuda
FROM ${base}

WORKDIR /opt
RUN git clone https://github.com/NVIDIA/nccl-tests && \
    cd nccl-tests && make MPI=1 MPI_HOME=/usr