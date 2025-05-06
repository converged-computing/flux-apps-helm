ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204-cuda
FROM ${base}

WORKDIR /opt
RUN git clone https://github.com/NVIDIA/multi-gpu-programming-models && \
    cd multi-gpu-programming-models/mpi && \
    make

EXPOSE 22
WORKDIR /opt/multi-gpu-programming-models/mpi
