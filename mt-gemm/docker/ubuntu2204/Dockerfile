ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN git clone https://repository.prace-ri.eu/git/CodeVault/hpc-kernels/dense_linear_algebra.git
COPY gemm_mpi.cpp /opt/dense_linear_algebra/gemm/mpi/src/
RUN cd /opt/dense_linear_algebra/gemm/mpi && \
    mkdir build && cd build && \
    cmake ../ && make && make install

# command is 1_dense_gemm_mpi
WORKDIR /opt/dense_linear_algebra/gemm/mpi