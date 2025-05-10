ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN python3 -m pip install mpi4jax==0.7.1 && \
    python3 -m pip install jax[cpu]==0.5.2
RUN git clone -b v0.7.1 https://github.com/mpi4jax/mpi4jax && \
    python3 -m pip install tqdm matplotlib && \
    apt-get install -y ffmpeg
WORKDIR /opt/mpi4jax/examples
