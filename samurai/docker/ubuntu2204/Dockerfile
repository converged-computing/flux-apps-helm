ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}
WORKDIR /opt

RUN wget https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh && \
    chmod +x Miniforge3-Linux-x86_64.sh && \
    bash Miniforge3-Linux-x86_64.sh -p /opt/miniconda -b

ENV PATH=/opt/miniconda/bin:$PATH
COPY ./mpi-environment.yaml ./mpi-environment.yaml
RUN mamba env create --file ./mpi-environment.yaml
SHELL ["conda", "run", "-n", "samurai-env", "/bin/bash", "-c"]

RUN mamba install -y cxx-compiler
RUN git clone https://github.com/hpc-maths/samurai /opt/samurai && \
    cd /opt/samurai && \
    cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_MPI=ON \
    -DBUILD_DEMOS=ON && \
    cmake --build ./build --config Release --target finite-volume-advection-2d
