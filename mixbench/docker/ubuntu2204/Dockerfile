ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN mkdir mixbench && \
    cd mixbench && \
    git init && \
    git remote add origin https://github.com/ekondis/mixbench && \
    git fetch --depth 1 origin 440a133a6423840ce613d1eaab43cd586effd389 && \
    git checkout FETCH_HEAD && \
    cd /opt/mixbench/mixbench-cpu && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    cmake --build ./ && make && \
    cp mixbench-cpu /usr/local/bin

EXPOSE 22
WORKDIR /opt/mixbench