ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
ENV NRSCONFIG_NOBUILD=1

RUN mkdir nekrs && \
    cd nekrs && \
    git init && \
    git remote add origin https://github.com/Nek5000/nekRS && \
    git fetch --depth 1 origin 4f87e0e2ec0492e2a3edf27791252d6886814d00 && \
    git checkout FETCH_HEAD && \
    CC=mpicc CXX=mpic++ FC=mpif77 ./nrsconfig -DCMAKE_INSTALL_PREFIX=/usr && \
    cd build && \
    cmake ../ && make -j 4 && make install
   
WORKDIR /opt/nekrs
ENV NEKRS_HOME=/usr
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

# This is trying to handle just in time compiling, which produces a cache with an so
# if you don't do this, the worker nodes can't access it.
WORKDIR /opt/nekrs/examples/turbPipe