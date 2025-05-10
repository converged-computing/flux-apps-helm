ARG base=ghcr.io/converged-computing/flux-intel-mpi:rocky8
FROM ${base}

WORKDIR /opt
RUN . /opt/rh/gcc-toolset-13/enable && \
    . /opt/intel/mpi/latest/env/vars.sh && \
   git clone --depth 1 https://github.com/lammps/lammps.git && \
   cd lammps && mkdir build && \
   cd build && \
    cmake ../cmake -D PKG_REAXFF=yes -D BUILD_MPI=yes -D PKG_OPT=yes -D FFT=FFTW3 \
    -D CMAKE_INSTALL_PREFIX=/usr \
    && make && make install 
    
WORKDIR /opt/lammps/examples/reaxff/HNS
