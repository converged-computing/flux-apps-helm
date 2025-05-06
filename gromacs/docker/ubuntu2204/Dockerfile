ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}
WORKDIR /opt
ENV GROMACS_VERSION=2024.2

# Configure GROMACS with CMake.
# -DGMX_MPI=ON enables MPI support for multi-node execution.
# -DGMX_BUILD_OWN_FFTW=ON is an alternative if you don't want to use the system FFTW.
# -DCMAKE_INSTALL_PREFIX sets the installation directory.
# -DREGRESSIONTEST_DOWNLOAD=ON will download regression tests
RUN wget http://ftp.gromacs.org/pub/gromacs/gromacs-${GROMACS_VERSION}.tar.gz && \
    tar xvf gromacs-${GROMACS_VERSION}.tar.gz && \
    rm gromacs-${GROMACS_VERSION}.tar.gz && \
    cd gromacs-${GROMACS_VERSION} && mkdir build && cd build && \
    cmake .. \
    -DGMX_MPI=ON \
    -DGMX_BUILD_OWN_FFTW=ON \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DREGRESSIONTEST_DOWNLOAD=ON \
    -DCMAKE_BUILD_TYPE=Release && make -j4 && make install

WORKDIR /opt/gromacs
