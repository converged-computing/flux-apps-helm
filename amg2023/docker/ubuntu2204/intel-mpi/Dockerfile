ARG base=ghcr.io/converged-computing/flux-intel-mpi:ubuntu2204
FROM $base

WORKDIR /opt
RUN git clone --recursive https://github.com/hypre-space/hypre && \
    cd hypre/src && \
    ./configure --disable-fortran --enable-shared && \
    make -j 8 && make install

RUN apt-get install -y g++-multilib gfortran
RUN git clone --recursive https://github.com/LLNL/AMG2023 amg && \
    cd amg && \ 
    mpicc -O2 -DHAVE_CONFIG_H -I. -I/opt/hypre/src/hypre/include -DHYPRE_TIMING -c amg.c && \
    mpic++ -o amg amg.o -L/opt/intel/oneapi/2025.1/lib -L/opt/hypre/src/hypre/lib -lHYPRE -Wl,-rpath,/opt/hypre/src/hypre/lib -lm -Wl,-rpath,/opt/hypre/src/hypre/lib -Wl,-rpath,/opt/intel/oneapi/2025.1/lib && \
    mv ./amg /usr/local/bin/amg
    
ENV PATH=$PATH:/opt/intel/oneapi/2025.1/bin
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/oneapi/2025.1/lib
