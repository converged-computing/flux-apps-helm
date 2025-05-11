ARG base=ghcr.io/converged-computing/flux-mpich:ubuntu2204-cuda
FROM ${base}

WORKDIR /opt
 
# Clone hypre - note there is a message about --with-unified-memory
# Note I'm not using this, couldn't get it to work
RUN git clone --recursive https://github.com/hypre-space/hypre && \
    cd hypre/src && \
    ./configure --with-cuda --enable-unified-memory --enable-mixedint --with-gpu-arch=70 --with-cuda-home=$CUDA_HOME && \
    make -j && make install

RUN apt-get install -y g++-multilib
RUN git clone --recursive https://github.com/LLNL/AMG2023 amg && \
    cd amg && \ 
    mpicc -O2 -DHAVE_CONFIG_H -I. -I/opt/hypre/src/hypre/include -I/usr/local/cuda/include -DHYPRE_TIMING -c amg.c && \
    mpic++ -o amg amg.o \
    -L/opt/hypre/src/hypre/lib -lHYPRE -Wl,-rpath,/opt/hypre/src/hypre/lib \
    -lm \
    -L/usr/local/cuda/lib64 -L /usr/local/cuda-12.4/compat \
    -lcudart -lcusparse -lcublas -lcurand \
    -Wl,-rpath,/usr/local/cuda-12.4/compat && \
    mv ./amg /usr/local/bin/amg
