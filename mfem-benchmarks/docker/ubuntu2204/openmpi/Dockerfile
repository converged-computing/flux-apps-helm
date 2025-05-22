ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN mkdir build && \
    cd build && \ 
    git clone -b pbench_ceed https://github.com/mfem/mfem.git && \
    git clone https://github.com/hypre-space/hypre.git && \
    git clone https://github.com/google/benchmark.git google-benchmark && \
    wget "https://github.com/mfem/tpls/raw/refs/heads/gh-pages/metis-5.1.0.tar.gz" && \
    tar zxf metis-5.1.0.tar.gz && \
    cd metis-5.1.0/build && \
    cmake \
      .. \
      -DCMAKE_C_COMPILER=mpicc \
      -DGKLIB_PATH="../GKlib" \
      -DCMAKE_INSTALL_PREFIX="../install" && \
    make install -j 4

RUN cd /opt/build/hypre/src && \
    ./configure \
      CXX=mpicxx \
      CC=mpicc \
      CFLAGS=-O3 \
      CXXFLAGS=-O3 \
      --disable-fortran \
      --enable-mixedint && \
    make -j 4

RUN cd /opt/build/google-benchmark && \
    cmake \
      -DBENCHMARK_ENABLE_TESTING=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -S . \
      -B build \
      -DCMAKE_INSTALL_PREFIX="install" && \
    cmake --build build --config Release --target install -j 4 

RUN cd /opt/build/mfem && \
    make config \
      MPICXX=mpicxx \
      MFEM_USE_MPI=YES \
      MFEM_USE_METIS_5=YES \
      METIS_DIR="/opt/build/metis-5.1.0/install" \
      MFEM_USE_BENCHMARK=YES \
      BENCHMARK_DIR="/opt/build/google-benchmark/install" \
      BENCHMARK_LIB='-L$(BENCHMARK_DIR)/lib -lbenchmark -lpthread' && \
    make -j 4
    
RUN cd /opt/build/mfem/tests/benchmarks && \
    make pbench_ceed

# run the BP3 benchmark (serial for now):
# ./bench_ceed \
#  --benchmark_filter=BP3 \
#  --benchmark_context=device=cpu \
#  --benchmark_out_format=csv
