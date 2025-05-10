ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt
RUN apt-get install -y libfreetype6-dev libtk tcl-dev tk-dev mesa-common-dev && \
    wget https://github.com/Open-Cascade-SAS/OCCT/archive/refs/tags/V7_9_0.tar.gz && \
    tar -xzvf V7_9_0.tar.gz && \
    cd OCCT-7_9_0 && mkdir build && cd build && cmake ../ && make -j4 && make install
    
# flux run -N 4 ./t8_time_forest_partition -g -b -C 0.8 -x -0.4 -X -0.3 -l 4 -r 3 -O -o -T 0.05
RUN git clone https://github.com/DLR-AMR/t8code && \
    git submodule init && \
    git submodule update && mkdir build && cd build && \
    cmake .. \
      -DCMAKE_C_COMPILER="mpicc" \
      -DCMAKE_CXX_COMPILER="mpicxx" \
      -DCMAKE_Fortran_COMPILER="mpif90" \
      -DCMAKE_CXX_FLAGS="-O" \
      -DOpenCASCADE_INCLUDE_DIR=/usr/local/include/opencascade \
      -DCMAKE_BUILD_TYPE=Release \
      -DT8CODE_ENABLE_OCC=ON \
      -DCMAKE_INSTALL_PREFIX="/usr" \
      -DT8CODE_BUILD_TUTORIALS=ON \
      -DT8CODE_BUILD_EXAMPLES=ON && make -j4 && make install

WORKDIR /opt/t8code
