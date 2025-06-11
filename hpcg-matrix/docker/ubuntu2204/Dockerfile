ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE} AS builder

# --- Environment Variables ---
ENV DEBIAN_FRONTEND=noninteractive

# --- Install Build Dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gfortran \
    wget \
    ca-certificates \
    openmpi-bin \
    libopenmpi-dev \
    sed \
    && rm -rf /var/lib/apt/lists/*

# --- Download and Extract HPCG Source ---
ARG HPCG_VERSION=3.1
ENV HPCG_DIR=/opt/hpcg-${HPCG_VERSION}
WORKDIR /opt
# RUN wget https://www.hpcg-benchmark.org/downloads/hpcg-${HPCG_VERSION}.tar.gz | tar -xz
COPY ./hpcg-3.1.tar.gz .
RUN tar -xzvf hpcg-3.1.tar.gz

# --- Build-time Configuration Arguments ---
ARG ARCH=Linux_OpenMPI
ARG CXX_COMPILER=mpicxx
ARG OPTIMIZATION_FLAGS="-O3 -march=native"
ARG MARCH_FLAG="native"

# --- Configure the HPCG Build (Create setup/Make.ARCH) ---
WORKDIR ${HPCG_DIR}
RUN mkdir -p setup && \
  { \
    echo "SHELL        = /bin/sh"; \
    echo "CXX          = ${CXX_COMPILER}"; \
    echo "CXXFLAGS     = \$(DEFINES) ${OPTIMIZATION_FLAGS} -march=${MARCH_FLAG} -fopenmp"; \
    echo "LINKER       = \$(CXX)"; \
    echo "LINKFLAGS    = \$(CXXFLAGS)"; \
    echo "MPI_INC      ="; \
    echo "MPI_LIBS     ="; \
    echo "MPI_DEFINES  = -DHPCG_WITH_MPI"; \
    echo "DEFINES      = \$(MPI_DEFINES)"; \
    echo "HPCG_INCLUDES= "; \
    echo "HPCG_LIBS    = "; \
  } > setup/Make.${ARCH}

RUN sed -i 's/shared(local_residual, v1v, v2v)/shared(local_residual, v1v, v2v, n)/' src/ComputeResidual.cpp \
    && make arch=${ARCH}

# ===================================================================
# Stage 2: Final Image
# ===================================================================
FROM ${BASE_IMAGE}

# --- Install Runtime Dependencies ---
# libgomp1 is the OpenMP runtime. libgfortran5 is a dependency for MPI.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openmpi-bin \
    libgfortran5 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hpcg
COPY --from=builder /opt/hpcg-*/bin/xhpcg .
COPY --from=builder /opt/hpcg-*/bin/hpcg.dat .
COPY ./entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
