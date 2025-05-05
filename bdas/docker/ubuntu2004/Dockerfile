ARG tag=20.04
FROM ubuntu:${tag}
ENV DEBIAN_FRONTEND=noninteractive

# Example commands
# mpirun -np num_ranks ./source/cxx/build/princomp num_local_rows num_global_cols
# mpirun -np num_ranks Rscript princomp.r num_local_rows num_global_cols
# 16 ranks, 50 total columns, and a total of 16,000 rows (local number of rows 1000)
# mpirun -np 16 princomp 1000 50

RUN apt-get update && \
    apt-get install -y fftw3-dev fftw3 pdsh libfabric-dev libfabric1 \
        openssh-client openssh-server \
        dnsutils telnet strace cmake git g++ \
        r-base r-base-dev \
        unzip bzip2 \
        openmpi-bin openmpi-common libopenmpi-dev libgtk2.0-dev \
        libopenmpi-dev

WORKDIR /opt
RUN wget https://asc.llnl.gov/sites/asc/files/2020-09/BDAS_b4bcf27_0.zip && \
    unzip BDAS_b4bcf27_0.zip && \
    rm -rf __MACOSX && \
    rm BDAS_b4bcf27_0.zip && \
    path=$(ls .) && \
    mv $path bdas && \
    cd bdas/source/cxx && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make 

WORKDIR /opt/bdas/source/r
COPY ./install.R ./install.R
RUN R CMD INSTALL rlecuyer_0.3-4.tar.gz && \
    Rscript ./install.R && \
    # This does not work
    # R CMD INSTALL pbdMPI_0.3-3.tar.gz && \
    R CMD INSTALL kazaam_0.2-0.tar.gz

# Hack for ssh for now...
RUN echo "        LogLevel ERROR" >> /etc/ssh/ssh_config && \
    echo "        StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
    echo "        UserKnownHostsFile=/dev/null" >> /etc/ssh/ssh_config && \
    cd /root && \
    mkdir -p /run/sshd && \
    ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa && chmod og+rX . && \
    cd .ssh && cat id_rsa.pub > authorized_keys && chmod 644 authorized_keys

EXPOSE 22
WORKDIR /opt/bdas
