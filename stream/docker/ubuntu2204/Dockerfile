ARG base=ghcr.io/converged-computing/flux-openmpi:ubuntu2204
FROM ${base}

WORKDIR /opt/stream
COPY ./src .
RUN apt-get install -y gfortran && \
    make && cp stream_c.exe /usr/local/bin && cp stream_f.exe /usr/local/bin