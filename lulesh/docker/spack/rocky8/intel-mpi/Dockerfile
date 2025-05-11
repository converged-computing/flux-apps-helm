ARG tag="8"
FROM rockylinux:${tag} as builder

ENV SPACK_ROOT=/opt/spack-environment/spack
ARG spack_cpu_arch=x86_64

#  Enable PowerTools for development packages
RUN yum -y update \
 && dnf -y install 'dnf-command(config-manager)' \
 && yum config-manager --set-enabled powertools || dnf config-manager --enable crb \
 && yum -y update \
 && yum -y install epel-release \
 && yum -y install \
	wget \
        fftw-devel \
        fftw \
	git \
	bind-utils \
	sudo \
	jq \
	which \
	file \
	unzip \
	vim \
	patch \
	diffutils \
	pkgconfig \
	libtool \
	autoconf \
	automake \
	gcc-gfortran \
	gcc \
	gcc-c++ \
	make \
	cmake \
	bison \	
	flex \
	python3-devel \
        fftw3-devel fftw3 \
        openssh-server \
        openssh-clients \
 && yum clean all

#  Set default /usr/bin/python to python3
RUN alternatives --set python /usr/bin/python3 || true

ENV LANG=C.UTF-8
RUN printf "LANG=C.UTF-8" > /etc/locale.conf

RUN git clone https://github.com/GoogleCloudPlatform/hpc-tools && \
    yum group install -y "Development tools" && \
    cd hpc-tools/rocky_linux_8 && \
    chmod +x google_install_intelmpi && \
    # installs to /opt/intel
    ./google_install_intelmpi --impi_2021

# IMPORTANT: cpu gets +int64, and gpu +mixedint
RUN mkdir /opt/spack-environment \
    &&  (echo "spack:" \
    &&   echo "  specs:" \
    &&   echo "  - flux-sched" \
    &&   echo "  - flux-core" \
    &&   echo "  - pmix@4.2.2" \
    &&   echo "  - flux-pmix@0.4.0" \
    &&   echo "  - lulesh" \
    &&   echo "  concretizer:" \
    &&	 echo "    unify: true" \
    &&	 echo "  packages:" \
    &&	 echo "    intel-oneapi-mpi:" \
    &&	 echo "      externals:" \
    &&	 echo "      - spec: intel-oneapi-mpi@2021.13.0" \
    &&	 echo "        prefix: /opt/intel" \
    &&	 echo "        buildable: false" \
    &&	 echo "    all:" \
    &&	 echo "      providers:" \
    &&	 echo "        mpi: [intel-oneapi-mpi]" \
    &&   echo "  config:" \
    &&   echo "    install_tree: /opt/software" \
    &&   echo "    prefer_externals: true" \
    &&   echo "  view: /opt/view") > /opt/spack-environment/spack.yaml

RUN cd /opt/spack-environment \
    && git clone --depth 1 --branch v0.22.1 https://github.com/spack/spack.git \
    && . spack/share/spack/setup-env.sh \
    && spack env activate . \
    && spack external find openssh \
    && spack external find cmake \
    && spack install --reuse --fail-fast \
    && spack gc -y

# Modifications to the environment that are necessary to run
RUN cd /opt/spack-environment \
    && . spack/share/spack/setup-env.sh \
    && spack env activate --sh -d . >> /etc/profile.d/z10_spack_environment.sh

WORKDIR /opt
RUN yum update -y && yum install -y curl
    
# Finally, install oras for saving artifacts
RUN export VERSION="1.2.0" && \
    curl -LO "https://github.com/oras-project/oras/releases/download/v${VERSION}/oras_${VERSION}_linux_amd64.tar.gz" && \
    mkdir -p oras-install/ && \
    tar -zxf oras_${VERSION}_*.tar.gz -C oras-install/ && \
    mv oras-install/oras /usr/local/bin/ && \
    rm -rf oras_${VERSION}_*.tar.gz oras-install/
