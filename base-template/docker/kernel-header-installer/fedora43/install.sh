#!/usr/bin/env bash
set -eo pipefail
dnf update -y
dnf in -y kernel-devel kernel-headers
kernel_dir=/lib/modules/$(ls /lib/modules)
# This is a symbolic (broken) link
rm -rf rm $kernel_dir/build
src_dir=/usr/src/kernels/$(ls /usr/src/kernels)
ln -s $src_dir $kernel_dir/build
exit 0
