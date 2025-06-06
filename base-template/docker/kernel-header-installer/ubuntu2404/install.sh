#!/usr/bin/env bash
set -eo pipefail
apt-get update
apt-get install -y linux-headers-$(uname -r)
apt-get install -y linux-headers-generic
exit 0
