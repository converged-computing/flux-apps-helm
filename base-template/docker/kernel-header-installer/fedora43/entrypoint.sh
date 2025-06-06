#!/usr/bin/env bash
set -o errexit
set -o pipefail
set -o nounset

set -x

# We have to clean up or else there are dangling symlinks
rm -rf /opt/shared/*

# Copy our install script into the shared volume with the host
ls /opt/actions
cp /opt/actions/install.sh /opt/shared/install.sh
ls /opt/shared

ACTION_FILE="/opt/shared/install.sh"
if [[ ! -f "$ACTION_FILE" ]]; then
    echo "Expected to find action file '$ACTION_FILE', but did not exist"
    exit 1
fi

cat ${ACTION_FILE}

# Run the update commands on the host directly
echo "Executing nsenter"
nsenter -t 1 -m bash "${ACTION_FILE}"
RESULT="${PIPESTATUS[0]}"

if [ $RESULT -eq 0 ]; then
    echo "Completed successfully"
    sleep infinity
else
    echo "Failed during nsenter command execution"
    exit 1
fi
