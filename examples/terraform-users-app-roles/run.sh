#!/usr/bin/env bash
# Apply this example against the simulator in one step.
#
# Starts the simulator in Docker if it is not already running, trusts its CA for the duration of
# the run, and applies main.tf. Remove everything again with ./run.sh destroy.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=../simulator.sh
source ../simulator.sh

# The provider fetches the simulator's metadata over HTTPS, so it has to trust the simulator's CA.
export SSL_CERT_FILE="$SIM_CA"

terraform init -input=false >/dev/null
terraform "${1:-apply}"
