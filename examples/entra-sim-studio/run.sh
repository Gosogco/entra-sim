#!/usr/bin/env bash
# Run the studio against the simulator in one step.
#
# Starts the simulator in Docker if it is not already running, then starts the studio on
# http://localhost:5174/. With --seed, it first creates the React example's app registration
# and user, which resets the simulator's directory.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=../simulator.sh
source ../simulator.sh

if [ "${1:-}" = "--seed" ]; then
  echo "Creating the React example's app registration and user (this resets the directory)."
  CA="$SIM_CA" ../react-spa/scripts/setup.sh > /dev/null
fi

if [ ! -d node_modules ]; then
  npm install
fi

echo
echo "Open http://localhost:5174/"
echo

npm run dev
