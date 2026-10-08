#!/usr/bin/env bash
# Run the React example against the simulator in one step.
#
# Starts the simulator in Docker if it is not already running, creates the app registration and
# the user, writes .env, and starts the site on http://localhost:5173/.
#
# Creating the objects resets the simulator's directory first, so anything else in it is lost.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=../simulator.sh
source ../simulator.sh

echo "Creating the app registration and alice@example.test (this resets the directory)."
if ! CA="$SIM_CA" scripts/setup.sh > .env; then
  echo "Setup failed. If the simulator was already running, it may not serve example.test;" \
    "stop it and run this again." >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  npm install
fi

# The sign-in fails silently until the browser accepts the simulator's certificate, so open its
# HTTPS address for the user to accept.
open https://localhost:8443/__sim__/health

cat <<'MESSAGE'

A browser window opened at https://localhost:8443/__sim__/health. If it shows a certificate
warning, choose Advanced, then Proceed. In Chrome, if there is no Proceed link, type
thisisunsafe on that page.

Then open http://localhost:5173/ and sign in as alice@example.test.

MESSAGE

npm run dev
