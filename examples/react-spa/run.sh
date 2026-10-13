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
# HTTPS address for the user to accept: `open` on macOS, `xdg-open` on Linux, `explorer.exe` on
# WSL, which exits 1 even when it opens the page.
HEALTH=https://localhost:8443/__sim__/health
OPENED=yes
if command -v open > /dev/null; then
  open "$HEALTH"
elif command -v xdg-open > /dev/null; then
  xdg-open "$HEALTH"
elif command -v explorer.exe > /dev/null; then
  explorer.exe "$HEALTH" || true
else
  OPENED=no
fi

echo
if [ "$OPENED" = yes ]; then
  echo "A browser window opened at $HEALTH."
else
  echo "Open $HEALTH in your browser."
fi
cat <<'MESSAGE'
If it shows a certificate warning, choose Advanced, then Proceed. In Chrome, if there is no
Proceed link, type thisisunsafe on that page.

Then open http://localhost:5173/ and sign in as alice@example.test.

MESSAGE

npm run dev
