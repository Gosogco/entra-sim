#!/usr/bin/env bash
# Run the FastAPI example against the simulator in one step.
#
# Starts the simulator in Docker if it is not already running, generates the certificates,
# creates the directory objects with Terraform, starts the backend on http://127.0.0.1:8000,
# runs both daemons once, and starts the site on http://localhost:5174/.
#
# Creating the objects resets the simulator's directory first, so anything else in it is lost.
set -euo pipefail
cd "$(dirname "$0")"

# shellcheck source=../simulator.sh
source ../simulator.sh

# Before the CA is exported below, which would make pip distrust PyPI.
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install --quiet -r requirements.txt

# The provider, MSAL and the backend's key download all reach the simulator over HTTPS.
export SSL_CERT_FILE="$SIM_CA" REQUESTS_CA_BUNDLE="$SIM_CA"
export ARM_METADATA_HOSTNAME=localhost:8443
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000001
export ARM_CLIENT_ID=11111111-1111-1111-1111-111111111111
export ARM_CLIENT_SECRET=entra-sim-bootstrap-secret

echo "Resetting the simulator's directory and creating the example's objects."
curl --silent --fail --output /dev/null -X POST http://127.0.0.1:8080/__sim__/reset
# The reset emptied the directory, so the old state describes objects that no longer exist.
rm -f terraform/terraform.tfstate terraform/terraform.tfstate.backup

mkdir -p certs
for name in api reporter intruder; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=entra-sim FastAPI example $name" \
    -keyout "certs/$name-key.pem" -out "certs/$name.pem" 2>/dev/null
done

terraform -chdir=terraform init -input=false >/dev/null
terraform -chdir=terraform apply -input=false -auto-approve >/dev/null
terraform -chdir=terraform output -raw env > .env

# Only the backend's and daemons' lines. Vite reads the VITE_ ones itself, and the shell would
# strip the quotes from the JSON among them.
set -a
# shellcheck source=/dev/null
source <(grep -v '^VITE_' .env)
set +a

.venv/bin/uvicorn --app-dir backend app:app --host 127.0.0.1 --port 8000 --log-level warning &
backend=$!
# Replaces simulator.sh's trap, so it repeats that trap's cleanup.
trap 'kill "$backend" 2>/dev/null; rm -rf "$SIM_CA_DIR"' EXIT
for _ in $(seq 1 30); do
  curl --silent --output /dev/null http://127.0.0.1:8000/api/orders && break
  sleep 1
done

echo
echo "The daemons:"
.venv/bin/python daemon/daemon.py reporter || true
.venv/bin/python daemon/daemon.py intruder || true

if [ ! -d frontend/node_modules ]; then
  (cd frontend && npm install)
fi

# The sign-in fails silently until the browser accepts the simulator's certificate, so open its
# HTTPS address for the user to accept: `open` on macOS, `xdg-open` on Linux, `explorer.exe` on
# WSL, which exits 1 even when it opens the page.
HEALTH=https://localhost:8443/__sim__/health
if command -v open > /dev/null; then
  open "$HEALTH"
elif command -v xdg-open > /dev/null; then
  xdg-open "$HEALTH"
elif command -v explorer.exe > /dev/null; then
  explorer.exe "$HEALTH" || true
fi

cat <<MESSAGE

If $HEALTH shows a certificate warning, choose Advanced, then Proceed. In Chrome, if there is
no Proceed link, type thisisunsafe on that page.

Then open http://localhost:5174/ and sign in as alice, bob or carol.

MESSAGE

(cd frontend && npm run dev)
