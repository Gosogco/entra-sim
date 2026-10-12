#!/usr/bin/env bash
# Build the simulator's image from this checkout and run it.
#
# The container serves the studio at http://localhost:8080/, plain HTTP on 8080 and HTTPS on
# 8443. A container left by an earlier run is replaced, so the new build is the one running.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=entra-sim:local
CONTAINER_NAME=entra-sim

sim_healthy() {
  curl --silent --fail --output /dev/null http://127.0.0.1:8080/__sim__/health
}

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start it (for example: colima start) and try again." >&2
  exit 1
fi

docker build --tag "$IMAGE" .

docker rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Ports on 127.0.0.1 only: the simulator has no real authentication, and the snapshot the studio
# reads holds every secret, so it stays off the network.
docker run --detach --rm --name "$CONTAINER_NAME" \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 \
  "$IMAGE" >/dev/null

# Startup generates an RSA key, which takes a few seconds.
for _ in $(seq 1 60); do
  sim_healthy && break
  sleep 1
done
if ! sim_healthy; then
  echo "The simulator did not become healthy. Its log:" >&2
  docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
  exit 1
fi

echo
echo "Open http://localhost:8080/"
echo "Stop it with: docker stop $CONTAINER_NAME"
