# Sourced by the examples' run.sh scripts, not run on its own.
#
# Makes sure a simulator is serving 127.0.0.1:8080 (HTTP) and 127.0.0.1:8443 (HTTPS), starting
# one in a container if none is, and exports SIM_CA: a copy of its CA certificate, which the
# setup script needs to talk to it over HTTPS.
#
# A simulator that is already running in a container is reused rather than replaced, so both
# examples can run side by side against the same directory.

IMAGE="${ENTRA_SIM_IMAGE:-ghcr.io/gosogco/entra-sim:0.4.0}"
CONTAINER_NAME=entra-sim-examples

sim_healthy() {
  curl --silent --fail --output /dev/null http://127.0.0.1:8080/__sim__/health
}

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start it (for example: colima start) and try again." >&2
  exit 1
fi

container=$(docker ps --quiet --filter publish=8443)
if [ -n "$container" ]; then
  echo "Using the simulator already running in container" \
    "$(docker ps --filter "id=$container" --format '{{.Names}} ({{.Image}})')."
elif sim_healthy; then
  # Most likely `cargo run`. Its CA is wherever it was told to write it, which this script
  # cannot know, so say so rather than guess.
  echo "A simulator outside Docker is serving 127.0.0.1:8080. Stop it, or run the example by" \
    "hand as its README describes." >&2
  exit 1
else
  echo "Starting $IMAGE as container $CONTAINER_NAME."
  # Ports on 127.0.0.1 only: the simulator has no real authentication, so it stays off the
  # network. example.test, because the example's user is alice@example.test.
  docker run --detach --rm --name "$CONTAINER_NAME" \
    -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 \
    -e ENTRA_SIM_TENANT_DOMAIN=example.test \
    "$IMAGE" >/dev/null
  container=$CONTAINER_NAME
  echo "Stop it with: docker stop $CONTAINER_NAME"
fi

# Startup generates an RSA key, which takes a few seconds.
for _ in $(seq 1 60); do
  sim_healthy && break
  sleep 1
done
if ! sim_healthy; then
  echo "The simulator did not become healthy. Its log:" >&2
  docker logs "$container" 2>&1 | tail -20 >&2
  exit 1
fi

# Copied out of the container rather than mounted, so this works from any directory: Colima
# only shares the home directory with containers.
SIM_CA_DIR=$(mktemp -d)
trap 'rm -rf "$SIM_CA_DIR"' EXIT
docker cp "$container:/certs/ca.pem" "$SIM_CA_DIR/ca.pem" >/dev/null
export SIM_CA="$SIM_CA_DIR/ca.pem"
