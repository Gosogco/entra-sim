#!/usr/bin/env bash
# Create the directory objects this example needs, and print its .env to stdout.
#
# terraform/ does the same thing properly, and is what you should read to see how this would be
# done against a real tenant. This script exists so the example can be brought up without
# Terraform installed, and so CI has one command to call.
#
#   CA=certs/ca.pem scripts/setup.sh > .env
set -euo pipefail

SIM="${SIM:-https://localhost:8443}"
TENANT="${TENANT:-00000000-0000-0000-0000-000000000001}"
CLIENT="${CLIENT:-11111111-1111-1111-1111-111111111111}"
SECRET="${SECRET:-entra-sim-bootstrap-secret}"
CA="${CA:-}"
# The trailing slash matches what the azuread provider requires and what the app sends.
REDIRECT="${REDIRECT:-http://localhost:5173/}"
UPN="${UPN:-alice@example.test}"
DISPLAY_NAME="${DISPLAY_NAME:-Alice Example}"

curl_args=(--silent --show-error --fail)
if [ -n "$CA" ]; then
  curl_args+=(--cacert "$CA")
fi

token=$(curl "${curl_args[@]}" \
  --data grant_type=client_credentials \
  --data "client_id=$CLIENT" \
  --data "client_secret=$SECRET" \
  --data "scope=$SIM/.default" \
  "$SIM/$TENANT/oauth2/v2.0/token" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

graph() {
  local method=$1 path=$2 body=${3:-}
  local args=("${curl_args[@]}" --request "$method" --header "Authorization: Bearer $token")
  if [ -n "$body" ]; then
    args+=(--header 'Content-Type: application/json' --data "$body")
  fi
  curl "${args[@]}" "$SIM$path"
}

field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# Start from a known directory, so repeated runs do not accumulate objects.
curl "${curl_args[@]}" --request POST "$SIM/__sim__/reset" >/dev/null

# The redirect URI goes under `spa`, which is the platform a browser client registers against.
application=$(graph POST /v1.0/applications "$(
  python3 - "$REDIRECT" <<'PY'
import json, sys
print(json.dumps({
    "displayName": "entra-sim React example",
    "signInAudience": "AzureADMyOrg",
    "spa": {"redirectUris": [sys.argv[1]]},
}))
PY
)")
client_id=$(printf '%s' "$application" | field appId)

graph POST /v1.0/servicePrincipals "{\"appId\":\"$client_id\"}" >/dev/null

graph POST /v1.0/users "$(
  python3 - "$UPN" "$DISPLAY_NAME" <<'PY'
import json, sys
upn, name = sys.argv[1], sys.argv[2]
print(json.dumps({
    "displayName": name,
    "userPrincipalName": upn,
    "mailNickname": upn.split("@")[0],
    "accountEnabled": True,
    "passwordProfile": {"password": "Sup3rSecret!Passw0rd"},
}))
PY
)" >/dev/null

# The instance-discovery answer MSAL would otherwise ask Microsoft for.
host="${SIM#https://}"
discovery=$(
  python3 - "$SIM" "$TENANT" "$host" <<'PY'
import json, sys
sim, tenant, host = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "tenant_discovery_endpoint":
        f"{sim}/{tenant}/v2.0/.well-known/openid-configuration",
    "api-version": "1.1",
    "metadata": [{
        "preferred_network": host,
        "preferred_cache": host,
        "aliases": [host],
    }],
}, separators=(",", ":")))
PY
)

cat <<ENV
VITE_CLIENT_ID=$client_id
VITE_AUTHORITY=$SIM/$TENANT
VITE_GRAPH_BASE=$SIM
VITE_SCOPES=User.Read
VITE_CLOUD_DISCOVERY_METADATA=$discovery
ENV
