#!/usr/bin/env bash
# Sign one of the example's users in to Orders or Inventory and print the access token's claims.
#
#   ./token.sh bob orders
#
# Needs the simulator that run.sh started, and main.tf applied. Uses the plain HTTP listener on
# 8080, so no CA certificate is needed.
set -euo pipefail
cd "$(dirname "$0")"

usage="usage: ./token.sh <alice|bob|carol|dave|erin> <orders|inventory>"
user=${1:?$usage}
api=${2:?$usage}

SIM=http://127.0.0.1:8080
TENANT=00000000-0000-0000-0000-000000000001
REDIRECT=http://localhost/callback

client_id=$(terraform output -raw viewer_client_id)
user_id=$(terraform output -json user_ids | python3 -c "import json, sys; print(json.load(sys.stdin)['$user'])")

# Choosing a user on the simulator's sign-in page is a form POST. Sending it with curl stands in
# for the browser. The answer is a redirect to the client, carrying the authorization code.
location=$(curl --silent --show-error --output /dev/null --write-out '%{redirect_url}' \
  --data-urlencode "client_id=$client_id" \
  --data-urlencode "response_type=code" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "scope=openid api://$api/.default" \
  --data-urlencode "user_id=$user_id" \
  "$SIM/$TENANT/oauth2/v2.0/authorize")
code=$(python3 -c "import sys, urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query)['code'][0])" "$location")

curl --silent --show-error \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$client_id" \
  --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  "$SIM/$TENANT/oauth2/v2.0/token" |
  python3 -c '
import base64, json, sys
token = json.load(sys.stdin)["access_token"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
'
