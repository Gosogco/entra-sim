"""A daemon that calls the orders API with an app-only token.

    python daemon/daemon.py reporter
    python daemon/daemon.py intruder

The reporter holds Orders.Read, the intruder holds no role. Both authenticate with a certificate.
Configuration comes from the environment, which run.sh fills from ../.env. REQUESTS_CA_BUNDLE must
name the simulator's CA.
"""

import os
import sys

import msal
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes

BACKEND = os.environ.get("BACKEND", "http://127.0.0.1:8000")
CERTS = os.path.join(os.path.dirname(__file__), "..", "certs")

name = sys.argv[1] if len(sys.argv) > 1 else ""
if name not in ("reporter", "intruder"):
    sys.exit("usage: daemon.py reporter|intruder")

with open(os.path.join(CERTS, f"{name}.pem"), "rb") as file:
    certificate = x509.load_pem_x509_certificate(file.read())
with open(os.path.join(CERTS, f"{name}-key.pem")) as file:
    key = file.read()

# `thumbprint` makes MSAL name the certificate with the older SHA-1 x5t and sign with RS256.
app = msal.ConfidentialClientApplication(
    os.environ[f"{name.upper()}_CLIENT_ID"],
    authority=os.environ["AUTHORITY"],
    client_credential={
        "private_key": key,
        "thumbprint": certificate.fingerprint(hashes.SHA1()).hex(),
    },
    # MSAL would otherwise ask Microsoft whether the simulator's host is a genuine authority.
    instance_discovery=False,
)
result = app.acquire_token_for_client(["api://orders-api/.default"])
if "access_token" not in result:
    print(f"{name}: no token: {result.get('error_description')}")
    sys.exit(1)

headers = {"Authorization": f"Bearer {result['access_token']}"}
for method, path in [("GET", "/api/orders"), ("POST", "/api/orders"), ("GET", "/api/me")]:
    response = requests.request(method, BACKEND + path, headers=headers, timeout=10)
    body = response.json()
    print(f"{name}: {method} {path}: {response.status_code} {body.get('reason', 'allowed')}")
