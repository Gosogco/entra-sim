"""The orders API: validates the bearer token on every request and decides whether to allow it.

Configuration comes from the environment, which run.sh fills from ../.env. REQUESTS_CA_BUNDLE
and SSL_CERT_FILE must name the simulator's CA, because both the key download and MSAL use
HTTPS.
"""

import os
import ssl

import jwt
import msal
import requests
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

TENANT_ID = os.environ["TENANT_ID"]
AUTHORITY = os.environ["AUTHORITY"]
API_CLIENT_ID = os.environ["API_CLIENT_ID"]
GRAPH_BASE = os.environ["GRAPH_BASE"]
CERTS = os.path.join(os.path.dirname(__file__), "..", "certs")

# A v2.0 access token names the simulator's own address as its issuer, and the API's client ID
# as its audience.
ISSUER = f"{AUTHORITY}/v2.0"
jwks = jwt.PyJWKClient(
    f"{AUTHORITY}/discovery/v2.0/keys",
    ssl_context=ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"]),
)

# The backend's own identity, for the on-behalf-of call to Graph. `public_certificate` makes MSAL
# name the certificate with x5t#S256 and sign with PS256.
with open(os.path.join(CERTS, "api.pem")) as certificate, open(
    os.path.join(CERTS, "api-key.pem")
) as key:
    confidential_client = msal.ConfidentialClientApplication(
        API_CLIENT_ID,
        authority=AUTHORITY,
        client_credential={"private_key": key.read(), "public_certificate": certificate.read()},
        # MSAL would otherwise ask Microsoft whether the simulator's host is a genuine authority.
        instance_discovery=False,
    )

app = FastAPI()


class Denied(Exception):
    def __init__(self, status: int, reason: str, claims: dict | None = None):
        self.status = status
        self.reason = reason
        self.claims = claims or {}


@app.exception_handler(Denied)
def denied(_: Request, error: Denied) -> JSONResponse:
    return JSONResponse(
        status_code=error.status,
        content={"allowed": False, "reason": error.reason, **summary(error.claims)},
    )


def summary(claims: dict) -> dict:
    """What the response tells the caller about its token, so a refusal explains itself."""
    return {"roles": claims.get("roles", []), "scp": claims.get("scp")}


def claims(request: Request) -> dict:
    """The validated claims of the request's bearer token. Any fault is a 401."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise Denied(401, "No bearer token.")
    token = header.removeprefix("Bearer ")
    try:
        key = jwks.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=API_CLIENT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWTError as error:
        raise Denied(401, f"The token is not valid: {error}.")


def require_role(role: str):
    def check(token: dict = Depends(claims)) -> dict:
        if role not in token.get("roles", []):
            raise Denied(403, f"The token does not hold the {role} role.", token)
        return token

    return check


@app.get("/api/orders")
def list_orders(token: dict = Depends(require_role("Orders.Read"))):
    return {"allowed": True, "orders": [{"id": 1, "item": "Widget"}], **summary(token)}


@app.post("/api/orders")
def create_order(token: dict = Depends(require_role("Orders.Write"))):
    return {"allowed": True, "created": {"id": 2, "item": "Gadget"}, **summary(token)}


@app.get("/api/me")
def me(request: Request, token: dict = Depends(claims)):
    # An app-only token has no scp, and there is no user to call Graph for.
    if "access_as_user" not in token.get("scp", "").split():
        raise Denied(403, "Only a user's token with the access_as_user scope may call this.", token)

    assertion = request.headers["Authorization"].removeprefix("Bearer ")
    result = confidential_client.acquire_token_on_behalf_of(assertion, ["User.Read"])
    if "access_token" not in result:
        # The backend's own credential or consent is at fault, not the caller's token.
        return JSONResponse(
            status_code=502,
            content={
                "allowed": True,
                "reason": f"The on-behalf-of call failed: {result.get('error_description')}",
                **summary(token),
            },
        )
    graph = requests.get(
        f"{GRAPH_BASE}/v1.0/me",
        headers={"Authorization": f"Bearer {result['access_token']}"},
        timeout=10,
    )
    graph.raise_for_status()
    return {"allowed": True, "displayName": graph.json()["displayName"], **summary(token)}
