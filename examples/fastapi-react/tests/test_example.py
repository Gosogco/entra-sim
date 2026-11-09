"""Checks every row of the README's expected results against the running example.

Needs what run.sh sets up: the simulator, terraform/ applied, ../.env written, and the backend on
127.0.0.1:8000. REQUESTS_CA_BUNDLE must name the simulator's CA, for the daemons.

    .venv/bin/pytest tests

Users sign in by posting the simulator's sign-in form directly, which stands in for the browser.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import urllib.parse

import pytest
import requests

ROOT = os.path.join(os.path.dirname(__file__), "..")
SIM = "http://127.0.0.1:8080"
BACKEND = "http://127.0.0.1:8000"
REDIRECT = "http://localhost:5174/"
CALLS = [("GET", "/api/orders"), ("POST", "/api/orders"), ("GET", "/api/me")]

with open(os.path.join(ROOT, ".env")) as file:
    ENV = dict(line.split("=", 1) for line in file.read().splitlines())
USER_IDS = json.loads(
    subprocess.check_output(
        ["terraform", f"-chdir={ROOT}/terraform", "output", "-json", "user_ids"]
    )
)


def user_token(user: str, scope: str = "api://orders-api/access_as_user") -> str:
    """Sign a user in to the site's application and redeem the code, with PKCE as MSAL does."""
    tenant, client_id = ENV["TENANT_ID"], ENV["VITE_CLIENT_ID"]
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    redirect = requests.post(
        f"{SIM}/{tenant}/oauth2/v2.0/authorize",
        allow_redirects=False,
        data={
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "scope": f"openid {scope}",
            "user_id": USER_IDS[user],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    query = urllib.parse.urlsplit(redirect.headers["location"]).query
    response = requests.post(
        f"{SIM}/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": urllib.parse.parse_qs(query)["code"][0],
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        },
    )
    response.raise_for_status()
    return response.json()["access_token"]


def statuses(token: str | None) -> list[int]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return [
        requests.request(method, BACKEND + path, headers=headers, timeout=30).status_code
        for method, path in CALLS
    ]


@pytest.mark.parametrize(
    "user, expected",
    [
        ("alice", [200, 200, 200]),
        ("bob", [200, 403, 200]),
        ("carol", [403, 403, 200]),
    ],
)
def test_users(user, expected):
    assert statuses(user_token(user)) == expected


def test_me_calls_graph_on_behalf_of_the_user():
    response = requests.get(
        f"{BACKEND}/api/me", headers={"Authorization": f"Bearer {user_token('bob')}"}, timeout=30
    )
    assert response.json()["displayName"] == "Bob Brown"


def test_no_token():
    assert statuses(None) == [401, 401, 401]


def test_a_graph_token_is_for_another_audience():
    assert statuses(user_token("alice", "User.Read")) == [401, 401, 401]


@pytest.mark.parametrize(
    "daemon, expected",
    [
        ("reporter", [200, 403, 403]),
        ("intruder", [403, 403, 403]),
    ],
)
def test_daemons(daemon, expected):
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "daemon", "daemon.py"), daemon],
        capture_output=True,
        text=True,
        env={**os.environ, **ENV},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Each line is "<daemon>: <method> <path>: <status> <reason>".
    assert [int(line.split(": ")[2].split()[0]) for line in result.stdout.splitlines()] == expected
