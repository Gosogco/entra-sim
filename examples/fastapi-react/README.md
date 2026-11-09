# FastAPI and React example

A React site signs a user in with MSAL and calls a FastAPI backend with the access token. The
backend validates the token and allows or denies each call by the token's roles. Two Python
daemons call the same backend with app-only tokens. Terraform creates the users, roles and
applications, so both allowed and denied calls are shown.

The backend and the daemons authenticate to the simulator with certificates, through MSAL Python.

## What it demonstrates

| | |
|---|---|
| Sign-in | `msal-browser` in AAD protocol mode, authorization code with PKCE, through the simulator's user picker |
| Token validation | The backend checks the signature against the simulator's published keys, plus `iss`, `aud` and `exp`, with PyJWT |
| Authorization | App roles `Orders.Read` and `Orders.Write`, held directly, through a group, or not at all |
| On-behalf-of | The backend exchanges the user's token for a Graph token with MSAL Python and a certificate (`x5t#S256`, PS256), then calls `GET /me` |
| Client credentials | Two daemons get app-only tokens with MSAL Python and a certificate (`x5t`, RS256) |

## Quick start

Needs Docker, Python 3, Node and Terraform.

```sh
./run.sh
```

It starts the simulator in Docker if it isn't running, resets its directory, generates three
certificates in `certs/`, applies `terraform/`, writes `.env`, starts the backend on
http://127.0.0.1:8000, runs both daemons once, and starts the site on http://localhost:5174/.
The browser has to accept the simulator's certificate once per simulator start; the script says
how. Stop everything with Ctrl-C, and the simulator with `docker stop entra-sim-examples`.

The certificate paths need entra-sim 1.1.0 or later. 1.0.2 rejected the assertions MSAL Python
builds, because it required unpadded thumbprints and an `nbf` claim. `run.sh` pulls `latest`; if a
simulator container from an older image is already running, stop it first.

## Who may do what

| User or application | Holds |
|---|---|
| alice | `Orders.Read` and `Orders.Write`, through the group `Order managers` |
| bob | `Orders.Read`, assigned directly |
| carol | Nothing |
| `entra-sim FastAPI example reporter` | `Orders.Read`, as an application role |
| `entra-sim FastAPI example intruder` | Nothing. The API does not require assignment, so it still gets a token, without roles, and the backend refuses it |

| Endpoint | Allowed when |
|---|---|
| `GET /api/orders` | The token holds `Orders.Read` |
| `POST /api/orders` | The token holds `Orders.Write` |
| `GET /api/me` | The token is a user's token with the `access_as_user` scope |

A missing or invalid token is a `401`: no token, a bad signature, an expired token, or a token for
another audience such as Graph. A valid token without the role or scope is a `403`. Every
response says why, and lists the token's `roles` and `scp`.

## Expected results

| Caller | `GET /api/orders` | `POST /api/orders` | `GET /api/me` |
|---|---|---|---|
| alice | 200 | 200 | 200, `Alice Anders` |
| bob | 200 | 403 | 200, `Bob Brown` |
| carol | 403 | 403 | 200, `Carol Chen` |
| No token | 401 | 401 | 401 |
| A Graph token | 401 | 401 | 401 |
| reporter daemon | 200 | 403 | 403 |
| intruder daemon | 403 | 403 | 403 |

## The end-to-end test

`tests/test_example.py` checks every row of the table above against the running example, the
daemons included. With `run.sh` running, in another terminal:

```sh
docker cp entra-sim-examples:/certs/ca.pem /tmp/entra-sim-ca.pem
REQUESTS_CA_BUNDLE=/tmp/entra-sim-ca.pem .venv/bin/pytest tests
```

Use the container name `run.sh` printed, `entra-sim` if the root `run.sh` started it. Users
sign in by posting the simulator's sign-in form directly, so the test needs no browser. CI runs it
in the `Python example` job.

## Files

| File | What it is |
|---|---|
| `run.sh` | Everything above in one step |
| `terraform/main.tf` | The applications, roles, scope, users, group, assignments, consent grants and certificates |
| `backend/app.py` | The FastAPI backend |
| `daemon/daemon.py` | The daemon, `python daemon/daemon.py reporter` or `intruder` |
| `frontend/` | The React site. Vite proxies `/api` to the backend, so the backend needs no CORS |
| `tests/test_example.py` | The end-to-end test |
| `requirements.txt` | The backend's, the daemons' and the test's Python packages |
