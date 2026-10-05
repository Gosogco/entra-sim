# entra-sim

A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API, in Rust.

It exists so that code and infrastructure depending on Entra can be tested locally and in CI,
without a real tenant, credentials, or a shared directory to pollute. The aim is that an existing
client — application code or a Terraform configuration — can be pointed at it by changing
configuration only.

## What it does

- **OAuth 2.0 and OpenID Connect**: the client credentials grant, the authorization code grant
  with PKCE, and refresh tokens. Real RS256-signed JWTs, OIDC discovery, and a JWKS endpoint, so
  clients validate tokens exactly as they would in production.
- **Microsoft Graph**: users, groups with membership and ownership, applications, service
  principals, client secrets and certificates, federated identity credentials, app role
  assignments, delegated permission grants, directory roles, domains and organization. Served
  under both `/v1.0` and `/beta`.
- **OData**: `$filter` (comparisons, `and`/`or`/`not`, `startswith`, `endswith`, `contains`, `in`,
  and `any` lambdas), `$select`, `$orderby`, `$top`, `$skiptoken`, `$count`, and `$expand` for
  membership.
- **Permission enforcement**: each request's token is checked against the permissions Microsoft
  publishes for that endpoint, so a client missing a permission fails here the way it would
  against the real service.
- **Terraform**: the `hashicorp/azuread` provider works against it unmodified.

## Running it

```sh
docker run --rm -p 8080:8080 -p 8443:8443 -v "$PWD/certs:/certs" \
  ghcr.io/gosogco/entra-sim:latest
```

It serves HTTPS on 8443 and plain HTTP on 8080, generates a CA and server certificate at
startup, and writes the CA to `/certs/ca.pem` so clients can be told to trust it.

A bootstrap application is registered so there is something to authenticate as from a cold
start:

| | |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000001` |
| Client ID | `11111111-1111-1111-1111-111111111111` |
| Client secret | `entra-sim-bootstrap-secret` |

All three are configurable; see `--help`.

```sh
curl --cacert certs/ca.pem \
  -d grant_type=client_credentials \
  -d client_id=11111111-1111-1111-1111-111111111111 \
  -d client_secret=entra-sim-bootstrap-secret \
  -d 'scope=https://localhost:8443/.default' \
  https://localhost:8443/00000000-0000-0000-0000-000000000001/oauth2/v2.0/token
```

## Pointing Terraform at it

The `azuread` provider offers exactly one hook for this: `metadata_host`. The provider fetches
`/metadata/endpoints` from that host and reconfigures every endpoint from the result, so no
provider or configuration change is needed beyond setting it.

```sh
export ARM_METADATA_HOSTNAME=localhost:8443
export SSL_CERT_FILE=$PWD/certs/ca.pem          # trust the generated CA
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000001
export ARM_CLIENT_ID=11111111-1111-1111-1111-111111111111
export ARM_CLIENT_SECRET=entra-sim-bootstrap-secret

terraform apply
```

`terraform/accept/` holds a worked example that creates a user, a group, a membership, an app
registration with API permissions, a service principal, a secret and an app role assignment. CI
applies it, checks that the following plan is empty, and destroys it.

Note that the provider forces HTTPS when fetching the metadata document, which is why the
simulator terminates TLS itself rather than expecting a proxy in front of it.

## Pointing application code at it

For a client using the Azure SDKs, set `AZURE_AUTHORITY_HOST` to the simulator and request tokens
for its base URL as the resource. For anything reading OIDC discovery, point it at
`https://<host>/<tenant>/v2.0/.well-known/openid-configuration`.

Interactive clients register their redirect URIs on the application as usual. The simulator's
sign-in page lists the tenant's users and the permissions being requested; choosing a user both
signs in and records consent as a real `oauth2PermissionGrant`, so the resulting token's scopes
come from the directory the way Entra derives them. Set `--auto-sign-in-user` to skip the page
in tests that cannot drive a browser.

## Driving it from a test suite

State is held in memory. Three endpoints under `/__sim__` manage it, outside any Graph path:

| | |
|---|---|
| `GET /__sim__/health` | liveness and the tenant it serves |
| `POST /__sim__/reset` | return the directory to its seeded state |
| `GET /__sim__/snapshot` | dump everything, including secrets |
| `POST /__sim__/snapshot` | replace everything |

`--seed <file>` loads a snapshot at startup and on every reset, so a suite can reset between
cases and land back on its fixtures.

## Fidelity

Three things are generated from Microsoft's own published documentation rather than written by
hand, because inventing them would break real configurations that name them:

| File | Source |
|---|---|
| `src/graph/graph_permissions.json` | Graph's app roles and delegated scopes, with their real identifiers |
| `src/graph/directory_roles.json` | the built-in directory role templates |
| `src/auth/permission_requirements.json` | the permissions required per endpoint |

`scripts/generate-*.py` regenerate them; CI reports drift against upstream as a warning.

`contract/envcheck` runs the `azuread` provider's own discovery and client-credentials code
against a running simulator, at the SDK version the provider pins, so a change upstream that
breaks the simulator surfaces as a failing check rather than a confusing provider error.

## What it does not do

- No `$batch`, no delta queries.
- One tenant per process. `common`, `organizations` and `consumers` resolve to it.
- Writes are immediately readable; there is no eventual consistency to trip over.
- Conditional access, entitlement management, administrative units, PIM and synchronization jobs
  are all out of scope.
- `client_assertion` (`private_key_jwt`) client authentication is not implemented; secrets and
  PKCE are.

## Building

```sh
cargo test
cargo clippy --all-targets -- -D warnings
docker build -t entra-sim .
```
