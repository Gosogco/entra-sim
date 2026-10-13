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
- **Tokens for your own APIs**: a client can ask for a token for any app registration by its
  identifier URI or appId, such as `api://orders/.default`. The token carries that API's
  delegated scopes in `scp` and the app roles the caller holds on it in `roles`, in the v1.0 or
  v2.0 format the API asks for with `api.requestedAccessTokenVersion`.
- **Microsoft Graph**: `/me`, users, groups with membership and ownership, applications, service
  principals, client secrets and certificates, federated identity credentials, app role
  assignments, delegated permission grants, directory roles, domains and organization. Served
  under both `/v1.0` and `/beta`.
- **OData**: `$filter` (comparisons, `and`/`or`/`not`, `startswith`, `endswith`, `contains`, `in`,
  and `any` lambdas), `$select`, `$orderby`, `$top`, `$skiptoken`, `$count`, and `$expand` for
  membership.
- **Permission enforcement**: each request's token is checked against the permissions Microsoft
  publishes for that endpoint, so a client missing a permission fails here the way it would
  against the real service.
- **Client authentication**: secrets, certificate assertions, and federated identity
  credentials. A federated assertion from an external issuer, such as a GitHub Actions token, is
  checked against that issuer's published keys, so the simulator then makes an outbound HTTPS
  request to the issuer.
- **Terraform**: the `hashicorp/azuread` provider works against it unmodified.
- **Browser clients**: cross-origin headers, and the fragment response mode MSAL requires.

## Running it

From a checkout, `./run.sh` builds the image, starts it, and waits until it answers:

```sh
./run.sh
```

Then open http://localhost:8080/ for the studio, a read-only view of everything the simulator
holds: users, groups, app registrations, enterprise apps, permissions, directory roles, the
tokens it has issued, and a log of every request it answered. Stop it with `docker stop entra-sim`.
The log is kept on the Docker volume `entra-sim-logs`, so it survives a stop and the next
`./run.sh`; `docker volume rm entra-sim-logs` empties it.

To run the published image instead:

```sh
mkdir -p certs
docker run --rm --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 \
  -v "$PWD/certs:/certs" \
  ghcr.io/gosogco/entra-sim:latest
```

It serves HTTPS on 8443 and plain HTTP on 8080, generates a CA and server certificate at
startup, and writes the CA to `/certs/ca.pem` so clients can be told to trust it. Both listeners
serve the studio at `/`. The image sets `ENTRA_SIM_STUDIO_DIR` to the built studio; the binary
run outside a container serves nothing at `/` unless given `--studio-dir`.

`127.0.0.1:` keeps the ports off the network. The simulator has no real authentication: the
bootstrap secret below is public, and `/__sim__/snapshot` returns every secret it holds. The
binary run outside a container binds to `127.0.0.1` by default for the same reason.

`./certs` is any directory on your machine; the container writes the CA into it, and `$PWD`
just makes the path absolute, as Docker requires. Create it before the first run, because
Docker would otherwise create it owned by root. `--user` makes the container write as you
rather than as its own unprivileged user, so a `ca.pem` left by an earlier run can be replaced
and you can read what it writes. Without `--user`, give the directory mode `777` instead.

The container is not ready the moment `docker run` returns. It generates an RSA signing key
first, which takes a few seconds. Wait for it:

```sh
until curl -sf -o /dev/null http://127.0.0.1:8080/__sim__/health; do sleep 1; done
```

**The CA changes on every restart.** Each start mints a new one, so a client holding the
previous `ca.pem` fails with "certificate signed by unknown authority". Read the file again
after a restart, or pass your own certificate with `--tls-cert` and `--tls-key` to keep one
across restarts.

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

`examples/terraform-users-app-roles/` creates five users and two applications with three app roles
each, and assigns a mix of those roles to the users.

Note that the provider forces HTTPS when fetching the metadata document, which is why the
simulator terminates TLS itself rather than expecting a proxy in front of it.

## Pointing a browser client at it

A single-page application works, including MSAL in its normal AAD protocol mode. The simulator
sends cross-origin headers, returns the authorization code in the URL fragment as `msal-browser`
requires, and serves `GET /me`.

Two MSAL settings are needed, because MSAL otherwise asks Microsoft whether the authority's host
is genuine:

```ts
knownAuthorities: ['localhost:8443'],
cloudDiscoveryMetadata: '{"tenant_discovery_endpoint":"…","api-version":"1.1","metadata":[…]}',
```

Both are unset against a real tenant. Nothing else changes.

`examples/react-spa/` is a working example with the Terraform to create its app registration, and
a Playwright test that drives the sign-in in a real browser. Its README covers `mkcert`, which the
browser needs in order to trust the generated certificate.

## More than one tenant

`--additional-tenant TENANT_ID=DOMAIN` (`ENTRA_SIM_ADDITIONAL_TENANTS`, comma-separated) serves
more tenants beside the primary one, each with its own directory holding Microsoft Graph and the
bootstrap client. The identity endpoints take the tenant from the path, by ID or domain, and
Graph from the token's `tid`. Through `common` or `organizations` the sign-in page offers every
tenant's users; a user signs in to their own tenant, and a multitenant application gets a
service principal there on consent, as in Entra. The control endpoints under `/__sim__` act on
the primary tenant, except `reset`, which resets them all.

## Pointing application code at it

For a client using the Azure SDKs, set `AZURE_AUTHORITY_HOST` to the simulator. Graph tokens are
requested as in a real tenant, with `https://graph.microsoft.com/.default` or a bare scope such as
`User.Read`; the simulator's own base URL also names Graph, because its metadata document
advertises it. Tokens for your own API are requested with its identifier URI or appId. For
anything reading OIDC discovery, point it at
`https://<host>/<tenant>/v2.0/.well-known/openid-configuration`. An API that validates v1.0 tokens
reads `https://<host>/<tenant>/.well-known/openid-configuration` instead, as it would in Entra.
That document gives the v1.0 issuer and the keys; the v1.0 sign-in endpoints themselves are not
implemented.

Interactive clients register their redirect URIs on the application as usual. The simulator's
sign-in page lists the tenant's users and the permissions being requested; choosing a user both
signs in and records consent as a real `oauth2PermissionGrant`, so the resulting token's scopes
come from the directory the way Entra derives them. Signing in starts a browser session, so a
later sign-in by the same browser skips the page once consent is in place, and `prompt=none`,
`prompt=select_account`, `prompt=consent`, `prompt=login` and `login_hint` behave as they do in
Entra. Set `--auto-sign-in-user` to skip the page in tests that cannot drive a browser.

## Conditional access

Policies are managed at `/identity/conditionalAccess/policies`, so `azuread_conditional_access_policy`
works, and enabled ones are enforced when tokens are issued; report-only ones are logged. A
policy can match users, groups, directory roles, guests, applications and client app types,
with their exclusions. `block` refuses the sign-in with `AADSTS53003`. `mfa` adds a step to the
sign-in page, and the token's `amr` then includes `mfa`; a grant with no page, such as the
password grant or a refresh, answers `interaction_required` with `AADSTS50076` instead. Device
requirements cannot be met and refuse the sign-in with Entra's codes. The simulator knows
nothing of locations, platforms, devices or risk, so a policy limited by one of those applies only
when it covers everything, and policies for workload identities are not enforced.

## Privileged Identity Management

Directory roles can be made eligible and activated through
`/roleManagement/directory/roleEligibilityScheduleRequests` and
`roleAssignmentScheduleRequests`, so `azuread_directory_role_eligibility_schedule_request` works.
Every request completes at once, with no approval step, and the schedule it creates has the
request's ID. An eligible user activates a role with a `selfActivate` request made with their own
token; the role then counts in `wids`, group claims, conditional access and the role's members
until the requested time runs out, eight hours when none is given. The schedules are listed at
`roleEligibilitySchedules` and `roleAssignmentSchedules`.

## Administrative units

Units are managed at `/directory/administrativeUnits`, with `members` and `scopedRoleMembers`,
so `azuread_administrative_unit`, `azuread_administrative_unit_member` and
`azuread_administrative_unit_role_member` work. Only the roles Microsoft lists as assignable over a
unit can be scoped to one. A delegated call that changes or deletes another user needs the
signed-in user to be a Global Administrator or User Administrator, or a User Administrator over a
unit the user is a direct member of, through a scoped role membership or a PIM schedule; otherwise
Graph answers `403`. Membership through a group in the unit does not count, as in Entra.

## Driving it from a test suite

State is held in memory. Endpoints under `/__sim__` inspect and manage it, outside any Graph
path:

| | |
|---|---|
| `GET /__sim__/health` | liveness and the tenant it serves |
| `POST /__sim__/reset` | return the directory to its seeded state |
| `GET /__sim__/snapshot` | dump everything, including secrets |
| `POST /__sim__/snapshot` | replace everything |
| `GET /__sim__/tokens` | the tokens issued, and the refresh tokens and codes still redeemable, with their expiry |
| `GET /__sim__/logs` | the log of requests and events, newest first, a page at a time (`before`, `after`, `limit`) |

The token log holds metadata, not tokens, and shows only a prefix of each refresh token and code.
It keeps the last 1000 issued and empties on reset. The studio at `/` shows all of this in a
browser.

The request log is different. Given `--log-dir` (`ENTRA_SIM_LOG_DIR`, which the image sets to
`/logs`), the simulator appends to `entra-sim.jsonl` there: every request with its headers and
both bodies, secrets and tokens included, and every event it logs, each tied to the request it
happened during. Nothing trims the file and a reset leaves it alone. The studio's own reads of
`/__sim__/*` and of its files are left out, so polling does not bury everything else.

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

- Writes are immediately readable; there is no eventual consistency to trip over.
- Entitlement management and synchronization jobs are out of scope.
- A delegated call is checked against the signed-in user's directory roles only when it changes
  or deletes another user, and only User Administrator and Global Administrator count. Dynamic
  and restricted management administrative units behave as ordinary ones.
- PIM requests never wait for approval, and PIM for groups and Azure resources is not
  present.

## Building

```sh
cargo test
cargo clippy --all-targets -- -D warnings
docker build -t entra-sim .
```

## License

MIT. See [LICENSE](LICENSE).
