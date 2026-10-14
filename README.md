# entra-sim

A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API, in Rust.

It lets code and infrastructure that depend on Entra run locally and in CI without a real
tenant. An existing client, such as application code, an Azure SDK, MSAL in a browser or a
Terraform configuration, is pointed at it by changing configuration only.

The full documentation is in [`docs/`](docs/index.html). Open `docs/index.html` in a browser.

## Capabilities

- **OAuth 2.0 and OpenID Connect:** client credentials, authorization code with PKCE, refresh
  tokens, on-behalf-of, device code and the password grant. OIDC discovery (v2.0 and v1.0),
  JWKS, UserInfo, logout, browser sessions and `prompt`.
- **Client authentication:** secrets, certificate assertions, and federated identity
  credentials checked against the external issuer's keys.
- **Tokens:** RS256-signed JWTs for Graph and for any registered API, in the v1.0 or v2.0 format
  the API asks for. `scp`, `roles`, group claims, `wids` and optional claims come from the
  directory.
- **Policy:** `appRoleAssignmentRequired`, conditional access (block, MFA, device controls), and
  more than one tenant.
- **Microsoft Graph** under `/v1.0` and `/beta`: users, groups, applications, service principals,
  credentials, app role assignments, delegated permission grants, directory roles, PIM for
  directory roles, administrative units, conditional access policies, organization and domains.
- **Graph protocol:** OData `$filter`, `$select`, `$orderby`, `$top`, `$skiptoken`, `$count` and
  `$expand`; JSON batching; delta queries.
- **Permission enforcement:** each Graph request is checked against the permissions Microsoft
  publishes for that endpoint.
- **Terraform:** the `hashicorp/azuread` provider works unmodified.
- **Test control:** reset, snapshots, seed files, a token list and a request log under
  `/__sim__`, and a browser studio at `/`.

[Limits](docs/limits.html) lists what is not implemented and where it differs from Entra.

## Quick start

From a checkout, `./run.sh` builds the image, starts it and opens the studio at
http://localhost:8080/. To run the published image:

```sh
mkdir -p certs
docker run --rm --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 \
  -v "$PWD/certs:/certs" \
  ghcr.io/gosogco/entra-sim:latest

until curl -sf -o /dev/null http://127.0.0.1:8080/__sim__/health; do sleep 1; done
```

HTTPS is on 8443 and HTTP on 8080. The CA is written to `certs/ca.pem` and changes on every
restart. A bootstrap client exists from the start:

| | |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000001` |
| Client ID | `11111111-1111-1111-1111-111111111111` |
| Client secret | `entra-sim-bootstrap-secret` |

```sh
curl --cacert certs/ca.pem \
  -d grant_type=client_credentials \
  -d client_id=11111111-1111-1111-1111-111111111111 \
  -d client_secret=entra-sim-bootstrap-secret \
  -d 'scope=https://graph.microsoft.com/.default' \
  https://localhost:8443/00000000-0000-0000-0000-000000000001/oauth2/v2.0/token
```

The simulator has no real authentication and its snapshot holds every secret, so keep its ports
on `127.0.0.1`. Every setting is listed by `--help` and in
[Configuration](docs/configuration.html).

## Connecting clients

| Client | Settings |
|---|---|
| Terraform `azuread` | `ARM_METADATA_HOSTNAME=localhost:8443`, `SSL_CERT_FILE=$PWD/certs/ca.pem`, and the bootstrap credentials in `ARM_TENANT_ID`, `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET` |
| Azure SDKs | `AZURE_AUTHORITY_HOST=https://localhost:8443/`, and the CA in the runtime's trust setting |
| MSAL in a browser | `knownAuthorities` and an inline `cloudDiscoveryMetadata`, and a certificate the browser trusts |
| Your own API | The discovery document at `https://localhost:8443/{tenant}/v2.0/.well-known/openid-configuration`, or the one without `/v2.0` for v1.0 tokens |

[Connecting clients](docs/clients.html) has the details.

## Examples

- [`examples/react-spa/`](examples/react-spa/): a React app signing in with MSAL and calling
  Graph. The same build runs against the simulator and a real tenant, with a Playwright suite.
- [`examples/terraform-users-app-roles/`](examples/terraform-users-app-roles/): users and two
  APIs with app roles, and a script that shows the roles in a user's token.
- [`tests/terraform/`](tests/terraform/): the Terraform acceptance fixture CI applies, checks
  for an empty plan, and destroys.

## Testing against it

`POST /__sim__/reset` returns the directory to its starting state, `GET /__sim__/snapshot` saves
it, and `--seed` loads a saved snapshot at startup and on every reset.
`--auto-sign-in-user` signs a user in without the sign-in page. See
[Testing and the studio](docs/testing.html).

## Building

```sh
cargo test
cargo clippy --all-targets -- -D warnings
docker build -t entra-sim .
```

## License

MIT. See [LICENSE](LICENSE).
