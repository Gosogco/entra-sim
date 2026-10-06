# entra-sim explained

This document explains the simulator in full. It has four parts:

1. **Why the code is large.** An account of the size.
2. **How Entra works.** The background you need to read the rest.
3. **What the code does.** Each part, and the reason for it.
4. **How to test with the container.** Recipes you can copy.

---

## Part 1. Why the code is large

The code is larger than you expected. This section explains why.

### The counts

| Part | Lines |
|---|---|
| Rust source | 9051 |
| Tests | 4738 |
| Generated JSON data | 18241 |
| Python generator scripts | 626 |
| React example, TypeScript | 509 |

The JSON data is over half of the repository. No person wrote it. Three scripts
make it from Microsoft documentation. Part 3 explains this data.

### The four reasons

**Reason 1. You asked for an exact API.** Your prompt said the simulator must
have "the exact same API as entra/graph". You also said a client must work
after a config change only. These two requirements remove all shortcuts.

A simple mock returns fixed answers. An exact API must do all of this:

- Return the same error codes.
- Return the same HTTP status codes.
- Keep every property a client writes.
- Refuse the same requests.
- Sign real tokens.

**Reason 2. Terraform needs real identifiers.** Terraform configurations name
Microsoft Graph permissions by GUID. Here is a normal example:

```hcl
resource_access {
  id   = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"  # Application.ReadWrite.All
  type = "Role"
}
```

The simulator must know that GUID. Invented GUIDs break real configurations.
There are 1504 Graph permissions and 136 directory roles. This is the 18199
lines of JSON.

**Reason 3. OAuth has many flows.** You chose three grant types. Each flow
needs its own code:

- Client credentials. For machines.
- Authorization code with PKCE. For users with a browser.
- Refresh token. To replace an expired access token.

**Reason 4. Graph uses OData.** Clients send queries like this:

```
GET /v1.0/users?$filter=startswith(displayName,'A')&$select=id,mail&$top=10
```

The simulator must parse `$filter`. A parser needs a lexer, a parser and an
evaluator. This is about 700 lines.

### What you can remove

You can make the simulator much smaller. Each option has a cost:

| Remove | Saves | Cost |
|---|---|---|
| The permission catalogues | 18241 lines | Terraform configurations with real GUIDs stop working |
| Permission enforcement | ~400 lines | The simulator cannot find missing-permission faults |
| The interactive flow | ~900 lines | You cannot test browser clients |
| The OData filter engine | ~700 lines | `$filter` stops working, so most list calls fail |
| The tests | 4738 lines | You lose all proof that the simulator is correct |

---

## Part 2. How Microsoft Entra works

Read this part if Entra is new to you. Skip it if you know Entra well.

### The tenant

A **tenant** is one directory. It holds users, groups and applications. Each
tenant has a GUID and at least one domain name.

The simulator serves one tenant. Its default GUID is
`00000000-0000-0000-0000-000000000001`. Its default domain is
`entra-sim.test`.

Entra accepts three alias names for a tenant: `common`, `organizations` and
`consumers`. The simulator accepts all three. It always puts the real GUID in
the tokens it makes.

### Users and groups

A **user** is a person. The main property is the `userPrincipalName`, for
example `alice@entra-sim.test`. Entra compares this name without case.

A **group** holds members. Members can be users, other groups or service
principals. A group inside a group is a **nested group**.

Entra does not put members in the group object. You read them from a separate
path:

```
GET /v1.0/groups/{id}              -> the group, with no members
GET /v1.0/groups/{id}/members      -> the direct members
GET /v1.0/groups/{id}/transitiveMembers  -> members of nested groups also
```

To add a member, you POST a reference:

```
POST /v1.0/groups/{id}/members/$ref
{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/<member-id>"}
```

The URL in `@odata.id` always names the real Graph host. The service reads
only the last part of the path.

### Application and service principal

This is the part people find most difficult. An app in Entra is **two
objects**:

| Object | What it is |
|---|---|
| **Application** | The global definition. It holds the secrets, the redirect URIs and the permission requests. |
| **Service principal** | The local identity in one tenant. Role assignments point at this object. Tokens represent this object. |

An application has **two identifiers**:

| Identifier | Name | Use |
|---|---|---|
| `id` | Object ID | To address the object in Graph paths |
| `appId` | Client ID | To authenticate at the token endpoint |

Entra makes both. A client cannot choose them.

Microsoft Graph is itself an application. Its `appId` is always
`00000003-0000-0000-c000-000000000000`. Your tenant has no Application object
for Graph, because Microsoft owns it. Your tenant has only the local service
principal.

### App roles and delegated scopes

Entra has **two different** permission types. Do not mix them.

| Type | Claim in the token | Who acts |
|---|---|---|
| **App role** (application permission) | `roles` | The application, with no user |
| **Delegated scope** (delegated permission) | `scp` | The application, for a signed-in user |

`Application.ReadWrite.All` exists as both. The two have **different GUIDs**:

| Form | GUID |
|---|---|
| App role | `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9` |
| Delegated scope | `bdfbf15f-ee85-4955-8675-146e8e5296b5` |

An app role grant is an **appRoleAssignment** object. It has three fields:

- `principalId`. The identity that receives the role.
- `resourceId`. The service principal that defines the role.
- `appRoleId`. The role.

A delegated grant is an **oauth2PermissionGrant** object. It records consent.

### Directory roles

A **directory role** gives administrative rights, for example "Global
Administrator". Entra has 136 built-in **role templates**.

A template does nothing until you **activate** it. Activation makes a
`directoryRole` object with a new object ID. You then add members to that
object.

### Tokens

Entra makes JSON Web Tokens. They are signed with RS256. A client checks a
token like this:

1. Read the `kid` field from the token header.
2. Download the OIDC discovery document.
3. Follow its `jwks_uri` to get the public keys.
4. Find the key with the same `kid`.
5. Check the signature, the `aud`, the `iss` and the `exp`.

An app-only token has these important claims:

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://login.microsoftonline.com/<tenant>/v2.0",
  "appid": "<client id>",
  "oid":   "<service principal object id>",
  "idtyp": "app",
  "roles": ["Application.ReadWrite.All"],
  "iat": 1760000000, "exp": 1760003600
}
```

A delegated token has `scp` in place of `roles`. It also has `upn`, `name`
and `preferred_username` for the user.

### Flow 1. Client credentials

A machine gets a token for itself. There is no user.

```
POST /{tenant}/oauth2/v2.0/token
grant_type=client_credentials
client_id=<client id>
client_secret=<secret>
scope=https://graph.microsoft.com/.default
```

The `/.default` suffix means "give me every app role I already have". The
service reads the app role assignments and puts the role values in `roles`.

### Flow 2. Authorization code with PKCE

A user signs in with a browser. The flow has two steps.

**Step 1.** The client sends the user to the authorize endpoint:

```
GET /{tenant}/oauth2/v2.0/authorize
    ?client_id=<client id>
    &response_type=code
    &redirect_uri=https://app.example/callback
    &scope=openid offline_access User.Read
    &state=<random>
    &code_challenge=<SHA-256 of a secret, base64url>
    &code_challenge_method=S256
```

Entra shows a sign-in page. The user signs in and consents. Entra then sends
the browser back:

```
302 Found
Location: https://app.example/callback?code=<code>&state=<random>
```

**Step 2.** The client exchanges the code for tokens:

```
POST /{tenant}/oauth2/v2.0/token
grant_type=authorization_code
client_id=<client id>
code=<code>
redirect_uri=https://app.example/callback
code_verifier=<the secret>
```

The answer has three tokens:

- `access_token`. To call APIs.
- `id_token`. To tell the client who signed in.
- `refresh_token`. To get a new access token later.

**PKCE** stops code theft. The client makes a random secret, the
**verifier**. It sends only the SHA-256 hash, the **challenge**. A thief who
copies the code cannot use it, because the thief has no verifier.

### Flow 3. Refresh token

The access token expires after one hour. The client sends the refresh token:

```
POST /{tenant}/oauth2/v2.0/token
grant_type=refresh_token
client_id=<client id>
refresh_token=<token>
```

Entra **rotates** refresh tokens. The answer has a new refresh token. The old
one stops working. The client must store the new one.

---

## Part 3. What the code does

### The module map

```
src/
  main.rs       Start the process. Open two listeners.
  config.rs     All settings, from flags or environment variables.
  tls.rs        Make a CA and a server certificate.
  cors.rs       Cross-origin headers, so a browser can connect.
  metadata.rs   The Azure cloud metadata document. Terraform reads this.
  state.rs      The state that all handlers share.
  control.rs    The /__sim__ test control endpoints.

  store/        The directory data, held in memory.
    model.rs    The entity types: User, Group, Application, and others.
    mod.rs      The Directory container and its lookups.
    bootstrap.rs  The objects that exist at startup.
    snapshot.rs   Save and load the whole directory.

  odata/        The query engine.
    filter.rs   Turn a $filter string into a tree.
    eval.rs     Test one object against the tree.
    mod.rs      $select, $orderby, $top, $skiptoken, $count. Paging.

  auth/         Identity.
    keys.rs       The RSA signing key and the JWKS document.
    oidc.rs       The OIDC discovery document.
    token.rs      Make and check tokens.
    endpoints.rs  The token endpoint and its three grant types.
    authorize.rs  The authorize endpoint and the sign-in page.
    pkce.rs       Check a code verifier.
    sessions.rs   Hold codes and refresh tokens for a short time.
    middleware.rs Read the bearer token. Run the permission check.
    permissions.rs The permission table and the check itself.

  graph/        The Microsoft Graph API.
    mod.rs        Put the routes under /v1.0 and /beta.
    error.rs      The Graph error body.
    users.rs  groups.rs  applications.rs  service_principals.rs
    app_role_assignments.rs  directory_roles.rs  tenant.rs
    permissions_catalogue.rs  Read the built-in permission data.
```

### The generated data files

Three files hold data from Microsoft documentation. Scripts make them. No
person edits them.

| File | Content | Source |
|---|---|---|
| `src/graph/graph_permissions.json` | 707 app roles and 797 delegated scopes, with real GUIDs | Microsoft Graph permissions reference |
| `src/graph/directory_roles.json` | 136 directory role templates, with real GUIDs | Microsoft Entra role reference |
| `src/auth/permission_requirements.json` | The permissions each of 86 routes needs | Microsoft per-endpoint permission tables |

**Why generate them?** Because a wrong GUID breaks a real configuration. A
person who writes 1504 GUIDs by hand makes mistakes. A script does not.

To make them again:

```sh
git clone --depth 1 https://github.com/microsoftgraph/microsoft-graph-docs-contrib
git clone --depth 1 https://github.com/MicrosoftDocs/entra-docs

scripts/generate-graph-permissions.py \
  microsoft-graph-docs-contrib/concepts/permissions-reference.md \
  src/graph/graph_permissions.json

scripts/generate-directory-roles.py \
  entra-docs/docs/identity/role-based-access-control/permissions-reference.md \
  src/graph/directory_roles.json

scripts/generate-permission-requirements.py \
  microsoft-graph-docs-contrib/api-reference/v1.0 \
  src/auth/permission_requirements.json
```

CI runs these scripts on each push. CI reports a difference as a warning.
This tells you when Microsoft changes its documentation.

### Why the simulator serves /v1.0 and /beta

The Terraform `azuread` provider uses the **beta** Graph endpoint for several
common resources. These are `azuread_group`, `azuread_application`,
`azuread_group_member` and some data sources.

A simulator with only `/v1.0` fails on these resources. The code therefore
puts the same handlers under both prefixes. The cost is one loop.

### Why the simulator terminates TLS

The provider forces the `https` scheme when it reads the metadata document.
The code is in `go-azure-sdk`:

```go
env, err := environments.FromEndpoint(ctx, fmt.Sprintf("https://%s", metadataHost))
```

A simulator that serves only HTTP cannot work with Terraform. The simulator
therefore makes its own CA and server certificate at startup. It writes the
CA to a file. You tell the client to trust that file.

### How Terraform connects: the metadata document

The `azuread` provider has **one** setting that changes its endpoints:
`metadata_host`, or the `ARM_METADATA_HOSTNAME` environment variable.

The provider then does this:

1. It gets `https://<metadata_host>/metadata/endpoints?api-version=2022-09-01`.
2. It reads four fields from the answer.
3. It uses those fields for every later call.

The four fields are:

| Field | Use |
|---|---|
| `name` | The environment name. Must not be empty. |
| `resourceManager` | Must not be empty. The `azuread` provider never calls it. |
| `microsoftGraphResourceId` | **Both** the Graph base URL **and** the token resource. |
| `authentication.loginEndpoint` | The base for the token URL. |

The provider builds the token URL like this:

```go
fmt.Sprintf("%s/%s/oauth2/v2.0/token", LoginEndpoint, tenant)
```

It joins the strings. It does not remove a slash. The simulator therefore
sends `loginEndpoint` **with no trailing slash**. A slash would make
`https://host//tenant/oauth2/v2.0/token`.

`contract/envcheck` is a small Go program. It runs this same provider code
against a running simulator. CI runs it on each push.

### Scenario A. A machine gets a token

This is the client credentials flow.

1. The client POSTs to `/{tenant}/oauth2/v2.0/token`.
2. `auth/endpoints.rs` finds the application by its `appId`.
3. It compares the secret against the stored `passwordCredentials`.
4. It also checks the start date and the end date of the credential.
5. It finds the service principal for the same `appId`.
6. It reads the app role assignments for that principal.
7. It turns each `appRoleId` into a role value, with the Graph role list.
8. It signs a token with those values in `roles`.

Step 6 is important. The role values come from the directory, not from a
stored list. An operator who deletes an assignment changes the **next**
token. A revocation that did not do this would have no effect.

The simulator refuses a `scope` for any other resource. It answers
`400 invalid_scope`. This finds a client that points at the wrong host.

### Scenario B. A user signs in

This is the authorization code flow.

The simulator shows a sign-in page. The page lists the users in the tenant.
It also lists the permissions the client asks for. The page has no external
files, so it works with no network.

When you choose a user, the simulator does three things:

1. It records consent as a real `oauth2PermissionGrant` object.
2. It makes a code and stores it for 10 minutes.
3. It sends a 302 answer to the client `redirect_uri`.

The consent record matters. The token's `scp` claim comes from the directory.
Three results follow:

- A client cannot widen its own token. It gets only consented scopes.
- An operator can see the consent with `GET /v1.0/oauth2PermissionGrants`.
- An operator who deletes the grant narrows the next token.

The simulator also refuses a permission that Graph does not publish. An
invented scope name gives no access.

The code exchange has four checks:

| Check | Reason |
|---|---|
| The code is unused | A stolen code works one time at most |
| The `client_id` matches | Another client cannot use the code |
| The `redirect_uri` matches | A thief cannot send the code to another place |
| The `code_verifier` matches the challenge | Only the first client holds the verifier |

For tests with no browser, set `--auto-sign-in-user`. The simulator then
skips the page and signs that user in. A client can still force the page with
`prompt=login`.

### Scenario C. Directory CRUD

The simulator holds the directory in memory. It uses a `BTreeMap` for each
collection, with the object ID as the key. This gives a stable order. A
stable order makes `$skiptoken` paging safe.

Each entity keeps unknown properties in an `extra` map. This is important for
Terraform. The provider writes many properties the simulator does not
understand. A simulator that dropped one would show a difference on every
`terraform plan`.

The code also keeps an explicit `null`. A property set to `null` reads back as
`null`, not as absent. The shape must not change.

The code never returns a write-only item. These are examples:

- `owners@odata.bind` is an instruction, not a property.
- `secretText` appears one time only, in the `addPassword` answer.
- A user password never appears in any answer.

### Scenario D. Permission enforcement

The simulator checks each request against the permissions Microsoft publishes
for that endpoint.

The check runs inside the `Caller` extractor. A handler that asks for the
caller gets the check. A route cannot miss it.

A requirement is a list of alternatives. Each alternative is a list of
permissions you must hold together. Microsoft documents some endpoints this
way. Here is `POST /servicePrincipals/{id}/appRoleAssignedTo`:

```
(AppRoleAssignment.ReadWrite.All AND Application.Read.All)
OR (AppRoleAssignment.ReadWrite.All AND Directory.Read.All)
OR Application.ReadWrite.All
```

Half of a conjunction is not enough. The simulator answers `403` with the
real Graph code:

```json
{"error": {
  "code": "Authorization_RequestDenied",
  "message": "Insufficient privileges to complete the operation."
}}
```

The code adds **one** rule to Microsoft's tables. A write permission also
satisfies a read requirement. `Directory.ReadWrite.All` works where
`Directory.Read.All` is listed. Entra behaves this way. The tables list the
two separately. Without this rule the simulator would refuse a request the
real service serves.

An app-only token is judged on `roles`. A delegated token is judged on `scp`.
The two are never mixed. A client cannot get app-only rights by signing a
user in.

To turn the check off, set `--enforce-permissions false`. This helps when you
write tests before you set up consent.

### Scenario E. Terraform deploys an app registration

`terraform/accept/` holds a working example. It makes seven resources:

- A user.
- A group.
- A group membership.
- An application, with Graph permissions named by GUID.
- A service principal.
- A client secret.
- An app role assignment.

The example works with no simulator-specific code. Only the environment
differs from a real tenant.

This test found four faults that unit tests did not find:

1. Entra makes the caller the **initial owner** of a new application and of a
   new service principal. The provider then removes that owner. The removal
   failed, because the simulator added no owner.
2. The provider reads one app role assignment after it makes it. Only the
   collection route answered. The provider got a `405`.
3. `owners@odata.bind` was stored as data. It appeared in every read.
4. An explicit `null` was dropped. The property read back as absent.

Fault 4 is the reason for the strongest test in CI:

```sh
terraform apply -auto-approve
terraform plan -detailed-exitcode   # must exit 0
```

An exit code of 0 means the plan is empty. A plan that is not empty means the
simulator does not return something the provider wrote. This is the fault
type that is hardest to see in unit tests.

### The tests

There are 177 tests.

| File | Subject |
|---|---|
| Unit tests in `src/` | The `$filter` parser, PKCE, the permission table, the session store |
| `tests/metadata.rs` | The Terraform metadata contract |
| `tests/oidc.rs` | Discovery and JWKS |
| `tests/token.rs` | Client credentials |
| `tests/users.rs` | Users, OData, both path prefixes |
| `tests/groups.rs` | Groups, membership, nested groups |
| `tests/applications.rs` | Applications, secrets, service principals |
| `tests/roles.rs` | Role assignments, grants, directory roles |
| `tests/enforcement.rs` | Permission refusals |
| `tests/interactive.rs` | The browser flow, PKCE, refresh |
| `tests/control.rs` | Seed, snapshot, reset |

---

## Part 4. How to test with the container

### Start the container

```sh
mkdir -p certs
docker run --rm \
  --name entra-sim \
  --user "$(id -u):$(id -g)" \
  -p 8080:8080 \
  -p 8443:8443 \
  -v "$PWD/certs:/certs" \
  ghcr.io/gosogco/entra-sim:latest
```

The container opens two ports:

| Port | Protocol | Use |
|---|---|---|
| 8443 | HTTPS | Terraform, and any client that needs TLS |
| 8080 | HTTP | Simple clients, and health checks |

The container writes its CA certificate to `certs/ca.pem`. Clients must trust
this file.

### The certs directory

`./certs` is any directory on your machine. It has no special meaning. `$PWD`
makes the path absolute, which Docker requires on the left of a `-v` flag.

The flag `-v "$PWD/certs:/certs"` is a **bind mount**. It is not a copy. The
host directory and `/certs` inside the container are the same directory. A
write on one side is a write to the same file.

Two rules follow. Both stop the container if you break them:

**Rule 1. Make the directory first.** Docker creates a missing directory as
`root`. The container's own user cannot then write in it. The container stops
with this error:

```
Error: writing CA certificate to /certs/ca.pem
Caused by:
    Permission denied (os error 13)
```

**Rule 2. The container must be able to replace the file.** The container runs
as user 10001. A `ca.pem` that you made, or that `root` made, is not writable
by that user. Mode 777 on the directory is not enough. Linux needs write
permission on the **file** to replace it.

`--user "$(id -u):$(id -g)"` solves both rules. The container then writes as
you. You can read and delete what it writes. A file from an earlier run can be
replaced.

Without `--user`, give the directory mode 777 instead:

```sh
mkdir -p certs && chmod 777 certs
```

### The CA changes on every restart

Each start makes a new CA and a new server certificate. A client that holds the
previous `ca.pem` then fails with "certificate signed by unknown authority".

Read the file again after each restart. To keep one CA, supply your own
certificate:

```sh
-e ENTRA_SIM_TLS_CERT=/certs/server.pem \
-e ENTRA_SIM_TLS_KEY=/certs/server.key
```

The signing key behaves the same way. Set `ENTRA_SIM_SIGNING_KEY` to keep a
stable `kid` across restarts.

### Wait for the container

The container is not ready when `docker run` returns. It makes an RSA key
first. This takes some seconds:

```sh
until curl -sf -o /dev/null http://127.0.0.1:8080/__sim__/health; do sleep 1; done
```

### The bootstrap client

The simulator registers one application at startup. Without it, no client
could authenticate.

| Item | Default value |
|---|---|
| Tenant ID | `00000000-0000-0000-0000-000000000001` |
| Client ID | `11111111-1111-1111-1111-111111111111` |
| Client secret | `entra-sim-bootstrap-secret` |
| Tenant domain | `entra-sim.test` |

This client holds the app roles that Terraform needs.

### Get a token and call Graph

```sh
TOKEN=$(curl -s --cacert certs/ca.pem \
  -d grant_type=client_credentials \
  -d client_id=11111111-1111-1111-1111-111111111111 \
  -d client_secret=entra-sim-bootstrap-secret \
  -d 'scope=https://localhost:8443/.default' \
  https://localhost:8443/00000000-0000-0000-0000-000000000001/oauth2/v2.0/token \
  | jq -r .access_token)

curl -s --cacert certs/ca.pem \
  -H "Authorization: Bearer $TOKEN" \
  'https://localhost:8443/v1.0/users?$top=5' | jq
```

**Note the scope.** It is the simulator's own base URL, not
`https://graph.microsoft.com`. The simulator refuses any other resource.

### Test 1. Terraform

Set five environment variables. Then run Terraform as normal.

```sh
export ARM_METADATA_HOSTNAME=localhost:8443
export SSL_CERT_FILE=$PWD/certs/ca.pem
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000001
export ARM_CLIENT_ID=11111111-1111-1111-1111-111111111111
export ARM_CLIENT_SECRET=entra-sim-bootstrap-secret

terraform init
terraform apply
terraform plan -detailed-exitcode    # 0 means no difference
terraform destroy
```

Your `.tf` files need **no change**. Remove `ARM_METADATA_HOSTNAME` to use a
real tenant again.

`SSL_CERT_FILE` is necessary. The provider is a Go program. Go reads this
variable to find extra trusted CAs.

### Test 2. An application client

For an Azure SDK client, set the authority host:

```sh
export AZURE_AUTHORITY_HOST=https://localhost:8443/
export AZURE_TENANT_ID=00000000-0000-0000-0000-000000000001
export AZURE_CLIENT_ID=11111111-1111-1111-1111-111111111111
export AZURE_CLIENT_SECRET=entra-sim-bootstrap-secret
export SSL_CERT_FILE=$PWD/certs/ca.pem          # Go and some tools
export REQUESTS_CA_BUNDLE=$PWD/certs/ca.pem     # Python requests
export NODE_EXTRA_CA_CERTS=$PWD/certs/ca.pem    # Node.js
```

Then request tokens for the simulator's base URL as the resource.

For a client that reads OIDC discovery, give it this URL:

```
https://localhost:8443/00000000-0000-0000-0000-000000000001/v2.0/.well-known/openid-configuration
```

### Test 3. A browser client

`examples/react-spa/` is a complete working example. Read its README first. What follows is the
background.

A single-page application needs three things from the simulator, and all three are present:

| Need | Why |
|---|---|
| Cross-origin headers | The browser refuses the call to the token endpoint without them |
| `response_mode=fragment` | `msal-browser` uses it and offers no alternative |
| `GET /me` | The usual first Graph call a signed-in client makes |

MSAL also checks that an authority's host is a genuine Microsoft endpoint, by asking Microsoft's
instance-discovery service. For a local simulator that call is both wrong and unreachable, so the
answer is given to MSAL inline:

```ts
knownAuthorities: ['localhost:8443'],
cloudDiscoveryMetadata: JSON.stringify({
  tenant_discovery_endpoint:
    'https://localhost:8443/<tenant>/v2.0/.well-known/openid-configuration',
  'api-version': '1.1',
  metadata: [{
    preferred_network: 'localhost:8443',
    preferred_cache: 'localhost:8443',
    aliases: ['localhost:8443'],
  }],
}),
```

Both are unset against a real tenant. MSAL stays in **AAD** protocol mode for both targets, so
the simulator is driven through the same MSAL code path as production.

The browser must also trust the certificate. Use `mkcert` and feed the result to
`ENTRA_SIM_TLS_CERT` and `ENTRA_SIM_TLS_KEY`. That also stops the CA changing on each restart.

To register the redirect URIs on an application:

```sh
curl -s --cacert certs/ca.pem -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "displayName": "My Web App",
    "web": { "redirectUris": ["https://localhost:3000/callback"] }
  }' \
  https://localhost:8443/v1.0/applications
```

Then make a service principal for it. Then open the authorize URL in a
browser. The simulator shows the sign-in page.

For a test with no browser, start the container with an automatic user:

```sh
docker run ... -e ENTRA_SIM_AUTO_SIGN_IN_USER=alice@entra-sim.test ...
```

The authorize endpoint then answers `302` at once.

### Test 4. Docker Compose

```yaml
services:
  entra-sim:
    image: ghcr.io/gosogco/entra-sim:latest
    ports: ["8080:8080", "8443:8443"]
    volumes: ["./certs:/certs"]
    environment:
      ENTRA_SIM_TLS_SAN: localhost,127.0.0.1,entra-sim
      ENTRA_SIM_PUBLIC_HOST: entra-sim:8443
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/__sim__/health"]
      interval: 10s
      start_period: 20s

  my-app:
    build: .
    depends_on:
      entra-sim:
        condition: service_healthy
    volumes: ["./certs:/certs:ro"]
    environment:
      SSL_CERT_FILE: /certs/ca.pem
      AZURE_AUTHORITY_HOST: https://entra-sim:8443/
```

Put the service name in `ENTRA_SIM_TLS_SAN` and in `ENTRA_SIM_PUBLIC_HOST`.
Other containers reach the simulator by that name.

### Test 5. GitHub Actions

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      entra-sim:
        image: ghcr.io/gosogco/entra-sim:latest
        ports: ['8080:8080', '8443:8443']
        env:
          ENTRA_SIM_PUBLIC_HOST: localhost:8443
    steps:
      - uses: actions/checkout@v5

      # A service container cannot share a volume, so copy the CA out.
      - name: Get the CA certificate
        run: |
          until curl -sf -o /dev/null http://localhost:8080/__sim__/health; do sleep 1; done
          docker cp "$(docker ps -qf ancestor=ghcr.io/gosogco/entra-sim:latest)":/certs/ca.pem ca.pem

      - name: Test
        env:
          SSL_CERT_FILE: ${{ github.workspace }}/ca.pem
          ARM_METADATA_HOSTNAME: localhost:8443
          ARM_TENANT_ID: 00000000-0000-0000-0000-000000000001
          ARM_CLIENT_ID: 11111111-1111-1111-1111-111111111111
          ARM_CLIENT_SECRET: entra-sim-bootstrap-secret
        run: ./run-tests.sh
```

### Control the state

Three endpoints manage the directory. They are under `/__sim__`. No Graph
path can conflict with this prefix.

| Request | Result |
|---|---|
| `GET /__sim__/health` | Liveness, version and tenant ID |
| `POST /__sim__/reset` | Return to the start state |
| `GET /__sim__/snapshot` | Write out everything, with secrets |
| `POST /__sim__/snapshot` | Replace everything |

These endpoints need no token. A person who can reach the simulator can
already make a token for any identity in it.

Call reset between test cases:

```sh
curl -X POST http://127.0.0.1:8080/__sim__/reset
```

Reset also deletes all authorization codes and refresh tokens.

### Use a seed file

A seed file gives you fixed test data. Make the file from a snapshot:

```sh
# 1. Build the state you want through the API.
# 2. Save it.
curl -s http://127.0.0.1:8080/__sim__/snapshot > seed.json
```

Then start the container with that file:

```sh
docker run ... -v "$PWD/seed.json:/seed/tenant.json:ro" \
  -e ENTRA_SIM_SEED=/seed/tenant.json ...
```

The simulator loads the seed at startup **and on every reset**. Your test
suite can reset between cases and keep its fixtures.

A seed file that is not valid stops the startup. The simulator does not start
with an empty tenant. An empty tenant looks like a working simulator with
lost data. That fault is much harder to find.

### Settings reference

All settings have a flag and an environment variable.

| Environment variable | Default | Purpose |
|---|---|---|
| `ENTRA_SIM_BIND` | `0.0.0.0` | The listen address |
| `ENTRA_SIM_HTTP_PORT` | `8080` | The HTTP port |
| `ENTRA_SIM_HTTPS_PORT` | `8443` | The HTTPS port |
| `ENTRA_SIM_NO_TLS` | off | Stop the HTTPS listener |
| `ENTRA_SIM_PUBLIC_HOST` | `localhost:8443` | The host and port in all URLs the simulator makes |
| `ENTRA_SIM_TLS_SAN` | `localhost,127.0.0.1` | The names in the server certificate |
| `ENTRA_SIM_CA_OUT` | none | Where to write the CA certificate |
| `ENTRA_SIM_TLS_CERT` | none | Use this certificate chain |
| `ENTRA_SIM_TLS_KEY` | none | Use this private key |
| `ENTRA_SIM_TENANT_ID` | `00000000-...-0001` | The tenant GUID |
| `ENTRA_SIM_TENANT_DOMAIN` | `entra-sim.test` | The tenant domain |
| `ENTRA_SIM_SIGNING_KEY` | none | Use this PKCS#8 key, to keep a stable `kid` |
| `ENTRA_SIM_SEED` | none | The snapshot to load |
| `ENTRA_SIM_AUTO_SIGN_IN_USER` | none | Skip the sign-in page |
| `ENTRA_SIM_ENFORCE_PERMISSIONS` | `true` | Check permissions |
| `ENTRA_SIM_BOOTSTRAP_CLIENT_ID` | `11111111-...-1111` | The first client |
| `ENTRA_SIM_BOOTSTRAP_CLIENT_SECRET` | `entra-sim-bootstrap-secret` | Its secret |
| `ENTRA_SIM_BOOTSTRAP_APP_ROLES` | 7 roles | Its app roles |
| `ENTRA_SIM_TOKEN_TTL` | `3600` | The token lifetime, in seconds |
| `ENTRA_SIM_LOG` | `info` | The log filter |

**Set `ENTRA_SIM_PUBLIC_HOST` correctly.** The simulator puts this value in
the metadata document, the discovery document and every token `iss` and
`aud`. Clients must reach the simulator at this address. A wrong value makes
tokens that no client accepts.

### Endpoint reference

**Identity endpoints.** `{tenant}` accepts the GUID, `common`,
`organizations` or `consumers`.

```
GET  /metadata/endpoints                                  Azure cloud metadata
GET  /{tenant}/v2.0/.well-known/openid-configuration      OIDC discovery
GET  /{tenant}/discovery/v2.0/keys                        JWKS
GET  /{tenant}/oauth2/v2.0/authorize                      Sign-in page
POST /{tenant}/oauth2/v2.0/authorize                      Choose a user
POST /{tenant}/oauth2/v2.0/token                          All three grants
GET  /{tenant}/oauth2/v2.0/logout                         Sign out
```

**Graph endpoints.** Each one works under `/v1.0` and under `/beta`.

```
Me
  GET    /me                         The signed-in user. Delegated tokens only.

Users
  GET    /users                      POST   /users
  GET    /users/{id}                 PATCH  /users/{id}
  DELETE /users/{id}                 GET    /users/{id}/memberOf
  GET    /users/{id}/appRoleAssignments
  POST   /users/{id}/appRoleAssignments

Groups
  GET    /groups                     POST   /groups
  GET    /groups/{id}                PATCH  /groups/{id}
  DELETE /groups/{id}
  GET    /groups/{id}/members        POST   /groups/{id}/members/$ref
  DELETE /groups/{id}/members/{member-id}/$ref
  GET    /groups/{id}/owners         POST   /groups/{id}/owners/$ref
  DELETE /groups/{id}/owners/{owner-id}/$ref
  GET    /groups/{id}/transitiveMembers
  GET    /groups/{id}/memberOf

Applications
  GET    /applications               POST   /applications
  GET    /applications/{id}          PATCH  /applications/{id}
  DELETE /applications/{id}
  POST   /applications/{id}/addPassword
  POST   /applications/{id}/removePassword
  POST   /applications/{id}/addKey
  POST   /applications/{id}/removeKey
  GET    /applications/{id}/owners
  POST   /applications/{id}/owners/$ref
  DELETE /applications/{id}/owners/{owner-id}/$ref
  GET    /applications/{id}/federatedIdentityCredentials
  POST   /applications/{id}/federatedIdentityCredentials

Service principals
  GET    /servicePrincipals          POST   /servicePrincipals
  GET    /servicePrincipals/{id}     PATCH  /servicePrincipals/{id}
  DELETE /servicePrincipals/{id}
  GET    /servicePrincipals/{id}/appRoleAssignedTo
  POST   /servicePrincipals/{id}/appRoleAssignedTo
  GET    /servicePrincipals/{id}/appRoleAssignments
  GET    /servicePrincipals/{id}/oauth2PermissionGrants
  GET    /servicePrincipals/{id}/owners
  GET    /servicePrincipals/{id}/memberOf

Permission grants
  GET    /oauth2PermissionGrants     POST   /oauth2PermissionGrants
  GET    /oauth2PermissionGrants/{id}
  PATCH  /oauth2PermissionGrants/{id}
  DELETE /oauth2PermissionGrants/{id}

Directory roles
  GET    /directoryRoleTemplates     GET    /directoryRoleTemplates/{id}
  GET    /directoryRoles             POST   /directoryRoles
  GET    /directoryRoles/{id}        GET    /directoryRoles/{id}/members
  POST   /directoryRoles/{id}/members/$ref
  DELETE /directoryRoles/{id}/members/{member-id}/$ref
  GET    /roleManagement/directory/roleDefinitions
  GET    /roleManagement/directory/roleAssignments
  POST   /roleManagement/directory/roleAssignments
  DELETE /roleManagement/directory/roleAssignments/{id}

Tenant
  GET    /organization               GET    /domains
  POST   /directoryObjects/getByIds
```

**Query options.** These work on all collections:

```
$filter    eq ne gt ge lt le, and or not, startswith endswith contains,
           in (...), path/any(x: ...)
$select    A list of properties
$orderby   A property, with asc or desc
$top       1 to 999
$skiptoken From @odata.nextLink
$count     true
$expand    members, owners
```

### Limits

The simulator does not support these:

| Not supported | Effect |
|---|---|
| `$batch` | A client that batches requests fails |
| Delta queries | A client that syncs changes fails |
| More than one tenant | One process serves one tenant |
| `client_assertion` (`private_key_jwt`) | Use a secret or PKCE |
| `prompt=none` in a hidden iframe | MSAL uses the refresh token first, so this is only reached after 24 hours |
| Eventual consistency | A write is readable at once. Real Entra is slower. |
| Conditional access, PIM, entitlement management | Not present |

A route that the permission table does not cover is **allowed**, with a
warning in the log. A refusal would break a client that the real service
serves.

### Faults and their causes

| Symptom | Cause | Action |
|---|---|---|
| `Permission denied (os error 13)` at startup | The CA directory or an old `ca.pem` is not writable by the container | Add `--user "$(id -u):$(id -g)"`, or `chmod 777` the directory |
| `certificate signed by unknown authority` | The client does not trust the CA | Set `SSL_CERT_FILE` to `ca.pem` |
| `certificate signed by unknown authority` after a restart | The CA is new. The client holds the old one. | Read `ca.pem` again, or set `ENTRA_SIM_TLS_CERT` and `ENTRA_SIM_TLS_KEY` |
| `Invalid audience` on a Graph call | `ENTRA_SIM_PUBLIC_HOST` is not the address the client uses | Make the two the same |
| `400 invalid_scope` | The `scope` names another resource | Use `<public-host>/.default` |
| `403 Authorization_RequestDenied` | The token has no required permission | Add an app role assignment, or set `ENTRA_SIM_ENFORCE_PERMISSIONS=false` |
| `404` on a `$ref` delete | The object is not in the collection | Read the collection first |
| Terraform `plan` is not empty | The simulator does not return a property | Report it. This is a fault. |
| The container is slow to start | It makes an RSA key | Wait for the health check |
| `kid` changes after a restart | The key is new | Set `ENTRA_SIM_SIGNING_KEY` |

### Known inconsistency

The Microsoft Graph service principal has
`https://graph.microsoft.com` in its `servicePrincipalNames`. This is correct
data. A real tenant has the same value.

But the simulator refuses a token request for that resource. It accepts only
its own base URL. A client that has a fixed
`https://graph.microsoft.com/.default` scope therefore fails.

Three options exist. No one has made the choice yet:

1. Remove the name. Nothing then names a resource the simulator refuses.
2. Accept `https://graph.microsoft.com/.default` as another name for the
   simulator's resource. This helps clients with a fixed scope. It needs a
   change to the token endpoint and to the token check.
3. Keep the behaviour. It finds a client that points at the wrong host.
