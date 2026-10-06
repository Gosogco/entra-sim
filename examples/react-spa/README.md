# React example

A single-page application that signs a user in with MSAL and calls Microsoft Graph.

The same build runs against `entra-sim` and against a real Microsoft Entra tenant. Only the
environment file differs. No source file changes between the two.

## What it demonstrates

| | |
|---|---|
| Sign-in | `msal-browser` in **AAD** protocol mode, the same mode a real tenant uses |
| Flow | Authorization code with PKCE, and refresh tokens |
| API call | `GET /me`, so the access token is proven usable and not only issued |
| Permissions | A `403` from the simulator's permission enforcement is shown with its Graph error code |

## Run it against the simulator

**1. Start the simulator.** It needs the `example.test` domain, because the user is
`alice@example.test`.

```sh
mkdir -p certs
docker run --rm --user "$(id -u):$(id -g)" \
  -p 8080:8080 -p 8443:8443 -v "$PWD/certs:/certs" \
  -e ENTRA_SIM_TENANT_DOMAIN=example.test \
  ghcr.io/gosogco/entra-sim:latest

# Wait for it. Generating an RSA key takes a few seconds.
until curl -sf -o /dev/null http://127.0.0.1:8080/__sim__/health; do sleep 1; done
```

**2. Trust the certificate.** The browser will not talk to the simulator otherwise. `mkcert`
installs a local certificate authority into your operating system and browser trust stores:

```sh
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1
```

Then restart the simulator with that certificate instead of its own:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -p 8080:8080 -p 8443:8443 -v "$PWD/certs:/certs" \
  -e ENTRA_SIM_TENANT_DOMAIN=example.test \
  -e ENTRA_SIM_TLS_CERT=/certs/localhost.pem \
  -e ENTRA_SIM_TLS_KEY=/certs/localhost-key.pem \
  ghcr.io/gosogco/entra-sim:latest
```

This also fixes a second problem: a supplied certificate does not change on restart, so the
browser keeps trusting it and the token signing key identifier stays stable.

**3. Create the directory objects.** Either with Terraform:

```sh
cd terraform
export ARM_METADATA_HOSTNAME=localhost:8443
export SSL_CERT_FILE=$PWD/../certs/ca.pem    # omit when using mkcert
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000001
export ARM_CLIENT_ID=11111111-1111-1111-1111-111111111111
export ARM_CLIENT_SECRET=entra-sim-bootstrap-secret
export TF_VAR_simulator_host=localhost:8443

terraform init && terraform apply
terraform output -raw env > ../.env
cd ..
```

Or without Terraform:

```sh
CA=certs/ca.pem scripts/setup.sh > .env
```

**4. Run the site.**

```sh
npm install
npm run dev
```

Open `http://localhost:5173/` and sign in as `alice@example.test`. The simulator's sign-in page
lists the tenant's users as buttons.

## Run it against a real tenant

Apply the same Terraform configuration with `ARM_METADATA_HOSTNAME` unset, so the provider talks
to the real service. Set `create_user=false`, because the account already exists and belongs to a
person: Terraform would otherwise fail on a conflict, or take over managing a real account and
delete it on destroy.

```sh
cd terraform
unset ARM_METADATA_HOSTNAME SSL_CERT_FILE TF_VAR_simulator_host
export ARM_TENANT_ID=<your tenant>
export ARM_CLIENT_ID=<a client that may manage applications>
export ARM_CLIENT_SECRET=<its secret>

terraform init && terraform apply -var create_user=false
terraform output -raw env > ../.env
```

Then `npm run dev` again. Nothing else changes.

## What differs between the two

| Value | Simulator | Real tenant |
|---|---|---|
| `VITE_AUTHORITY` | `https://localhost:8443/<tenant>` | `https://login.microsoftonline.com/<tenant>` |
| `VITE_GRAPH_BASE` | `https://localhost:8443` | `https://graph.microsoft.com` |
| `VITE_CLIENT_ID` | from Terraform | from Terraform |
| `VITE_CLOUD_DISCOVERY_METADATA` | an inline JSON answer | **unset** |

`.env.simulator` and `.env.entra` hold these as templates.

The last row is the only interesting one. MSAL checks that an authority's host is a genuine
Microsoft endpoint by asking Microsoft's instance-discovery service. For a local simulator that
call is both wrong and unreachable, so the answer is supplied inline instead. Two settings in
`src/authConfig.ts` do this:

- `knownAuthorities`, which tells MSAL the host is valid.
- `cloudDiscoveryMetadata`, which is the answer MSAL would have fetched.

Against a real tenant `cloudDiscoveryMetadata` is unset, so MSAL uses the real service.

Nothing else is needed. MSAL stays in AAD protocol mode for both, so the simulator is driven
through the same MSAL code path as production. Running it in OIDC mode would have been easier and
would have proved much less.

## The end-to-end test

```sh
npx playwright install chromium
npm run e2e
```

Three tests, against a running simulator with the fixtures applied:

1. MSAL completes a sign-in, **and no request reaches a Microsoft host**. Without that second
   assertion, a passing sign-in could mean MSAL had quietly used the real service.
2. The Graph call shows the user, which proves the access token is accepted by an API.
3. Revoking the consent grant narrows the next token, and the page shows the resulting `403`.

The third test needs a forced token refresh. An access token that has already been issued stays
valid until it expires, which is correct, so the page has a button that redeems the refresh token
to get a new one.

Playwright runs with `ignoreHTTPSErrors`, so the e2e test does not need `mkcert`. That is only
for interactive use in your own browser.

## Files

| Path | Purpose |
|---|---|
| `src/authConfig.ts` | The MSAL configuration, and every value that differs between targets |
| `src/graph.ts` | The `/me` call and token acquisition |
| `src/App.tsx` | The page |
| `terraform/` | The app registration, the user and the consent grant |
| `scripts/setup.sh` | The same objects, with `curl` instead of Terraform |
| `e2e/signin.spec.ts` | The browser test |
