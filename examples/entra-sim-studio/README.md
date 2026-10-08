# entra-sim studio

A read-only browser view of everything inside a running `entra-sim`: users, groups, app
registrations, enterprise apps, permissions, directory roles, and the tokens it has issued.

It is the answer to "what does the simulator think the directory looks like right now?" while a
test, a Terraform run or the React example is changing it underneath you. Every GUID is shown as
the name of what it refers to, with the GUID one hover away.

It never writes. There is no sign-in either: it reads the simulator's unauthenticated control
endpoints, so no MSAL and no app registration are involved.

## What it shows

| Tab | Contents |
|---|---|
| Overview | Simulator version, tenant ID, object counts, active access and refresh tokens, and the next thing to expire |
| Users | UPN, name, enabled, job title, mail, type, created. Expanded: group memberships (including through nested groups), directory roles, app role assignments, and the password |
| Groups | Type (security, Microsoft 365, mail-enabled), members and owners by name, including nested groups |
| App registrations | Name, client ID, object ID, sign-in audience, identifier URIs, owners. Expanded: redirect URIs, app roles, requested API permissions resolved to names and marked granted or not, client secrets with their values, certificates, federated credentials |
| Enterprise apps | Service principals: name, appId, linked registration, service principal names, tags, whether assignment is required. Expanded: roles and delegated permissions it holds, and who is assigned to it |
| Permissions | App role assignments (principal → resource : role) and delegated grants (client, resource, scopes, consent type, user) |
| Directory roles | Activated roles and their members |
| Tokens | Issued access and ID tokens, refresh tokens (prefix only), and authorization codes waiting to be redeemed |

Secrets and passwords are masked until clicked. Expiry times count down live on the simulator's
clock, not the browser's, and turn red when close: under 5 minutes for tokens and codes, under 7
days for client secrets, certificates and refresh tokens.

Permission GUIDs (in `requiredResourceAccess` and app role assignments) are resolved against the
resource service principal's own `appRoles` and `oauth2PermissionScopes`. Microsoft Graph's
principal is created when the simulator starts, so Graph permissions always resolve. A GUID that
does not resolve is shown as-is, in amber, which usually means a dangling reference.

## Quick start

```sh
./run.sh           # against whatever the simulator holds
./run.sh --seed    # first create the React example's app and user (resets the directory)
```

It starts the simulator in Docker if it isn't running, or reuses the one that is, so it can run
alongside the React example's `run.sh`. Then it starts the studio on http://localhost:5174/.

## Run it

**1. Start the simulator**, on the loopback interface only (see the warning below):

```sh
cd ../react-spa      # so step 2's setup script finds the CA in certs/
mkdir -p certs
docker run --rm --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 -v "$PWD/certs:/certs" \
  -e ENTRA_SIM_TENANT_DOMAIN=example.test \
  ghcr.io/gosogco/entra-sim:0.4.0
```

**2. Optionally put something in it.** The React example's setup script creates a user, an app
registration and its service principal:

```sh
cd ../react-spa
CA=certs/ca.pem scripts/setup.sh > .env
cd ../entra-sim-studio
```

The script resets the directory first, so do not run it against a simulator holding objects you
want to keep.

**3. Run the studio:**

```sh
npm install
npm run dev
```

Open `http://localhost:5174/`. It re-reads the simulator every 5 seconds; **Pause** stops that,
for example while you study a row that is about to change.

### Pointing it elsewhere

The studio reads from `VITE_SIM_URL`, by default `http://localhost:8080`. That is the
simulator's plain HTTP listener, which saves the browser from having to trust the simulator's
self-generated TLS certificate just to read from it.

```sh
VITE_SIM_URL=http://localhost:9080 npm run dev
```

Or put the line in `.env.local`, which git ignores. Vite reads the variable when the dev server
starts, so restart it after changing it.

## Tokens and federated credentials need simulator 0.4.0 or later

The token list comes from `/__sim__/tokens`, and federated credentials from the snapshot, both
added in 0.4.0. Against an older simulator the studio says so where they would appear, and the
rest works normally.

The command above pins `0.4.0`. If you use `:latest` instead, run `docker pull` first: Docker
otherwise keeps using whatever `latest` it downloaded before, which may be older.

Refresh tokens and authorization codes are listed by a short prefix only. The simulator never
returns a whole one, since a value copied from this page would otherwise be a working credential.

## Keep the simulator on 127.0.0.1

`/__sim__/snapshot`, which the studio reads, returns the **whole directory including every client
secret and user password**, with no authentication. That is fine for a simulator holding fake
credentials on your own machine, and the reason the `docker run` above publishes its ports on
`127.0.0.1` rather than on all interfaces. Do not expose it on a shared network.

## Where the data comes from

| Endpoint | Used for |
|---|---|
| `GET /__sim__/health` | Version and tenant ID |
| `GET /__sim__/snapshot` | Everything in the directory |
| `GET /__sim__/tokens` | Issued tokens, refresh tokens, pending codes (0.4.0+; a `404` means an older simulator) |

The three are fetched together on each poll. If the simulator stops answering, a banner says how
to start it and the last data received stays on screen.

Federated identity credentials are not part of the snapshot in simulator 0.3.x, so the App
registrations tab says so instead of claiming there are none.

## The end-to-end test

A smoke test that loads the studio in Chromium against a running simulator:

```sh
npx playwright install chromium
npm run e2e
```

It expects the simulator at `VITE_SIM_URL`, seeded by `../react-spa/scripts/setup.sh` beforehand.
The test does not run the script itself, because a test of a read-only viewer should not be what
changes the directory. It checks that:

1. The Users tab lists `alice@example.test`, or `E2E_USER` if you seeded a different user.
2. The App registrations tab lists the simulator's bootstrap client, with its secret masked until
   clicked.
3. The Tokens tab lists a client-credentials token the test requests itself, or shows the
   "needs ≥ 0.4.0" message on an older simulator. It requests its own because `setup.sh` resets
   the simulator, and a reset empties the token list. A token adds to that list, not to the
   directory.

Playwright starts `npm run dev` on port 5174, or reuses one that is already running.

## Files

| Path | Purpose |
|---|---|
| `src/api.ts` | Fetching the three endpoints, and the simulator clock offset |
| `src/types.ts` | The snapshot and token shapes, mirroring the simulator's `src/store/model.rs` |
| `src/directory.ts` | The cross-reference index: GUID to name, memberships, permission resolution |
| `src/components/` | `Ref`, `Masked`, `Expiry` and the searchable, expandable `DataTable` |
| `src/views/` | One file per tab |
| `src/App.tsx` | Polling, tabs, and the unreachable banner |
| `e2e/studio.spec.ts` | The smoke test |
