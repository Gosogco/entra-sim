# Users and app roles with Terraform

Creates five users and two applications, Orders and Inventory, each defining the app roles
`Reader`, `Writer` and `Admin`. It then assigns users to those roles:

| User  | Orders | Inventory      |
|-------|--------|----------------|
| alice | Admin  | Admin          |
| bob   | Writer | Reader         |
| carol | Reader | —              |
| dave  | —      | Writer, Reader |
| erin  | —      | —              |

User principal names are built from the tenant's initial domain. Orders and Inventory have the
identifier URIs `api://orders` and `api://inventory`, which is the name a client asks for a token
with.

## Running it

```sh
./run.sh            # start the simulator if needed, then terraform apply
./run.sh destroy    # remove everything again
```

`run.sh` starts the simulator in Docker on `localhost:8443` if none is running there, and makes
Terraform trust its CA certificate. The provider block in `main.tf` is pinned to
`localhost:8443` with the simulator's bootstrap credentials, so this configuration never reaches
Microsoft, whatever the environment holds.

## Seeing the roles in a token

The roles only matter once they are in a token, which is where an API reads them. `token.sh`
signs a user in to one of the two APIs through the public client `Role viewer`, and prints the
access token's claims:

```sh
./token.sh bob orders
```

```json
{
  "aud": "api://orders",
  "iss": "https://sts.windows.net/00000000-0000-0000-0000-000000000001/",
  "roles": ["Writer"],
  "upn": "bob@entra-sim.test",
  "ver": "1.0",
  ...
}
```

Bob holds `Writer` on Orders, so that is what the token carries; `./token.sh bob inventory` shows
`Reader` instead, and `erin` gets no `roles` claim at all. The token is in the v1.0 format because
the applications do not set `api.requestedAccessTokenVersion`, and v1.0 is Entra's default and the
`azuread` provider's. Set `requested_access_token_version = 2` in an `api` block to get a v2.0
token, whose `aud` is the application's client ID.

This needs a simulator that issues tokens for registered APIs, which versions after 0.7.0 do.
