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

User principal names are built from the tenant's initial domain.

## Running it

```sh
./run.sh            # start the simulator if needed, then terraform apply
./run.sh destroy    # remove everything again
```

`run.sh` starts the simulator in Docker on `localhost:8443` if none is running there, and makes
Terraform trust its CA certificate. The provider block in `main.tf` is pinned to
`localhost:8443` with the simulator's bootstrap credentials, so this configuration never reaches
Microsoft, whatever the environment holds.
