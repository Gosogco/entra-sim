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

User principal names are built from the tenant's initial domain, for example
`alice@entra-sim.test` against a simulator with the default domain.

## Running it

With the simulator running and its CA written to `certs/ca.pem`, run this from this directory:

```sh
export ARM_METADATA_HOSTNAME=localhost:8443
export SSL_CERT_FILE=/path/to/certs/ca.pem
export ARM_TENANT_ID=00000000-0000-0000-0000-000000000001
export ARM_CLIENT_ID=11111111-1111-1111-1111-111111111111
export ARM_CLIENT_SECRET=entra-sim-bootstrap-secret

terraform init
terraform apply
terraform output assignments
```

`terraform destroy` removes everything again.

Against a real tenant, unset `ARM_METADATA_HOSTNAME` and `SSL_CERT_FILE` and use that tenant's
credentials. Nothing in `main.tf` changes.
