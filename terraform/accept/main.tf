# Exercises the simulator through the real azuread provider.
#
# Nothing here is simulator-specific except the provider's metadata_host: the same configuration
# would apply against a real tenant with that line removed. That is the property being tested —
# that a client can be pointed at the simulator by changing configuration only.

terraform {
  required_version = ">= 1.6"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

provider "azuread" {
  # The one hook the provider offers: it fetches /metadata/endpoints from here and reconfigures
  # every endpoint from the result. Set ARM_METADATA_HOSTNAME to the simulator's host and port,
  # and SSL_CERT_FILE to the CA it writes out.
  #
  # Credentials come from ARM_TENANT_ID, ARM_CLIENT_ID and ARM_CLIENT_SECRET.
}

# The provider's own documented starting point: read the tenant's initial domain and build
# principal names from it.
data "azuread_domains" "current" {
  only_initial = true
}

locals {
  domain = data.azuread_domains.current.domains[0].domain_name
}

# Microsoft Graph, looked up by its well-known client ID. Almost every real azuread
# configuration contains this, and it is how permission identifiers are resolved by name.
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_user" "engineer" {
  user_principal_name = "terraform-engineer@${local.domain}"
  display_name        = "Terraform Engineer"
  mail_nickname       = "terraform-engineer"
  password            = "Sup3rSecret!Passw0rd"
  job_title           = "Engineer"
}

resource "azuread_group" "platform" {
  display_name     = "Platform Engineering"
  description      = "Managed by Terraform against the simulator"
  security_enabled = true
}

resource "azuread_group_member" "engineer" {
  group_object_id  = azuread_group.platform.object_id
  member_object_id = azuread_user.engineer.object_id
}

# An app registration with API permissions resolved by name from the Graph service principal,
# which only works if the simulator publishes Graph's real permission identifiers.
resource "azuread_application" "deployer" {
  display_name     = "Terraform Deployer"
  sign_in_audience = "AzureADMyOrg"

  required_resource_access {
    resource_app_id = data.azuread_service_principal.msgraph.client_id

    resource_access {
      id   = data.azuread_service_principal.msgraph.app_role_ids["Application.ReadWrite.All"]
      type = "Role"
    }

    resource_access {
      id   = data.azuread_service_principal.msgraph.oauth2_permission_scope_ids["User.Read"]
      type = "Scope"
    }
  }

  web {
    redirect_uris = ["https://deployer.example.test/callback"]
  }
}

resource "azuread_service_principal" "deployer" {
  client_id = azuread_application.deployer.client_id
}

resource "azuread_application_password" "deployer" {
  application_id = azuread_application.deployer.id
  display_name   = "terraform-managed"
}

# Granting the permission the application asked for, which is what puts a value in the roles
# claim of a token issued to this principal.
resource "azuread_app_role_assignment" "deployer_graph" {
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["Application.ReadWrite.All"]
  principal_object_id = azuread_service_principal.deployer.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

output "client_id" {
  value = azuread_application.deployer.client_id
}

output "client_secret" {
  value     = azuread_application_password.deployer.value
  sensitive = true
}

output "group_members" {
  value = [azuread_group_member.engineer.member_object_id]
}
