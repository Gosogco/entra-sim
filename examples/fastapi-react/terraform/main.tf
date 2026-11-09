# The directory objects the FastAPI example needs: an API with two app roles and a delegated
# scope, the React site that signs users in to it, three users with different roles, and two
# daemon applications, one with a role and one without.
#
# The API and both daemons authenticate with certificates, which run.sh generates in ../certs.

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
  # Credentials and the target come from the environment: ARM_TENANT_ID, ARM_CLIENT_ID,
  # ARM_CLIENT_SECRET and ARM_METADATA_HOSTNAME.
}

variable "simulator_host" {
  description = "Host and port of the simulator. Must match ARM_METADATA_HOSTNAME."
  type        = string
  default     = "localhost:8443"
}

variable "redirect_uri" {
  description = "Where the browser is sent back to after sign-in. Must match the dev server."
  type        = string
  # The trailing slash is required. The provider rejects a redirect URI with no path segment,
  # and Entra matches a redirect URI exactly, so the site must send the same string.
  default     = "http://localhost:5174/"
}

data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

data "azuread_client_config" "current" {}

# User principal names are built from the tenant's initial domain, so the same configuration
# works whatever domain the directory has.
data "azuread_domains" "current" {
  only_initial = true
}

locals {
  domain    = data.azuread_domains.current.domains[0].domain_name
  tenant_id = data.azuread_client_config.current.tenant_id
  authority = "https://${var.simulator_host}/${local.tenant_id}"

  # IDs are fixed rather than generated, so they stay the same from one plan to the next.
  role_ids = {
    "Orders.Read"  = "57885335-8c2f-4e6a-a191-fdae617fbdbb"
    "Orders.Write" = "a2db8620-f7c9-4015-8cb8-c5e734946b19"
  }
  access_as_user_id = "337e85f5-d509-4f7c-9910-aa4254a9959d"

  users = {
    alice = "Alice Anders"
    bob   = "Bob Brown"
    carol = "Carol Chen"
  }

  daemons = toset(["reporter", "intruder"])
}

# The API the backend serves.
resource "azuread_application" "api" {
  display_name     = "entra-sim FastAPI example API"
  sign_in_audience = "AzureADMyOrg"
  identifier_uris  = ["api://orders-api"]

  api {
    # v2.0 tokens carry the API's client ID as aud and the simulator's address in iss, which is
    # what the backend checks.
    requested_access_token_version = 2

    oauth2_permission_scope {
      id                         = local.access_as_user_id
      value                      = "access_as_user"
      type                       = "User"
      admin_consent_display_name = "Access the orders API"
      admin_consent_description  = "Call the orders API as the signed-in user."
      user_consent_display_name  = "Access the orders API"
      user_consent_description   = "Call the orders API as you."
      enabled                    = true
    }
  }

  dynamic "app_role" {
    for_each = local.role_ids

    content {
      id    = app_role.value
      value = app_role.key
      # Both users and daemons can hold the roles. A user's role arrives in a delegated token,
      # a daemon's in an app-only token, and the backend checks them the same way.
      allowed_member_types = ["User", "Application"]
      display_name         = app_role.key
      description          = "${app_role.key} on the orders API"
      enabled              = true
    }
  }

  # The backend calls Graph's /me on behalf of the signed-in user.
  required_resource_access {
    resource_app_id = data.azuread_service_principal.msgraph.client_id

    resource_access {
      id   = data.azuread_service_principal.msgraph.oauth2_permission_scope_ids["User.Read"]
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "api" {
  client_id = azuread_application.api.client_id
}

# The backend's certificate, for the on-behalf-of call.
resource "azuread_application_certificate" "api" {
  application_id = azuread_application.api.id
  type           = "AsymmetricX509Cert"
  value          = file("${path.module}/../certs/api.pem")
}

# On-behalf-of has no user interaction, so the consent for the API to call Graph has to exist up
# front. Without it the token endpoint answers AADSTS65001.
resource "azuread_service_principal_delegated_permission_grant" "api_graph" {
  service_principal_object_id          = azuread_service_principal.api.object_id
  resource_service_principal_object_id = data.azuread_service_principal.msgraph.object_id
  claim_values                         = ["User.Read"]
}

# The React site.
resource "azuread_application" "spa" {
  display_name     = "entra-sim FastAPI example SPA"
  sign_in_audience = "AzureADMyOrg"

  single_page_application {
    redirect_uris = [var.redirect_uri]
  }

  required_resource_access {
    resource_app_id = azuread_application.api.client_id

    resource_access {
      id   = local.access_as_user_id
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "spa" {
  client_id = azuread_application.spa.client_id
}

# Admin consent for access_as_user, so a sign-in does not stop at a consent step. The token's scp
# claim comes from this grant.
resource "azuread_service_principal_delegated_permission_grant" "spa_api" {
  service_principal_object_id          = azuread_service_principal.spa.object_id
  resource_service_principal_object_id = azuread_service_principal.api.object_id
  claim_values                         = ["access_as_user"]
}

resource "azuread_user" "this" {
  for_each = local.users

  user_principal_name = "${each.key}@${local.domain}"
  display_name        = each.value
  mail_nickname       = each.key
  password            = "Sup3rSecret!Passw0rd"
}

# Alice holds both roles through this group. Bob holds Orders.Read directly. Carol holds nothing.
resource "azuread_group" "order_managers" {
  display_name     = "Order managers"
  security_enabled = true
}

resource "azuread_group_member" "alice" {
  group_object_id  = azuread_group.order_managers.object_id
  member_object_id = azuread_user.this["alice"].object_id
}

resource "azuread_app_role_assignment" "order_managers" {
  for_each = local.role_ids

  app_role_id         = each.value
  principal_object_id = azuread_group.order_managers.object_id
  resource_object_id  = azuread_service_principal.api.object_id
}

resource "azuread_app_role_assignment" "bob_read" {
  app_role_id         = local.role_ids["Orders.Read"]
  principal_object_id = azuread_user.this["bob"].object_id
  resource_object_id  = azuread_service_principal.api.object_id
}

# Two daemons. The reporter holds Orders.Read. The intruder holds nothing: the API does not
# require assignment, so the intruder still gets a token, without roles, and the backend refuses
# it.
resource "azuread_application" "daemon" {
  for_each = local.daemons

  display_name     = "entra-sim FastAPI example ${each.key}"
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "daemon" {
  for_each = local.daemons

  client_id = azuread_application.daemon[each.key].client_id
}

resource "azuread_application_certificate" "daemon" {
  for_each = local.daemons

  application_id = azuread_application.daemon[each.key].id
  type           = "AsymmetricX509Cert"
  value          = file("${path.module}/../certs/${each.key}.pem")
}

resource "azuread_app_role_assignment" "reporter_read" {
  app_role_id         = local.role_ids["Orders.Read"]
  principal_object_id = azuread_service_principal.daemon["reporter"].object_id
  resource_object_id  = azuread_service_principal.api.object_id
}

output "user_ids" {
  description = "Object ID of each user, for signing in without a browser."
  value       = { for user, resource in azuread_user.this : user => resource.object_id }
}

output "env" {
  description = <<-DESC
    The configuration for the backend, the daemons and the site. run.sh writes it to ../.env:

        terraform output -raw env > ../.env
  DESC
  value = join("\n", [
    "TENANT_ID=${local.tenant_id}",
    "AUTHORITY=${local.authority}",
    "API_CLIENT_ID=${azuread_application.api.client_id}",
    "GRAPH_BASE=https://${var.simulator_host}",
    "REPORTER_CLIENT_ID=${azuread_application.daemon["reporter"].client_id}",
    "INTRUDER_CLIENT_ID=${azuread_application.daemon["intruder"].client_id}",
    "VITE_CLIENT_ID=${azuread_application.spa.client_id}",
    "VITE_AUTHORITY=${local.authority}",
    "VITE_API_SCOPE=api://orders-api/access_as_user",
    "VITE_CLOUD_DISCOVERY_METADATA=${jsonencode({
      tenant_discovery_endpoint = "${local.authority}/v2.0/.well-known/openid-configuration"
      "api-version"             = "1.1"
      metadata = [{
        preferred_network = var.simulator_host
        preferred_cache   = var.simulator_host
        aliases           = [var.simulator_host]
      }]
    })}",
  ])
}
