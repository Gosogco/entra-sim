# The directory objects the React example needs.
#
# This configuration is the same for both targets. Against the simulator, set
# ARM_METADATA_HOSTNAME. Against a real tenant, unset it. Nothing here is simulator-specific.

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
  # ARM_CLIENT_SECRET, and ARM_METADATA_HOSTNAME for the simulator.
}

variable "redirect_uri" {
  description = "Where the browser is sent back to after sign-in. Must match the dev server."
  type        = string
  # The trailing slash is required. The provider rejects a redirect URI with no path segment,
  # and Entra matches a redirect URI exactly, so the app must send the same string.
  default     = "http://localhost:5173/"
}

variable "user_principal_name" {
  description = "The user to sign in as."
  type        = string
  default     = "alice@example.test"
}

variable "create_user" {
  description = <<-DESC
    Whether to create the user.

    True for the simulator, where the directory starts empty. False for a real tenant, where the
    account already exists and belongs to a person: Terraform would either fail on a conflict or,
    worse, take over managing a real account and delete it on destroy.
  DESC
  type        = bool
  default     = true
}

variable "user_password" {
  description = "Initial password for the created user. Only used when create_user is true."
  type        = string
  default     = "Sup3rSecret!Passw0rd"
  sensitive   = true
}

# Microsoft Graph, by its well-known client ID. This is how permissions are resolved by name
# instead of by GUID, and it works against the simulator because the simulator publishes Graph's
# real permission identifiers.
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

data "azuread_client_config" "current" {}

resource "azuread_application" "spa" {
  display_name     = "entra-sim React example"
  sign_in_audience = "AzureADMyOrg"

  # `spa` rather than `web`. A browser client registers here, and in a real tenant this is what
  # makes Entra allow the cross-origin call to the token endpoint at all.
  single_page_application {
    redirect_uris = [var.redirect_uri]
  }

  required_resource_access {
    resource_app_id = data.azuread_service_principal.msgraph.client_id

    resource_access {
      # Delegated, not application: the site acts for a signed-in user.
      id   = data.azuread_service_principal.msgraph.oauth2_permission_scope_ids["User.Read"]
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "spa" {
  client_id = azuread_application.spa.client_id
}

resource "azuread_user" "signin" {
  count = var.create_user ? 1 : 0

  user_principal_name = var.user_principal_name
  display_name        = "Alice Example"
  mail_nickname       = split("@", var.user_principal_name)[0]
  password            = var.user_password
}

# Admin consent for User.Read, so the first sign-in does not have to stop at a consent step.
# The simulator derives a delegated token's scopes from exactly this object.
resource "azuread_service_principal_delegated_permission_grant" "user_read" {
  service_principal_object_id          = azuread_service_principal.spa.object_id
  resource_service_principal_object_id = data.azuread_service_principal.msgraph.object_id
  claim_values                         = ["User.Read"]
}

output "client_id" {
  description = "VITE_CLIENT_ID for the React app."
  value       = azuread_application.spa.client_id
}

output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "user_principal_name" {
  description = "The account to sign in as."
  value       = var.user_principal_name
}

output "env" {
  description = <<-DESC
    The app configuration for this target. Write it to examples/react-spa/.env:

        terraform output -raw env > ../.env
  DESC
  value = join("\n", concat(
    [
      "VITE_CLIENT_ID=${azuread_application.spa.client_id}",
      "VITE_AUTHORITY=${local.authority}",
      "VITE_GRAPH_BASE=${local.graph_base}",
      "VITE_SCOPES=User.Read",
    ],
    # Only the simulator needs the instance-discovery answer supplied inline. Against a real
    # tenant MSAL should use Microsoft's own service, so the value is left out.
    local.is_simulator ? ["VITE_CLOUD_DISCOVERY_METADATA=${local.cloud_discovery_metadata}"] : [],
  ))
}

locals {
  simulator_host = coalesce(var.simulator_host, "")
  is_simulator   = local.simulator_host != ""

  authority = local.is_simulator ? "https://${local.simulator_host}/${data.azuread_client_config.current.tenant_id}" : "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}"

  graph_base = local.is_simulator ? "https://${local.simulator_host}" : "https://graph.microsoft.com"

  cloud_discovery_metadata = jsonencode({
    tenant_discovery_endpoint = "${local.authority}/v2.0/.well-known/openid-configuration"
    "api-version"             = "1.1"
    metadata = [{
      preferred_network = local.simulator_host
      preferred_cache   = local.simulator_host
      aliases           = [local.simulator_host]
    }]
  })
}

variable "simulator_host" {
  description = <<-DESC
    Host and port of the simulator, for example localhost:8443. Leave null for a real tenant.

    Set it to the same value as ARM_METADATA_HOSTNAME, through TF_VAR_simulator_host. The
    generated .env has to know which target it describes, and Terraform cannot read
    ARM_METADATA_HOSTNAME itself.
  DESC
  type        = string
  default     = null
}
