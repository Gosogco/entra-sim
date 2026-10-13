# Five users, two applications that each define three app roles, and a mix of assignments from
# the users to those roles.
#
# The provider is pinned to the simulator on localhost:8443, so this configuration never reaches
# Microsoft. run.sh starts the simulator and applies it.

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
  # The provider fetches /metadata/endpoints from this host and takes every other endpoint from
  # it. The credentials are the simulator's bootstrap client.
  metadata_host = "localhost:8443"
  tenant_id     = "00000000-0000-0000-0000-000000000001"
  client_id     = "11111111-1111-1111-1111-111111111111"
  client_secret = "entra-sim-bootstrap-secret"
}

# User principal names are built from the tenant's initial domain, so the same configuration
# works whatever domain the directory has.
data "azuread_domains" "current" {
  only_initial = true
}

locals {
  domain = data.azuread_domains.current.domains[0].domain_name

  users = {
    alice = "Alice Anders"
    bob   = "Bob Brown"
    carol = "Carol Chen"
    dave  = "Dave Diaz"
    erin  = "Erin Evans"
  }

  # Role IDs are fixed rather than generated, so they stay the same from one plan to the next.
  apps = {
    orders = {
      display_name = "Orders"
      roles = {
        Reader = "4498124a-03bc-4812-ac13-ee626b9cebd8"
        Writer = "d68b1e79-2ac2-416d-b886-d5d0aa64893d"
        Admin  = "55ea6997-493d-4a73-838a-a885fd0dd1ec"
      }
    }
    inventory = {
      display_name = "Inventory"
      roles = {
        Reader = "d9b033f9-edb4-4cd8-914b-645c0f1d837f"
        Writer = "915ffa78-cd25-4492-b28e-c63e4c3c5e67"
        Admin  = "3925205a-7819-4eb4-87e1-4d35b9ef741b"
      }
    }
  }

  # Each entry is user/app/role. Erin has no roles.
  assignments = toset([
    "alice/orders/Admin",
    "alice/inventory/Admin",
    "bob/orders/Writer",
    "bob/inventory/Reader",
    "carol/orders/Reader",
    "dave/inventory/Writer",
    "dave/inventory/Reader",
  ])
}

resource "azuread_user" "this" {
  for_each = local.users

  user_principal_name = "${each.key}@${local.domain}"
  display_name        = each.value
  mail_nickname       = each.key
  password            = "Sup3rSecret!Passw0rd"
}

resource "azuread_application" "this" {
  for_each = local.apps

  display_name     = each.value.display_name
  sign_in_audience = "AzureADMyOrg"
  # The name clients ask for a token with: api://orders/.default.
  identifier_uris = ["api://${each.key}"]

  dynamic "app_role" {
    for_each = each.value.roles

    content {
      id                   = app_role.value
      value                = app_role.key
      display_name         = app_role.key
      description          = "${app_role.key} access to ${each.value.display_name}"
      allowed_member_types = ["User"]
      enabled              = true
    }
  }
}

# Roles are assigned on the service principal, not on the application.
resource "azuread_service_principal" "this" {
  for_each = local.apps

  client_id = azuread_application.this[each.key].client_id
}

# A public client that users sign in through, so token.sh can show what a user's token for
# Orders or Inventory carries.
resource "azuread_application" "viewer" {
  display_name     = "Role viewer"
  sign_in_audience = "AzureADMyOrg"

  public_client {
    redirect_uris = ["http://localhost/callback"]
  }
}

resource "azuread_service_principal" "viewer" {
  client_id = azuread_application.viewer.client_id
}

resource "azuread_app_role_assignment" "this" {
  for_each = local.assignments

  principal_object_id = azuread_user.this[split("/", each.key)[0]].object_id
  resource_object_id  = azuread_service_principal.this[split("/", each.key)[1]].object_id
  app_role_id         = local.apps[split("/", each.key)[1]].roles[split("/", each.key)[2]]
}

output "assignments" {
  description = "For each user, the roles assigned to them, as App.Role."
  value = {
    for user in keys(local.users) : "${user}@${local.domain}" => sort([
      for assignment in local.assignments :
      "${local.apps[split("/", assignment)[1]].display_name}.${split("/", assignment)[2]}"
      if split("/", assignment)[0] == user
    ])
  }
}

output "user_ids" {
  description = "Object ID of each user, which token.sh signs in as."
  value       = { for user, resource in azuread_user.this : user => resource.object_id }
}

output "viewer_client_id" {
  description = "Client ID of the public client token.sh signs in through."
  value       = azuread_application.viewer.client_id
}
