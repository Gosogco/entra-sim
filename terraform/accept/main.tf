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

# A certificate credential. The provider adds it by writing the application's whole
# keyCredentials list back, including the application's own id. The certificate is a
# self-signed one made for this test; its private key was never kept.
resource "azuread_application_certificate" "deployer" {
  application_id = azuread_application.deployer.id
  type           = "AsymmetricX509Cert"
  value          = <<-PEM
    -----BEGIN CERTIFICATE-----
    MIIDKzCCAhOgAwIBAgIUUlkkontG+G0j4nqFRqVS1E8hWugwDQYJKoZIhvcNAQEL
    BQAwJDEiMCAGA1UEAwwZZW50cmEtc2ltIGFjY2VwdGFuY2UgdGVzdDAgFw0yNjEw
    MTMxOTA2MjlaGA8yMTI2MDkxOTE5MDYyOVowJDEiMCAGA1UEAwwZZW50cmEtc2lt
    IGFjY2VwdGFuY2UgdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
    AKDjTe0cjaio/D8vVsT6IfolwIFrCm1ohdz3OQKmkib3v+VdDPO3FioSBaLLOrys
    mgcuUX1xY/VAkAuL5NlWxmYi/nsLmEdMSKJoopSq3m+i3S28NmHWiYXJIUsPOced
    SY1g1GqDKFeTssYKmp2JRy44d6fQEClJSokk2xDdFBkSyVaSKjIOws0NJ8B/XQQA
    48lUPiuHpTi5VPLFFZMjsisPjVdfPuryeYOzAPlEm8M7/yDfHqAl3kncmDnuUGzQ
    GLrJg1kZLf3Jy9ch/k9N95riiE5L26C6OJbz1SqH/vAGW7Y1MD/99u3P2aYzTXkO
    p/Htz8B0QUbt4uiydn+8zQkCAwEAAaNTMFEwHQYDVR0OBBYEFKyY9pTYvsqjcUF/
    vn7MoxyVJyyzMB8GA1UdIwQYMBaAFKyY9pTYvsqjcUF/vn7MoxyVJyyzMA8GA1Ud
    EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABkrT/Wbb4/8epNqE7eSrG8q
    dF9kxyUFQJj70VhxlaD7nCjHXkOposY4Ztt7vIWUttH/ZRz2cDAqV6kd3HpkbfAx
    261kkZsU2eXla9uxA9TyOlM8r7QY7ayTn/emhJs158R/9so99m0RwpHA45nQzOgt
    VbF7eoVTom6OuwYsuSFzGbySvSDkFq8x18Gxrv+tmpy2tz59bEGd9Al0g2CQKgAJ
    nIFA+h1NBPhQAtUNLkZlDp52pcxTKGFiewVIVgfJyUjI5A82+JDUsVEAHbizJ/zC
    gC9LNFwfHhAjt2Lg3dxxdXVxZLDoXCkoySUqB65i6YvhGplrMACcs+aPRWxriFg=
    -----END CERTIFICATE-----
  PEM
  end_date       = "2099-01-01T00:00:00Z"
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

# A conditional access policy in report-only mode, so it is evaluated and logged but never
# refuses a sign-in.
resource "azuread_conditional_access_policy" "legacy" {
  display_name = "Block legacy authentication"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [azuread_user.engineer.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# The engineer may activate User Administrator through Privileged Identity Management.
resource "azuread_directory_role_eligibility_schedule_request" "engineer" {
  role_definition_id = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  principal_id       = azuread_user.engineer.object_id
  directory_scope_id = "/"
  justification      = "On call for password resets"
}

# The engineer manages the users in the platform unit, and only those.
resource "azuread_directory_role" "user_administrator" {
  template_id = "fe930be7-5e62-47db-91af-98c3a49a38b1"
}

resource "azuread_user" "operator" {
  user_principal_name = "terraform-operator@${local.domain}"
  display_name        = "Terraform Operator"
  password            = "Sup3rSecret!Passw0rd"
}

resource "azuread_administrative_unit" "platform" {
  display_name = "Platform"
  description  = "Users the platform team manages"
}

resource "azuread_administrative_unit_member" "operator" {
  administrative_unit_object_id = azuread_administrative_unit.platform.object_id
  member_object_id              = azuread_user.operator.object_id
}

resource "azuread_administrative_unit_member" "platform" {
  administrative_unit_object_id = azuread_administrative_unit.platform.object_id
  member_object_id              = azuread_group.platform.object_id
}

resource "azuread_administrative_unit_role_member" "engineer" {
  administrative_unit_object_id = azuread_administrative_unit.platform.object_id
  role_object_id                = azuread_directory_role.user_administrator.object_id
  member_object_id              = azuread_user.engineer.object_id
}
