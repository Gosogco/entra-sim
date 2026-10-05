//! Graph directory entities.
//!
//! Each entity names the fields the simulator reasons about and keeps everything else in an
//! `extra` map. That matters for Terraform: the `azuread` provider writes many properties the
//! simulator has no opinion about, and silently dropping one would show up as a permanent diff
//! on every plan.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::serde::rfc3339;

/// The appId of the built-in Microsoft Graph service principal, which Terraform configurations
/// reference directly when declaring API permissions.
pub const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Directory object ID.
    pub id: String,
    pub user_principal_name: String,
    pub display_name: String,
    pub account_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(default)]
    pub user_type: Option<String>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
    /// Never serialised: Graph has no readable password property, and a password written through
    /// `passwordProfile` must not come back out on read.
    #[serde(skip)]
    pub password: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// Directory object ID.
    pub id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    pub mail_enabled: bool,
    pub security_enabled: bool,
    /// `Unified` marks a Microsoft 365 group; `DynamicMembership` a dynamic one.
    #[serde(default)]
    pub group_types: Vec<String>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
    /// Object IDs of the members.
    ///
    /// Not serialised with the group: Graph exposes members as a navigation property reached
    /// through `/members`, never as a property of the entity body.
    #[serde(skip)]
    pub members: Vec<String>,
    /// Object IDs of the owners, likewise a navigation property.
    #[serde(skip)]
    pub owners: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    /// Directory object ID.
    pub id: String,
    /// The client ID, which is what callers authenticate with.
    pub app_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_roles: Vec<AppRole>,
    /// Delegated permissions this application exposes, mirroring `api.oauth2PermissionScopes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth2_permission_scopes: Vec<PermissionScope>,
    /// Permissions this application requests from other applications.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_resource_access: Vec<RequiredResourceAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_credentials: Vec<PasswordCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_credentials: Vec<KeyCredential>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
    /// Object IDs of the owners, a navigation property reached through `/owners`.
    #[serde(skip)]
    pub owners: Vec<String>,
    /// Federated identity credentials, reached through their own navigation property.
    #[serde(skip)]
    pub federated_identity_credentials: Vec<FederatedIdentityCredential>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipal {
    pub id: String,
    /// The application this principal represents.
    pub app_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_roles: Vec<AppRole>,
    /// Delegated permissions, copied from the application when the principal is created.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth2_permission_scopes: Vec<PermissionScope>,
    /// The identifier URIs clients may use to address this principal, plus its appId.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_principal_names: Vec<String>,
    /// Whether a principal must hold an app role assignment before it can obtain a token.
    #[serde(default)]
    pub app_role_assignment_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_credentials: Vec<PasswordCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_credentials: Vec<KeyCredential>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
    /// Object IDs of the owners, a navigation property reached through `/owners`.
    #[serde(skip)]
    pub owners: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An app role defined by a resource application, such as `Application.ReadWrite.All` on Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRole {
    pub id: String,
    pub value: Option<String>,
    pub display_name: String,
    pub description: String,
    pub is_enabled: bool,
    /// `Application` for app-only roles, `User` for ones a user or group can hold.
    pub allowed_member_types: Vec<String>,
}

/// A delegated permission a resource application exposes, such as `User.Read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    pub id: String,
    pub value: Option<String>,
    pub admin_consent_display_name: String,
    pub admin_consent_description: String,
    #[serde(default)]
    pub user_consent_display_name: Option<String>,
    #[serde(default)]
    pub user_consent_description: Option<String>,
    pub is_enabled: bool,
    /// `Admin` when the permission needs admin consent, `User` otherwise.
    #[serde(rename = "type")]
    pub kind: String,
}

/// A block of permissions requested from one resource application.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredResourceAccess {
    /// The `appId` of the resource, such as Microsoft Graph.
    pub resource_app_id: String,
    pub resource_access: Vec<ResourceAccess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAccess {
    /// The ID of an app role or delegated scope on the resource.
    pub id: String,
    /// `Role` for an application permission, `Scope` for a delegated one.
    #[serde(rename = "type")]
    pub kind: String,
}

/// A trust relationship letting an external token stand in for a client secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIdentityCredential {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A client secret.
///
/// Graph returns `secretText` only in the response to `addPassword` and never again, so the
/// plaintext is kept out of serialisation and compared in place when a client authenticates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordCredential {
    pub key_id: String,
    pub display_name: Option<String>,
    /// The first three characters of the secret, which is all Graph discloses after creation.
    pub hint: Option<String>,
    #[serde(with = "rfc3339")]
    pub start_date_time: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub end_date_time: OffsetDateTime,
    #[serde(skip)]
    pub secret_text: String,
}

impl PasswordCredential {
    /// Whether `secret` matches and the credential is valid at `now`.
    pub fn accepts(&self, secret: &str, now: OffsetDateTime) -> bool {
        // Comparing in constant time would be theatre: this is a simulator holding fake secrets,
        // and the plaintext is in memory either way.
        self.secret_text == secret && self.start_date_time <= now && now < self.end_date_time
    }
}

/// A certificate credential, used for `private_key_jwt` client authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCredential {
    pub key_id: String,
    pub display_name: Option<String>,
    /// `AsymmetricX509Cert` in practice.
    #[serde(rename = "type")]
    pub kind: String,
    pub usage: String,
    /// Base64 DER certificate.
    pub key: Option<String>,
    #[serde(with = "rfc3339")]
    pub start_date_time: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub end_date_time: OffsetDateTime,
}

impl Application {
    /// A new registration with no credentials, permissions or owners.
    pub fn new(id: String, app_id: String, display_name: String) -> Self {
        Self {
            id,
            app_id,
            display_name,
            identifier_uris: Vec::new(),
            app_roles: Vec::new(),
            oauth2_permission_scopes: Vec::new(),
            required_resource_access: Vec::new(),
            // Entra's default for a new registration.
            sign_in_audience: Some("AzureADMyOrg".to_string()),
            password_credentials: Vec::new(),
            key_credentials: Vec::new(),
            created_date_time: OffsetDateTime::now_utc(),
            owners: Vec::new(),
            federated_identity_credentials: Vec::new(),
            extra: Map::new(),
        }
    }
}

impl ServicePrincipal {
    /// The principal Entra creates for an application registration.
    ///
    /// App roles and delegated permissions are copied from the application, because that is
    /// where they are defined and the principal is what other objects are assigned against.
    pub fn for_application(id: String, application: &Application) -> Self {
        let mut names = vec![application.app_id.clone()];
        names.extend(application.identifier_uris.iter().cloned());

        Self {
            id,
            app_id: application.app_id.clone(),
            display_name: application.display_name.clone(),
            app_roles: application.app_roles.clone(),
            oauth2_permission_scopes: application.oauth2_permission_scopes.clone(),
            service_principal_names: names,
            app_role_assignment_required: false,
            tags: Vec::new(),
            password_credentials: Vec::new(),
            key_credentials: Vec::new(),
            created_date_time: OffsetDateTime::now_utc(),
            owners: Vec::new(),
            extra: Map::new(),
        }
    }
}

/// A grant of one app role on a resource to one principal.
///
/// This is what puts a value in an app-only token's `roles` claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleAssignment {
    pub id: String,
    /// The `id` of an app role defined by the resource. The all-zero GUID means "no role",
    /// which Entra uses to grant access without granting a permission.
    pub app_role_id: String,
    /// Object ID of the user, group or service principal receiving the role.
    pub principal_id: String,
    pub principal_display_name: Option<String>,
    /// `User`, `Group` or `ServicePrincipal`.
    pub principal_type: String,
    /// Object ID of the service principal that defines the role.
    pub resource_id: String,
    pub resource_display_name: Option<String>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
}

/// Delegated permissions consented for a client against a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2PermissionGrant {
    pub id: String,
    /// Object ID of the client service principal.
    pub client_id: String,
    /// `AllPrincipals` for admin consent, `Principal` for one user.
    pub consent_type: String,
    /// Set only when `consentType` is `Principal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Object ID of the resource service principal.
    pub resource_id: String,
    /// Space-separated permission values, as Graph stores them.
    pub scope: String,
}

/// A directory role that has been activated in the tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRole {
    pub id: String,
    /// The built-in template this role was activated from.
    pub role_template_id: String,
    pub display_name: String,
    pub description: String,
    /// Object IDs of the members, a navigation property reached through `/members`.
    #[serde(skip)]
    pub members: Vec<String>,
}

/// A built-in role that can be activated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRoleTemplate {
    pub id: String,
    pub display_name: String,
    pub description: String,
}
