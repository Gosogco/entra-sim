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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_credentials: Vec<PasswordCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_credentials: Vec<KeyCredential>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_credentials: Vec<PasswordCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_credentials: Vec<KeyCredential>,
    #[serde(with = "rfc3339")]
    pub created_date_time: OffsetDateTime,
    /// App role values granted to this principal on the Graph resource, which become the
    /// `roles` claim of its app-only tokens.
    ///
    /// Not part of Graph and never serialised: in Entra this is derived by resolving the
    /// principal's `appRoleAssignments` against the resource application's `appRoles`. It is
    /// stored pre-resolved until that machinery exists, so no invented property can leak into
    /// an API response.
    #[serde(skip)]
    pub granted_app_roles: Vec<String>,
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
