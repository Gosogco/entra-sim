//! The objects the simulator registers for itself at startup.
//!
//! Two things have to exist before a client can do anything useful:
//!
//! - A client it can authenticate as. Without one the simulator is unusable from a cold start,
//!   because no caller could authenticate in order to create a caller.
//! - The Microsoft Graph resource itself, so that permissions can be requested against it.
//!   Terraform configurations name Graph's appId and its permission identifiers directly, and
//!   `data "azuread_service_principal"` on Graph is a fixture in almost every such
//!   configuration.

use time::{Duration, OffsetDateTime};

use crate::config::Config;
use crate::graph::permissions_catalogue;
use crate::store::Directory;
use crate::store::model::{
    Application, MICROSOFT_GRAPH_APP_ID, PasswordCredential, ServicePrincipal,
};

/// How long the bootstrap secret is valid. Long enough that a test suite never trips over it.
const SECRET_LIFETIME_YEARS: i64 = 10;

/// Register the Graph resource and the configured bootstrap client.
pub fn install(directory: &mut Directory, config: &Config) {
    install_microsoft_graph(directory);
    install_bootstrap_client(directory, config);
}

/// Register the Microsoft Graph service principal with its real permission catalogue.
///
/// Only the principal, not an application registration. In a real tenant Microsoft Graph is a
/// first-party application owned by Microsoft's own tenant, so `GET /applications` does not
/// return it; only the local service principal exists. Registering an application here would
/// both misrepresent the directory and put 700-odd app roles into every application listing.
fn install_microsoft_graph(directory: &mut Directory) {
    let (app_roles, oauth2_permission_scopes) = permissions_catalogue::load();

    // Built from a transient registration so the principal is assembled the same way as any
    // other, rather than through a second construction path that could drift.
    let mut definition = Application::new(
        String::new(),
        MICROSOFT_GRAPH_APP_ID.to_string(),
        "Microsoft Graph".to_string(),
    );
    definition.app_roles = app_roles;
    definition.oauth2_permission_scopes = oauth2_permission_scopes;
    definition.identifier_uris = vec!["https://graph.microsoft.com".to_string()];

    let mut principal = ServicePrincipal::for_application(
        deterministic_id(MICROSOFT_GRAPH_APP_ID, "servicePrincipal"),
        &definition,
    );
    // Entra marks first-party principals this way, and clients filter on it.
    principal.tags = vec!["HideApp".to_string()];

    directory
        .service_principals
        .insert(principal.id.clone(), principal);
}

/// Register the application the simulator hands out credentials for.
fn install_bootstrap_client(directory: &mut Directory, config: &Config) {
    let now = OffsetDateTime::now_utc();
    let app_id = config.bootstrap_client_id.clone();

    let mut application = Application::new(
        deterministic_id(&app_id, "application"),
        app_id.clone(),
        "entra-sim bootstrap client".to_string(),
    );
    application.password_credentials = vec![PasswordCredential {
        key_id: deterministic_id(&app_id, "secret"),
        display_name: Some("bootstrap secret".to_string()),
        hint: Some(hint(&config.bootstrap_client_secret)),
        start_date_time: now,
        end_date_time: now + Duration::days(365 * SECRET_LIFETIME_YEARS),
        secret_text: config.bootstrap_client_secret.clone(),
    }];

    let mut principal = ServicePrincipal::for_application(
        deterministic_id(&app_id, "servicePrincipal"),
        &application,
    );
    principal.granted_app_roles = config.bootstrap_app_roles.clone();

    directory
        .applications
        .insert(application.id.clone(), application);
    directory
        .service_principals
        .insert(principal.id.clone(), principal);
}

/// Derive a stable object ID from the client ID, so restarting with the same configuration
/// yields the same IDs and Terraform state written against them stays valid.
fn deterministic_id(app_id: &str, kind: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{kind}:{app_id}").as_bytes());
    // Format the first 16 bytes as a UUID, because clients parse these as GUIDs.
    let b = &digest[..16];
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Graph discloses only the first three characters of a secret after creation.
fn hint(secret: &str) -> String {
    secret.chars().take(3).collect()
}
