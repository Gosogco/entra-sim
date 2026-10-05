//! The application the simulator registers for itself at startup.
//!
//! Without this the simulator would be unusable on a fresh start: no client could authenticate,
//! so no client could create an application to authenticate as. Terraform in particular needs a
//! client ID and secret before it can do anything at all.

use time::{Duration, OffsetDateTime};

use crate::config::Config;
use crate::store::Directory;
use crate::store::model::{Application, PasswordCredential, ServicePrincipal};

/// How long the bootstrap secret is valid. Long enough that a test suite never trips over it.
const SECRET_LIFETIME_YEARS: i64 = 10;

/// Register the configured bootstrap client as an application and its service principal, the
/// same pair Entra creates when an app registration is given a service principal.
pub fn install(directory: &mut Directory, config: &Config) {
    let now = OffsetDateTime::now_utc();
    let app_id = config.bootstrap_client_id.clone();
    let display_name = "entra-sim bootstrap client".to_string();

    let credential = PasswordCredential {
        key_id: deterministic_id(&app_id, "secret"),
        display_name: Some("bootstrap secret".to_string()),
        hint: Some(hint(&config.bootstrap_client_secret)),
        start_date_time: now,
        end_date_time: now + Duration::days(365 * SECRET_LIFETIME_YEARS),
        secret_text: config.bootstrap_client_secret.clone(),
    };

    let application = Application {
        id: deterministic_id(&app_id, "application"),
        app_id: app_id.clone(),
        display_name: display_name.clone(),
        identifier_uris: Vec::new(),
        app_roles: Vec::new(),
        password_credentials: vec![credential],
        key_credentials: Vec::new(),
        created_date_time: now,
        extra: Default::default(),
    };

    let service_principal = ServicePrincipal {
        id: deterministic_id(&app_id, "servicePrincipal"),
        app_id: app_id.clone(),
        display_name,
        app_roles: Vec::new(),
        password_credentials: Vec::new(),
        key_credentials: Vec::new(),
        created_date_time: now,
        extra: Default::default(),
    };

    directory
        .applications
        .insert(application.id.clone(), application);
    directory
        .service_principals
        .insert(service_principal.id.clone(), service_principal);
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
