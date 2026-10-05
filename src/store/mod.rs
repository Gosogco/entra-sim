//! The in-memory directory.
//!
//! Collections are `BTreeMap`s keyed by object ID so that listing order is deterministic, which
//! is what makes `$skiptoken` paging stable across requests.
//!
//! Lookups by a secondary key, such as finding an application by its `appId`, scan the
//! collection. A simulated tenant holds tens or hundreds of objects, so an index would buy
//! nothing and would be one more thing to keep consistent.

pub mod bootstrap;
pub mod model;

use std::collections::BTreeMap;
use std::sync::Arc;

use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::store::model::{Application, PasswordCredential, ServicePrincipal};

/// Everything the simulated tenant contains.
#[derive(Debug, Default)]
pub struct Directory {
    pub applications: BTreeMap<String, Application>,
    pub service_principals: BTreeMap<String, ServicePrincipal>,
}

impl Directory {
    pub fn application_by_app_id(&self, app_id: &str) -> Option<&Application> {
        self.applications.values().find(|a| a.app_id == app_id)
    }

    pub fn service_principal_by_app_id(&self, app_id: &str) -> Option<&ServicePrincipal> {
        self.service_principals
            .values()
            .find(|sp| sp.app_id == app_id)
    }

    /// Find the credential matching `secret` for the client `app_id`, if any.
    ///
    /// Secrets live on the application, matching Entra: an app registration owns its
    /// credentials and the service principal is what the resulting token represents.
    pub fn matching_credential(
        &self,
        app_id: &str,
        secret: &str,
        now: OffsetDateTime,
    ) -> Option<&PasswordCredential> {
        self.application_by_app_id(app_id)?
            .password_credentials
            .iter()
            .find(|credential| credential.accepts(secret, now))
    }
}

/// Shared handle to the directory.
pub type Store = Arc<RwLock<Directory>>;

pub fn new_store(directory: Directory) -> Store {
    Arc::new(RwLock::new(directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use clap::Parser;
    use time::Duration;

    fn directory_with_bootstrap() -> (Directory, Config) {
        let config = Config::parse_from(["entra-sim"]);
        let mut directory = Directory::default();
        bootstrap::install(&mut directory, &config);
        (directory, config)
    }

    #[test]
    fn bootstrap_registers_an_application_and_its_service_principal() {
        let (directory, config) = directory_with_bootstrap();

        let application = directory
            .application_by_app_id(&config.bootstrap_client_id)
            .expect("the bootstrap application should exist");
        let principal = directory
            .service_principal_by_app_id(&config.bootstrap_client_id)
            .expect("the bootstrap service principal should exist");

        // They share an appId but are distinct directory objects, as in Entra.
        assert_eq!(application.app_id, principal.app_id);
        assert_ne!(application.id, principal.id);
    }

    #[test]
    fn the_configured_secret_authenticates_the_bootstrap_client() {
        let (directory, config) = directory_with_bootstrap();
        let now = OffsetDateTime::now_utc();

        assert!(
            directory
                .matching_credential(
                    &config.bootstrap_client_id,
                    &config.bootstrap_client_secret,
                    now
                )
                .is_some()
        );
        assert!(
            directory
                .matching_credential(&config.bootstrap_client_id, "wrong-secret", now)
                .is_none()
        );
        assert!(
            directory
                .matching_credential(
                    "22222222-2222-2222-2222-222222222222",
                    &config.bootstrap_client_secret,
                    now
                )
                .is_none(),
            "a secret must not authenticate a different client"
        );
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let (directory, config) = directory_with_bootstrap();
        let long_after = OffsetDateTime::now_utc() + Duration::days(365 * 50);

        assert!(
            directory
                .matching_credential(
                    &config.bootstrap_client_id,
                    &config.bootstrap_client_secret,
                    long_after
                )
                .is_none(),
            "a credential past its endDateTime must not authenticate"
        );
    }

    #[test]
    fn the_stored_secret_is_never_serialised() {
        let (directory, config) = directory_with_bootstrap();
        let application = directory
            .application_by_app_id(&config.bootstrap_client_id)
            .unwrap();

        // Graph discloses secretText only in the addPassword response, never on read.
        let json = serde_json::to_string(application).expect("serialising the application");
        assert!(
            !json.contains(&config.bootstrap_client_secret),
            "the plaintext secret leaked into {json}"
        );
        assert!(
            json.contains(r#""hint""#),
            "the hint should still be published"
        );
    }

    #[test]
    fn object_ids_are_stable_for_a_given_client_id() {
        let (first, _) = directory_with_bootstrap();
        let (second, _) = directory_with_bootstrap();

        // Restarting with the same configuration must not invalidate Terraform state that
        // already refers to these object IDs.
        assert_eq!(
            first.applications.keys().collect::<Vec<_>>(),
            second.applications.keys().collect::<Vec<_>>()
        );
    }
}
