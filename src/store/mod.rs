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

use serde_json::Value;

use crate::store::model::MICROSOFT_GRAPH_APP_ID;
use crate::store::model::{
    AppRoleAssignment, Application, DirectoryRole, Group, OAuth2PermissionGrant,
    PasswordCredential, ServicePrincipal, User,
};

/// Everything the simulated tenant contains.
#[derive(Debug, Default)]
pub struct Directory {
    pub users: BTreeMap<String, User>,
    pub groups: BTreeMap<String, Group>,
    pub applications: BTreeMap<String, Application>,
    pub service_principals: BTreeMap<String, ServicePrincipal>,
    pub app_role_assignments: BTreeMap<String, AppRoleAssignment>,
    pub oauth2_permission_grants: BTreeMap<String, OAuth2PermissionGrant>,
    /// Directory roles that have been activated in this tenant.
    pub directory_roles: BTreeMap<String, DirectoryRole>,
}

impl Directory {
    pub fn user_by_principal_name(&self, upn: &str) -> Option<&User> {
        // Entra treats the user principal name as case-insensitive.
        self.users
            .values()
            .find(|user| user.user_principal_name.eq_ignore_ascii_case(upn))
    }

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

impl Directory {
    /// The Microsoft Graph service principal, which is the resource every Graph permission is
    /// defined on and assigned against.
    pub fn graph_service_principal(&self) -> Option<&ServicePrincipal> {
        self.service_principal_by_app_id(MICROSOFT_GRAPH_APP_ID)
    }

    /// The app role values granted to a principal on the Graph resource.
    ///
    /// This is what fills an app-only token's `roles` claim. Entra derives it by resolving the
    /// principal's app role assignments against the resource's defined roles, and so does this:
    /// an assignment naming a role the resource does not define grants nothing.
    pub fn granted_graph_role_values(&self, principal_id: &str) -> Vec<String> {
        let Some(resource) = self.graph_service_principal() else {
            return Vec::new();
        };

        let mut values: Vec<String> = self
            .app_role_assignments
            .values()
            .filter(|assignment| {
                assignment.principal_id == principal_id && assignment.resource_id == resource.id
            })
            .filter_map(|assignment| {
                resource
                    .app_roles
                    .iter()
                    .find(|role| role.id == assignment.app_role_id)
                    .and_then(|role| role.value.clone())
            })
            .collect();

        // A principal can hold the same role through more than one assignment; the claim lists
        // each value once.
        values.sort();
        values.dedup();
        values
    }
}

/// The Graph type name of a directory object, as it appears in an `@odata.type` annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    User,
    Group,
    ServicePrincipal,
}

impl ObjectKind {
    pub fn odata_type(self) -> &'static str {
        match self {
            Self::User => "#microsoft.graph.user",
            Self::Group => "#microsoft.graph.group",
            Self::ServicePrincipal => "#microsoft.graph.servicePrincipal",
        }
    }
}

impl Directory {
    /// Find any directory object by ID, whatever its type.
    ///
    /// Membership and role assignments refer to objects by ID without naming a collection, so
    /// resolving one means looking across every collection that can hold a principal.
    pub fn object(&self, id: &str) -> Option<(ObjectKind, Value)> {
        if let Some(user) = self.users.get(id) {
            return Some((ObjectKind::User, annotate(ObjectKind::User, user)));
        }
        if let Some(group) = self.groups.get(id) {
            return Some((ObjectKind::Group, annotate(ObjectKind::Group, group)));
        }
        if let Some(principal) = self.service_principals.get(id) {
            return Some((
                ObjectKind::ServicePrincipal,
                annotate(ObjectKind::ServicePrincipal, principal),
            ));
        }
        None
    }

    /// Whether an object with this ID exists in any collection.
    pub fn contains_object(&self, id: &str) -> bool {
        self.users.contains_key(id)
            || self.groups.contains_key(id)
            || self.service_principals.contains_key(id)
    }

    /// Every group the object belongs to directly.
    pub fn groups_containing(&self, id: &str) -> Vec<&Group> {
        self.groups
            .values()
            .filter(|group| group.members.iter().any(|member| member == id))
            .collect()
    }

    /// Members of a group, following nested groups.
    ///
    /// Nested groups appear in the result as well as their members, which is what Graph does.
    /// Cycles are possible in a simulated directory, so visited IDs are tracked.
    pub fn transitive_members(&self, group_id: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut pending = vec![group_id.to_string()];

        while let Some(current) = pending.pop() {
            let Some(group) = self.groups.get(&current) else {
                continue;
            };
            for member in &group.members {
                if !seen.insert(member.clone()) {
                    continue;
                }
                found.push(member.clone());
                if self.groups.contains_key(member) {
                    pending.push(member.clone());
                }
            }
        }
        found.sort();
        found
    }
}

fn annotate<T: serde::Serialize>(kind: ObjectKind, object: &T) -> Value {
    let mut value = serde_json::to_value(object).unwrap_or(Value::Null);
    if let Some(fields) = value.as_object_mut() {
        // A heterogeneous collection needs the type annotation for a client to tell a user from
        // a group.
        fields.insert(
            "@odata.type".to_string(),
            Value::String(kind.odata_type().to_string()),
        );
    }
    value
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
