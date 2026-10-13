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
pub mod snapshot;

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use serde_json::Value;

use crate::store::model::MICROSOFT_GRAPH_APP_ID;
use crate::store::model::{
    AppRoleAssignment, Application, DirectoryRole, Group, OAuth2PermissionGrant, ServicePrincipal,
    User,
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
}

impl Directory {
    /// The Microsoft Graph service principal, which is the resource every Graph permission is
    /// defined on and assigned against.
    pub fn graph_service_principal(&self) -> Option<&ServicePrincipal> {
        self.service_principal_by_app_id(MICROSOFT_GRAPH_APP_ID)
    }

    /// The service principal of the API a scope's resource part names.
    ///
    /// Entra accepts an API's application ID URI or its `appId` there. The application's
    /// `identifierUris` are read rather than the principal's `servicePrincipalNames`, because
    /// they are what an administrator edits; principals with no registration in this tenant,
    /// such as Microsoft Graph, are found by their own names. `simulator_base_url` names Graph
    /// too, because the metadata document advertises it as Graph's resource identifier and
    /// the Terraform provider asks for exactly that.
    pub fn resource_for(&self, name: &str, simulator_base_url: &str) -> Option<&ServicePrincipal> {
        // Entra treats `api://orders` and `api://orders/` as the same resource.
        let name = name.trim_end_matches('/');
        if name == simulator_base_url.trim_end_matches('/') {
            return self.graph_service_principal();
        }

        let registered = self.applications.values().find(|application| {
            application.app_id.eq_ignore_ascii_case(name)
                || application
                    .identifier_uris
                    .iter()
                    .any(|uri| uri.trim_end_matches('/') == name)
        });
        if let Some(application) = registered {
            return self.service_principal_by_app_id(&application.app_id);
        }

        self.service_principals.values().find(|principal| {
            principal
                .service_principal_names
                .iter()
                .any(|known| known.trim_end_matches('/').eq_ignore_ascii_case(name))
        })
    }

    /// Whether a user may obtain a token for the application whose service principal is
    /// `resource_id`, when that application requires assignment.
    ///
    /// Microsoft: "If this option is set to Yes, then users and other applications or services
    /// must first be assigned this application before being able to access it", and "Users with
    /// a Global Administrator role can sign in to applications, regardless of the assignment
    /// required settings." Any assignment counts, including the default access role, and so does
    /// one made to a security group the user is a direct member of.
    pub fn user_may_access(&self, user_id: &str, resource_id: &str) -> bool {
        let Some(resource) = self.service_principals.get(resource_id) else {
            return true;
        };
        if !resource.app_role_assignment_required {
            return true;
        }
        if self
            .directory_roles_of(user_id)
            .iter()
            .any(|role| role.role_template_id == GLOBAL_ADMINISTRATOR_TEMPLATE_ID)
        {
            return true;
        }
        let mut holders = vec![user_id.to_string()];
        holders.extend(
            self.groups_containing(user_id)
                .into_iter()
                .filter(|group| group.security_enabled)
                .map(|group| group.id.clone()),
        );
        self.is_assigned(&holders, resource_id)
    }

    /// Whether an application may obtain an app-only token for the application whose service
    /// principal is `resource_id`, when that application requires assignment.
    pub fn app_may_access(&self, client_principal_id: &str, resource_id: &str) -> bool {
        self.service_principals
            .get(resource_id)
            .is_none_or(|resource| !resource.app_role_assignment_required)
            || self.is_assigned(&[client_principal_id.to_string()], resource_id)
    }

    fn is_assigned(&self, principal_ids: &[String], resource_id: &str) -> bool {
        self.app_role_assignments.values().any(|assignment| {
            assignment.resource_id == resource_id
                && principal_ids.contains(&assignment.principal_id)
        })
    }

    /// The registration of the application `app_id`: this tenant's, or one from `foreign`, the
    /// registrations held by other tenants.
    pub fn registration<'a>(
        &'a self,
        foreign: &'a [Application],
        app_id: &str,
    ) -> Option<&'a Application> {
        self.application_by_app_id(app_id).or_else(|| {
            foreign
                .iter()
                .find(|application| application.app_id == app_id)
        })
    }

    /// The app role values any of `principal_ids` holds on the resource `resource_id`.
    ///
    /// For an app-only token that is the client's own principal. For a user token it is the
    /// user and the groups the user is a direct member of, because Entra resolves role
    /// assignments made to a group for its members but does not follow nested groups.
    pub fn granted_role_values(&self, principal_ids: &[String], resource_id: &str) -> Vec<String> {
        let Some(resource) = self.service_principals.get(resource_id) else {
            return Vec::new();
        };

        let mut values: Vec<String> = self
            .app_role_assignments
            .values()
            .filter(|assignment| {
                assignment.resource_id == resource.id
                    && principal_ids.contains(&assignment.principal_id)
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

impl Directory {
    /// The grant through which `user_id` has consented to the client (a service principal ID)
    /// calling the resource: their own, or the tenant-wide one an administrator gave.
    pub fn user_grant(
        &self,
        client_id: &str,
        resource_id: &str,
        user_id: &str,
    ) -> Option<&OAuth2PermissionGrant> {
        self.oauth2_permission_grants.values().find(|grant| {
            grant.client_id == client_id
                && grant.resource_id == resource_id
                && (grant.consent_type == "AllPrincipals"
                    || grant.principal_id.as_deref() == Some(user_id))
        })
    }

    /// The delegated permissions currently consented for a client acting for one user.
    ///
    /// Read at the moment a token is issued rather than remembered from the sign-in, so that
    /// revoking a grant narrows the next token. Entra goes further and invalidates the refresh
    /// token outright; re-reading the directory reaches the same outcome by the shorter route.
    pub fn consented_scopes(
        &self,
        client_app_id: &str,
        user_id: &str,
        resource_id: &str,
    ) -> Vec<String> {
        let Some(client) = self.service_principal_by_app_id(client_app_id) else {
            return Vec::new();
        };

        let mut scopes: Vec<String> = self
            .oauth2_permission_grants
            .values()
            .filter(|grant| grant.client_id == client.id && grant.resource_id == resource_id)
            .filter(|grant| {
                // Tenant-wide consent covers every user; per-user consent covers only its own.
                grant.consent_type == "AllPrincipals"
                    || grant.principal_id.as_deref() == Some(user_id)
            })
            .flat_map(|grant| grant.scope.split_whitespace())
            .map(str::to_string)
            .collect();
        scopes.extend(self.preauthorized_scopes(client_app_id, resource_id));

        scopes.sort();
        scopes.dedup();
        scopes
    }

    /// The delegated permissions an API grants a client without consent, through its
    /// `api.preAuthorizedApplications`.
    ///
    /// Microsoft: "Resources can indicate that a given application always has permission to
    /// receive certain scopes", and "Preauthorized permissions always appear in the relevant
    /// token claims." The API's registration must be in this tenant for its list to be read.
    pub fn preauthorized_scopes(&self, client_app_id: &str, resource_id: &str) -> Vec<String> {
        let Some(resource) = self.service_principals.get(resource_id) else {
            return Vec::new();
        };
        let Some(api) = self
            .application_by_app_id(&resource.app_id)
            .and_then(|application| application.extra.get("api"))
        else {
            return Vec::new();
        };
        let permission_ids: Vec<&str> = api
            .get("preAuthorizedApplications")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("appId").and_then(Value::as_str) == Some(client_app_id))
            .filter_map(|entry| {
                entry
                    .get("delegatedPermissionIds")
                    .or(entry.get("permissionIds"))
            })
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        resource
            .oauth2_permission_scopes
            .iter()
            .filter(|scope| permission_ids.contains(&scope.id.as_str()))
            .filter_map(|scope| scope.value.clone())
            .collect()
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

    /// Every group the object belongs to, directly or through nested groups.
    ///
    /// Cycles are possible in a simulated directory, so visited IDs are tracked.
    pub fn transitive_groups_of(&self, id: &str) -> Vec<&Group> {
        let mut found: Vec<&Group> = Vec::new();
        let mut pending = vec![id.to_string()];
        while let Some(current) = pending.pop() {
            for group in self.groups_containing(&current) {
                if found.iter().any(|known| known.id == group.id) {
                    continue;
                }
                found.push(group);
                pending.push(group.id.clone());
            }
        }
        found.sort_by(|left, right| left.id.cmp(&right.id));
        found
    }

    /// The activated directory roles the object holds, directly or through a group it is a
    /// direct member of.
    pub fn directory_roles_of(&self, id: &str) -> Vec<&DirectoryRole> {
        let mut holders = vec![id.to_string()];
        holders.extend(
            self.groups_containing(id)
                .into_iter()
                .map(|group| group.id.clone()),
        );
        self.directory_roles
            .values()
            .filter(|role| role.members.iter().any(|member| holders.contains(member)))
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

/// The template ID of the built-in Global Administrator directory role.
pub const GLOBAL_ADMINISTRATOR_TEMPLATE_ID: &str = "62e90394-69f5-4237-9190-012177145e10";

/// The two access token formats Entra issues for a registered API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVersion {
    V1,
    V2,
}

impl TokenVersion {
    /// The version an API asks for in `api.requestedAccessTokenVersion`.
    ///
    /// Microsoft: "The values of `null` and `1` result in v1.0 tokens, and the value of `2`
    /// results in v2.0 tokens." An API with no registration has no setting, so it gets v1.0
    /// tokens as well.
    pub fn requested_by(registration: Option<&Application>) -> Self {
        let requested = registration
            .and_then(|application| application.extra.get("api"))
            .and_then(|api| api.get("requestedAccessTokenVersion"))
            .and_then(Value::as_u64);
        match requested {
            Some(2) => Self::V2,
            _ => Self::V1,
        }
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
    use time::{Duration, OffsetDateTime};

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
                .application_by_app_id(&config.bootstrap_client_id)
                .is_some_and(
                    |application| application.accepts_secret(&config.bootstrap_client_secret, now)
                )
        );
        assert!(
            !directory
                .application_by_app_id(&config.bootstrap_client_id)
                .is_some_and(|application| application.accepts_secret("wrong-secret", now))
        );
        assert!(
            !directory
                .application_by_app_id("22222222-2222-2222-2222-222222222222")
                .is_some_and(
                    |application| application.accepts_secret(&config.bootstrap_client_secret, now)
                ),
            "a secret must not authenticate a different client"
        );
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let (directory, config) = directory_with_bootstrap();
        let long_after = OffsetDateTime::now_utc() + Duration::days(365 * 50);

        assert!(
            !directory
                .application_by_app_id(&config.bootstrap_client_id)
                .is_some_and(|application| application
                    .accepts_secret(&config.bootstrap_client_secret, long_after)),
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

    /// A directory holding an API registration `Orders` and its service principal.
    fn directory_with_orders_api() -> (Directory, Config, String) {
        let (mut directory, config) = directory_with_bootstrap();
        let mut orders = model::Application::new(
            "orders-object".to_string(),
            "aaaaaaaa-0000-0000-0000-00000000000a".to_string(),
            "Orders".to_string(),
        );
        orders.identifier_uris = vec!["api://orders".to_string()];
        let principal = ServicePrincipal::for_application("orders-principal".to_string(), &orders);
        directory.applications.insert(orders.id.clone(), orders);
        directory
            .service_principals
            .insert(principal.id.clone(), principal);
        (directory, config, "orders-principal".to_string())
    }

    #[test]
    fn an_api_is_found_by_its_identifier_uri_or_app_id() {
        let (directory, config, orders) = directory_with_orders_api();
        let base = config.public_base_url();

        for name in [
            "api://orders",
            "api://orders/",
            "aaaaaaaa-0000-0000-0000-00000000000a",
        ] {
            assert_eq!(
                directory.resource_for(name, &base).map(|sp| sp.id.as_str()),
                Some(orders.as_str()),
                "{name} should name Orders"
            );
        }
    }

    #[test]
    fn graph_is_found_by_its_real_name_and_by_the_simulator_url() {
        let (directory, config, _) = directory_with_orders_api();
        let base = config.public_base_url();
        let graph = directory.graph_service_principal().unwrap().id.clone();

        for name in [
            "https://graph.microsoft.com",
            MICROSOFT_GRAPH_APP_ID,
            base.as_str(),
        ] {
            assert_eq!(
                directory.resource_for(name, &base).map(|sp| sp.id.clone()),
                Some(graph.clone()),
                "{name} should name Graph"
            );
        }
    }

    #[test]
    fn an_unknown_resource_is_not_found() {
        let (directory, config, _) = directory_with_orders_api();
        assert!(
            directory
                .resource_for("api://nothing-registered", &config.public_base_url())
                .is_none()
        );
    }

    #[test]
    fn an_identifier_uri_added_after_the_principal_still_resolves() {
        let (mut directory, config, orders) = directory_with_orders_api();
        // Terraform sets identifierUris in a separate PATCH after the principal exists, and the
        // principal's own names are not updated by that.
        directory
            .applications
            .get_mut("orders-object")
            .unwrap()
            .identifier_uris
            .push("https://orders.example.test".to_string());

        assert_eq!(
            directory
                .resource_for("https://orders.example.test", &config.public_base_url())
                .map(|sp| sp.id.as_str()),
            Some(orders.as_str())
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
