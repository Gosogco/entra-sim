//! The permissions Microsoft Graph exposes.
//!
//! Terraform configurations name these identifiers directly, for example
//!
//! ```hcl
//! required_resource_access {
//!   resource_app_id = "00000003-0000-0000-c000-000000000000"
//!   resource_access {
//!     id   = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"  # Application.ReadWrite.All
//!     type = "Role"
//!   }
//! }
//! ```
//!
//! so the simulator has to know the real values; invented ones would break real configurations.
//! The catalogue is generated from Microsoft's own permissions reference by
//! `scripts/generate-graph-permissions.py` and embedded, so the simulator needs no network
//! access and no tenant to be useful.

use serde::Deserialize;

use crate::store::model::{AppRole, PermissionScope};

const CATALOGUE: &str = include_str!("graph_permissions.json");

#[derive(Debug, Deserialize)]
struct Catalogue {
    #[serde(rename = "appRoles")]
    app_roles: Vec<AppRole>,
    #[serde(rename = "oauth2PermissionScopes")]
    oauth2_permission_scopes: Vec<PermissionScope>,
}

/// Parse the embedded catalogue.
///
/// Panics if it fails to parse: the file is compiled in and covered by a test, so a failure here
/// means the binary itself is broken rather than that the operator did something wrong.
pub fn load() -> (Vec<AppRole>, Vec<PermissionScope>) {
    let catalogue: Catalogue = serde_json::from_str(CATALOGUE)
        .expect("the embedded Graph permission catalogue should parse");
    (catalogue.app_roles, catalogue.oauth2_permission_scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_catalogue_parses_and_is_complete() {
        let (roles, scopes) = load();
        // A truncated or malformed file would otherwise only surface at runtime.
        assert!(roles.len() > 500, "only {} app roles", roles.len());
        assert!(scopes.len() > 500, "only {} scopes", scopes.len());
    }

    #[test]
    fn the_catalogue_carries_the_real_entra_identifiers() {
        let (roles, scopes) = load();

        // Spot-checked against Microsoft's published permissions reference. These exact values
        // appear in real Terraform configurations.
        let role = |value: &str| {
            roles
                .iter()
                .find(|role| role.value.as_deref() == Some(value))
                .unwrap_or_else(|| panic!("{value} should be in the catalogue"))
                .id
                .clone()
        };
        assert_eq!(
            role("Application.ReadWrite.All"),
            "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
        );
        assert_eq!(
            role("Directory.Read.All"),
            "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        );
        assert_eq!(
            role("Group.ReadWrite.All"),
            "62a82d76-70ea-41e2-9197-370581804d09"
        );

        let user_read = scopes
            .iter()
            .find(|scope| scope.value.as_deref() == Some("User.Read"))
            .expect("User.Read should be in the catalogue");
        assert_eq!(user_read.id, "e1fe6dd8-ba31-4d61-89e7-88639da4683d");
    }

    #[test]
    fn every_identifier_is_a_guid() {
        let (roles, scopes) = load();
        let is_guid = |id: &str| {
            id.len() == 36
                && id.chars().enumerate().all(|(index, ch)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        ch == '-'
                    } else {
                        ch.is_ascii_hexdigit()
                    }
                })
        };
        for role in &roles {
            assert!(is_guid(&role.id), "app role {:?} is not a GUID", role.id);
        }
        for scope in &scopes {
            assert!(is_guid(&scope.id), "scope {:?} is not a GUID", scope.id);
        }
    }

    #[test]
    fn app_roles_are_application_permissions() {
        let (roles, _) = load();
        for role in &roles {
            assert_eq!(
                role.allowed_member_types,
                vec!["Application".to_string()],
                "{:?} should be an application permission",
                role.value
            );
        }
    }
}
