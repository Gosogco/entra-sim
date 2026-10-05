//! Per-endpoint permission enforcement.
//!
//! The requirements are generated from Microsoft's own published permission tables by
//! `scripts/generate-permission-requirements.py`, so the simulator refuses and permits the same
//! calls the real service does. Writing them by hand would mean enforcing a plausible-looking
//! policy that differs from Graph in ways a client only discovers in production.
//!
//! A requirement is a disjunction of conjunctions: Graph documents alternatives such as
//! `AppRoleAssignment.ReadWrite.All and Application.Read.All` or `Application.ReadWrite.All`,
//! and the caller satisfies the endpoint by holding every permission in any one alternative.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

use crate::auth::token::AccessTokenClaims;
use crate::graph::VERSIONS;

const REQUIREMENTS: &str = include_str!("permission_requirements.json");

#[derive(Debug, Deserialize)]
struct Requirement {
    method: String,
    path: String,
    /// Alternatives acceptable for an app-only token, read from its `roles` claim.
    roles: Vec<Vec<String>>,
    /// Alternatives acceptable for a delegated token, read from its `scp` claim.
    scopes: Vec<Vec<String>>,
}

/// What an endpoint demands.
pub struct Demanded {
    pub roles: Vec<Vec<String>>,
    pub scopes: Vec<Vec<String>>,
}

static TABLE: LazyLock<HashMap<(String, String), Demanded>> = LazyLock::new(|| {
    let parsed: Vec<Requirement> = serde_json::from_str(REQUIREMENTS)
        .expect("the embedded permission requirement table should parse");
    parsed
        .into_iter()
        .map(|requirement| {
            (
                (requirement.method, requirement.path),
                Demanded {
                    roles: requirement.roles,
                    scopes: requirement.scopes,
                },
            )
        })
        .collect()
});

/// The requirement for a matched route, if the table covers it.
///
/// `matched_path` is the route pattern axum matched, including the version prefix, which is
/// stripped here because the simulator serves one object model under both.
pub fn demanded(method: &str, matched_path: &str) -> Option<&'static Demanded> {
    let path = strip_version(matched_path);
    TABLE.get(&(method.to_string(), path.to_string()))
}

fn strip_version(matched_path: &str) -> &str {
    for version in VERSIONS {
        if let Some(rest) = matched_path.strip_prefix(version) {
            return rest;
        }
    }
    matched_path
}

/// Whether the caller's token satisfies the requirement.
///
/// An app-only token is judged on its roles and a delegated one on its scopes, because the two
/// are different permission sets in Entra and holding a delegated scope does not grant the
/// app-only equivalent.
pub fn satisfied(demanded: &Demanded, claims: &AccessTokenClaims) -> bool {
    let (held, alternatives) = if claims.scp.is_some() {
        (delegated_scopes(claims), &demanded.scopes)
    } else {
        (claims.roles.clone(), &demanded.roles)
    };

    // An endpoint with no acceptable alternative for this token type cannot be satisfied by it.
    alternatives.iter().any(|alternative| {
        alternative
            .iter()
            .all(|required| held.iter().any(|permission| grants(permission, required)))
    })
}

/// Whether holding `permission` satisfies a requirement for `required`.
///
/// Beyond an exact match, a write permission grants the matching read permission:
/// `Directory.ReadWrite.All` serves a caller anywhere `Directory.Read.All` is demanded. Entra
/// behaves this way, but the published tables list the two separately, so an endpoint
/// documented as needing only the read permission would otherwise refuse a caller holding the
/// write one — a refusal the real service would not make.
fn grants(permission: &str, required: &str) -> bool {
    if permission.eq_ignore_ascii_case(required) {
        return true;
    }
    match required.split_once(".Read.") {
        Some((resource, scope)) => {
            permission.eq_ignore_ascii_case(&format!("{resource}.ReadWrite.{scope}"))
        }
        None => false,
    }
}

/// The `scp` claim is a space-separated list, unlike `roles`, which is an array.
fn delegated_scopes(claims: &AccessTokenClaims) -> Vec<String> {
    claims
        .scp
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_token(roles: &[&str]) -> AccessTokenClaims {
        AccessTokenClaims {
            aud: "https://sim.test".into(),
            iss: "https://sim.test/tid/v2.0".into(),
            iat: 0,
            nbf: 0,
            exp: 0,
            appid: "client".into(),
            appidacr: "1".into(),
            idtyp: "app".into(),
            oid: "principal".into(),
            sub: "principal".into(),
            tid: "tid".into(),
            ver: "2.0".into(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            scp: None,
            app_displayname: None,
            upn: None,
            name: None,
            preferred_username: None,
        }
    }

    #[test]
    fn the_embedded_table_parses_and_covers_every_resource_family() {
        // A family missing from the table would be silently unenforced.
        for (method, path) in [
            ("GET", "/v1.0/users"),
            ("POST", "/v1.0/groups"),
            ("POST", "/v1.0/applications"),
            ("POST", "/v1.0/servicePrincipals"),
            ("POST", "/v1.0/oauth2PermissionGrants"),
            ("POST", "/v1.0/directoryRoles"),
            ("GET", "/v1.0/directoryRoleTemplates"),
            ("GET", "/v1.0/roleManagement/directory/roleDefinitions"),
            ("GET", "/v1.0/domains"),
            ("GET", "/v1.0/organization"),
            ("POST", "/v1.0/directoryObjects/getByIds"),
        ] {
            assert!(
                demanded(method, path).is_some(),
                "{method} {path} has no published requirement"
            );
        }
    }

    #[test]
    fn the_version_prefix_does_not_affect_the_lookup() {
        // The same handlers serve both prefixes, so they must demand the same permissions.
        let from_v1 = demanded("POST", "/v1.0/applications").expect("v1.0 should be covered");
        let from_beta = demanded("POST", "/beta/applications").expect("beta should be covered");
        assert_eq!(from_v1.roles, from_beta.roles);
    }

    #[test]
    fn a_single_sufficient_role_satisfies_an_endpoint() {
        let requirement = demanded("POST", "/v1.0/applications").unwrap();
        assert!(satisfied(
            requirement,
            &app_token(&["Application.ReadWrite.All"])
        ));
        assert!(!satisfied(requirement, &app_token(&["User.Read.All"])));
        assert!(!satisfied(requirement, &app_token(&[])));
    }

    #[test]
    fn a_conjunction_requires_every_named_permission() {
        // Graph documents this endpoint as needing AppRoleAssignment.ReadWrite.All together
        // with a read permission, or Application.ReadWrite.All on its own.
        let requirement =
            demanded("POST", "/v1.0/servicePrincipals/{id}/appRoleAssignedTo").unwrap();
        assert!(!satisfied(
            requirement,
            &app_token(&["AppRoleAssignment.ReadWrite.All"])
        ));
        assert!(satisfied(
            requirement,
            &app_token(&["AppRoleAssignment.ReadWrite.All", "Directory.Read.All"])
        ));
        assert!(satisfied(
            requirement,
            &app_token(&["Application.ReadWrite.All"])
        ));
    }

    #[test]
    fn a_delegated_token_is_judged_on_its_scopes_not_its_roles() {
        let requirement = demanded("GET", "/v1.0/users").unwrap();

        // Holding the app-only role does not help a delegated caller, and vice versa.
        let mut delegated = app_token(&["User.Read.All"]);
        delegated.roles.clear();
        delegated.scp = Some("User.ReadBasic.All".to_string());
        assert!(satisfied(requirement, &delegated));

        delegated.scp = Some("Mail.Read".to_string());
        assert!(!satisfied(requirement, &delegated));
    }

    #[test]
    fn a_write_permission_grants_the_matching_read_permission() {
        // Entra behaves this way, but the published tables list the two separately, so without
        // this a caller holding the write permission would be refused where the real service
        // would serve it.
        let requirement = demanded("POST", "/v1.0/directoryObjects/getByIds").unwrap();
        assert!(satisfied(requirement, &app_token(&["Directory.Read.All"])));
        assert!(satisfied(
            requirement,
            &app_token(&["Directory.ReadWrite.All"])
        ));

        // The implication does not run the other way.
        let write_only = demanded("DELETE", "/v1.0/users/{id}").unwrap();
        assert!(!satisfied(write_only, &app_token(&["User.Read.All"])));
        assert!(satisfied(write_only, &app_token(&["User.ReadWrite.All"])));

        // And it does not leak across resources.
        assert!(!satisfied(
            requirement,
            &app_token(&["Group.ReadWrite.All"])
        ));
    }

    #[test]
    fn permission_names_are_compared_without_regard_to_case() {
        let requirement = demanded("POST", "/v1.0/applications").unwrap();
        assert!(satisfied(
            requirement,
            &app_token(&["application.readwrite.all"])
        ));
    }
}
