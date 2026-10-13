//! Evaluating conditional access policies at sign-in and token issuance.
//!
//! The policy shapes are Microsoft Graph's conditionalAccessPolicy, conditionalAccessConditionSet
//! and conditionalAccessGrantControls. Only `enabled` policies are enforced;
//! `enabledForReportingButNotEnforced` ones are evaluated and logged.
//!
//! The simulator knows the user, their groups and directory roles, the client, the API, whether
//! the sign-in was in a browser, and whether the user completed multifactor authentication. It
//! knows nothing about locations, platforms, devices or risk, so a policy limited by one of those
//! applies only when it covers everything ("All" locations, "all" platforms, the risk level
//! "none"), and never otherwise. Workload identity policies (`clientApplications`) are not
//! enforced.

use serde_json::Value;
use tracing::info;

use crate::store::Directory;
use crate::store::model::User;

/// What kind of client signed in, for the `clientAppTypes` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAppType {
    /// A sign-in through the simulator's page in a browser.
    Browser,
    /// The device code and password grants, and the on-behalf-of flow.
    MobileAppsAndDesktopClients,
}

impl ClientAppType {
    fn value(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::MobileAppsAndDesktopClients => "mobileAppsAndDesktopClients",
        }
    }
}

/// A sign-in or token request to evaluate.
pub struct Access<'a> {
    pub user: &'a User,
    pub client_app_id: &'a str,
    /// The APIs the request is for.
    pub resource_app_ids: &'a [String],
    pub client_app_type: ClientAppType,
    /// Whether the user completed multifactor authentication in this sign-in.
    pub mfa: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// A policy needs multifactor authentication the sign-in has not done.
    RequireMfa,
    /// A policy refuses the request, with Microsoft's code and description.
    Block {
        code: u32,
        description: String,
    },
}

/// Apply every enabled policy to the request.
pub fn evaluate(directory: &Directory, access: &Access<'_>) -> Decision {
    let mut decision = Decision::Allow;
    for policy in directory.conditional_access_policies.values() {
        let state = policy["state"].as_str().unwrap_or_default();
        if state == "disabled" || !applies(directory, policy, access) {
            continue;
        }
        let outcome = grant(policy, access.mfa);
        if state == "enabledForReportingButNotEnforced" {
            info!(
                policy = %policy["displayName"].as_str().unwrap_or_default(),
                outcome = ?outcome,
                "a report-only conditional access policy applied"
            );
            continue;
        }
        match outcome {
            Decision::Block { .. } => return outcome,
            Decision::RequireMfa => decision = Decision::RequireMfa,
            Decision::Allow => {}
        }
    }
    decision
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether the policy's conditions cover this request.
fn applies(directory: &Directory, policy: &Value, access: &Access<'_>) -> bool {
    let conditions = &policy["conditions"];
    if conditions["users"].is_null() {
        // A policy for workload identities only.
        return false;
    }
    users_match(directory, &conditions["users"], access.user)
        && applications_match(&conditions["applications"], access)
        && client_app_type_matches(&conditions["clientAppTypes"], access.client_app_type)
        && unknown_conditions_match(conditions)
}

fn users_match(directory: &Directory, users: &Value, user: &User) -> bool {
    let guest = user
        .user_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("Guest"));
    let groups: Vec<String> = directory
        .transitive_groups_of(&user.id)
        .into_iter()
        .map(|group| group.id.clone())
        .collect();
    let roles: Vec<String> = directory
        .directory_roles_of(&user.id)
        .into_iter()
        .map(|role| role.role_template_id.clone())
        .collect();
    let named = |users_key: &str, groups_key: &str, roles_key: &str, guests_key: &str| {
        let listed = strings(&users[users_key]);
        listed.contains(&"All")
            || listed.contains(&user.id.as_str())
            || (guest && listed.contains(&"GuestsOrExternalUsers"))
            || (guest && !users[guests_key].is_null())
            || strings(&users[groups_key])
                .iter()
                .any(|group| groups.iter().any(|known| known == group))
            || strings(&users[roles_key])
                .iter()
                .any(|role| roles.iter().any(|known| known == role))
    };
    named(
        "includeUsers",
        "includeGroups",
        "includeRoles",
        "includeGuestsOrExternalUsers",
    ) && !named(
        "excludeUsers",
        "excludeGroups",
        "excludeRoles",
        "excludeGuestsOrExternalUsers",
    )
}

fn applications_match(applications: &Value, access: &Access<'_>) -> bool {
    // A policy for user actions or authentication contexts is not about signing in to an app.
    if !strings(&applications["includeUserActions"]).is_empty()
        || !strings(&applications["includeAuthenticationContextClassReferences"]).is_empty()
    {
        return false;
    }
    let targets: Vec<&str> = std::iter::once(access.client_app_id)
        .chain(access.resource_app_ids.iter().map(String::as_str))
        .collect();
    let included = strings(&applications["includeApplications"]);
    let excluded = strings(&applications["excludeApplications"]);
    (included.contains(&"All") || targets.iter().any(|target| included.contains(target)))
        && !targets.iter().any(|target| excluded.contains(target))
}

fn client_app_type_matches(types: &Value, client_app_type: ClientAppType) -> bool {
    let types = strings(types);
    types.is_empty() || types.contains(&"all") || types.contains(&client_app_type.value())
}

/// Conditions the simulator has no data for apply only when they cover everything.
fn unknown_conditions_match(conditions: &Value) -> bool {
    let locations = strings(&conditions["locations"]["includeLocations"]);
    let platforms = strings(&conditions["platforms"]["includePlatforms"]);
    let risk_none = |key: &str| {
        let levels = strings(&conditions[key]);
        levels.is_empty() || levels.contains(&"none")
    };
    let device_filter_includes = conditions["devices"]["deviceFilter"]["mode"] == "include";
    (locations.is_empty() || locations.contains(&"All"))
        && (platforms.is_empty() || platforms.contains(&"all"))
        && risk_none("signInRiskLevels")
        && risk_none("userRiskLevels")
        && risk_none("servicePrincipalRiskLevels")
        && conditions["insiderRiskLevels"].is_null()
        && !device_filter_includes
        && strings(&conditions["authenticationFlows"]["transferMethods"]).is_empty()
}

/// What one control needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Control {
    Block,
    Mfa,
    /// A control the simulator cannot satisfy, such as a compliant device.
    Unsatisfiable {
        code: u32,
        description: String,
    },
}

/// The outcome of a policy's grant controls.
fn grant(policy: &Value, mfa: bool) -> Decision {
    let controls_value = &policy["grantControls"];
    if controls_value.is_null() {
        return Decision::Allow;
    }
    let mut controls: Vec<Control> = strings(&controls_value["builtInControls"])
        .into_iter()
        .map(|control| match control {
            "block" => Control::Block,
            "mfa" => Control::Mfa,
            // Microsoft's reference: "AADSTS53000 DeviceNotCompliant" and "AADSTS53001
            // DeviceNotDomainJoined".
            "compliantDevice" => Control::Unsatisfiable {
                code: 53000,
                description: "Conditional Access policy requires a compliant device, and the \
                              device isn't compliant."
                    .to_string(),
            },
            "domainJoinedDevice" => Control::Unsatisfiable {
                code: 53001,
                description: "Conditional Access policy requires a domain joined device, and \
                              the device isn't domain joined."
                    .to_string(),
            },
            other => Control::Unsatisfiable {
                code: 53003,
                description: format!(
                    "Access has been blocked by Conditional Access policies: the control \
                     {other:?} cannot be satisfied in the simulator."
                ),
            },
        })
        .collect();
    if !strings(&controls_value["termsOfUse"]).is_empty()
        || !strings(&controls_value["customAuthenticationFactors"]).is_empty()
    {
        controls.push(Control::Unsatisfiable {
            code: 53003,
            description: "Access has been blocked by Conditional Access policies: terms of use \
                          and custom controls cannot be satisfied in the simulator."
                .to_string(),
        });
    }
    // An authentication strength asks for a set of strong methods; the simulator's one strong
    // method is its multifactor step.
    if !controls_value["authenticationStrength"].is_null() {
        controls.push(Control::Mfa);
    }
    if controls.is_empty() {
        return Decision::Allow;
    }

    let block = |control: &Control| match control {
        Control::Block => Decision::Block {
            code: 53003,
            description: "Access has been blocked by Conditional Access policies. The access \
                          policy does not allow token issuance."
                .to_string(),
        },
        Control::Unsatisfiable { code, description } => Decision::Block {
            code: *code,
            description: description.clone(),
        },
        Control::Mfa => Decision::RequireMfa,
    };
    let and = controls_value["operator"].as_str() == Some("AND");
    if and {
        if let Some(refusal) = controls.iter().find(|control| **control != Control::Mfa) {
            return block(refusal);
        }
        return if mfa {
            Decision::Allow
        } else {
            Decision::RequireMfa
        };
    }
    // OR: any one control will do.
    if controls.contains(&Control::Mfa) {
        return if mfa {
            Decision::Allow
        } else {
            Decision::RequireMfa
        };
    }
    block(&controls[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn or_with_mfa_needs_only_mfa_and_and_needs_everything() {
        let policy = |operator: &str, controls: Value| json!({ "grantControls": { "operator": operator, "builtInControls": controls } });
        assert_eq!(
            grant(&policy("OR", json!(["mfa", "compliantDevice"])), false),
            Decision::RequireMfa
        );
        assert_eq!(
            grant(&policy("OR", json!(["mfa", "compliantDevice"])), true),
            Decision::Allow
        );
        assert!(matches!(
            grant(&policy("AND", json!(["mfa", "compliantDevice"])), true),
            Decision::Block { code: 53000, .. }
        ));
        assert!(matches!(
            grant(&policy("OR", json!(["block"])), true),
            Decision::Block { code: 53003, .. }
        ));
    }

    #[test]
    fn unknown_conditions_apply_only_when_they_cover_everything() {
        assert!(unknown_conditions_match(&json!({
            "locations": { "includeLocations": ["All"], "excludeLocations": ["AllTrusted"] },
            "signInRiskLevels": [],
        })));
        assert!(!unknown_conditions_match(&json!({
            "locations": { "includeLocations": ["00000000-0000-0000-0000-00000000aaaa"] }
        })));
        assert!(!unknown_conditions_match(
            &json!({ "signInRiskLevels": ["high"] })
        ));
        assert!(!unknown_conditions_match(&json!({
            "platforms": { "includePlatforms": ["android"] }
        })));
    }
}
