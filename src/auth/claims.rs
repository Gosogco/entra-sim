//! Claims an app registration asks to have added to the tokens issued for it.
//!
//! The rules follow Microsoft's "Configure group claims for applications" page and the access
//! token claims reference. For an access token the settings are the API's; for an ID token they
//! are the client's, because each token is configured by the application it is issued for.

use serde_json::{Map, Value, json};

use crate::store::Directory;
use crate::store::model::{Application, Group};

/// Microsoft: "The number of groups emitted in a token is limited to ... 200 for JWT, including
/// nested groups."
pub const GROUP_OVERAGE_LIMIT: usize = 200;

/// Which kind of token the claims are for, which picks the `optionalClaims` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Id,
    Access,
}

impl TokenType {
    fn optional_claims_key(self) -> &'static str {
        match self {
            Self::Id => "idToken",
            Self::Access => "accessToken",
        }
    }
}

/// Group claims for one token.
#[derive(Debug, Default)]
pub struct GroupClaims {
    /// Claims to add: `groups`, `wids`, or the overage pair `_claim_names` and `_claim_sources`.
    pub claims: Map<String, Value>,
    /// Set when the groups optional claim has `emit_as_roles`. Microsoft: "The group values
    /// will be emitted in the role claim", and "any configured application roles that the user
    /// is assigned to will not appear in the role claim".
    pub roles_instead: Option<Vec<String>>,
}

/// The group claims the application `app_id` asks for in tokens for the user `user_id`.
pub fn group_claims(
    directory: &Directory,
    tenant_id: &str,
    user_id: &str,
    app_id: &str,
    registration: Option<&Application>,
    token_type: TokenType,
) -> GroupClaims {
    let mut result = GroupClaims::default();
    let Some(application) = registration else {
        return result;
    };
    // "It's not case-sensitive, so `none` also works."
    let setting = application
        .extra
        .get("groupMembershipClaims")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    // "`All`: Emits security groups, distribution lists, and roles." "`SecurityGroup`: Emits
    // security groups and Microsoft Entra roles that the user is a member of in the group claim."
    // "`DirectoryRole`: If the user is assigned directory roles, they're emitted as a `wids`
    // claim. (A group claim won't be emitted.)" "`ApplicationGroup`: Emits only the groups that
    // are explicitly assigned to the application and that the user is a member of."
    let groups: Option<Vec<&Group>> = match setting.as_str() {
        "all" => Some(directory.transitive_groups_of(user_id)),
        "securitygroup" => Some(
            directory
                .transitive_groups_of(user_id)
                .into_iter()
                .filter(|group| group.security_enabled)
                .collect(),
        ),
        // "With this option, nested groups are not included and the user must be a direct
        // member of the group assigned to the application."
        "applicationgroup" => {
            let assigned: Vec<&str> = directory
                .service_principal_by_app_id(app_id)
                .map(|principal| {
                    directory
                        .app_role_assignments
                        .values()
                        .filter(|assignment| assignment.resource_id == principal.id)
                        .map(|assignment| assignment.principal_id.as_str())
                        .collect()
                })
                .unwrap_or_default();
            Some(
                directory
                    .groups_containing(user_id)
                    .into_iter()
                    .filter(|group| assigned.contains(&group.id.as_str()))
                    .collect(),
            )
        }
        _ => None,
    };
    let roles = directory.directory_roles_of(user_id);

    // The access token claims reference: `wids` is configured by setting groupMembershipClaims
    // "to `All` or `DirectoryRole`".
    if matches!(setting.as_str(), "all" | "directoryrole") && !roles.is_empty() {
        let mut templates: Vec<&str> = roles
            .iter()
            .map(|role| role.role_template_id.as_str())
            .collect();
        templates.sort();
        result.claims.insert("wids".to_string(), json!(templates));
    }

    let Some(groups) = groups else {
        return result;
    };
    let options = groups_optional_claim(application, token_type);
    let mut values: Vec<String> = groups
        .iter()
        .filter_map(|group| group_value(group, &options, &setting))
        .collect();
    // Directory roles go into the groups claim as object IDs with `All` and `SecurityGroup`.
    if matches!(setting.as_str(), "all" | "securitygroup") {
        values.extend(roles.iter().map(|role| role.id.clone()));
    }
    values.sort();

    if values.len() > GROUP_OVERAGE_LIMIT {
        // "If a user is a member of more groups than the overage limit ... Microsoft Entra ID
        // doesn't emit the groups claim in the token. Instead, it includes an overage claim".
        // The documented endpoint is the Azure AD Graph one, which this reproduces; Microsoft
        // tells clients not to rely on it.
        result
            .claims
            .insert("_claim_names".to_string(), json!({ "groups": "src1" }));
        result.claims.insert(
            "_claim_sources".to_string(),
            json!({ "src1": { "endpoint": format!(
                "https://graph.windows.net/{tenant_id}/users/{user_id}/getMemberObjects"
            ) } }),
        );
        return result;
    }
    if values.is_empty() {
        return result;
    }
    if options.iter().any(|option| option == "emit_as_roles") {
        result.roles_instead = Some(values);
    } else {
        result.claims.insert("groups".to_string(), json!(values));
    }
    result
}

/// The `additionalProperties` of the `groups` optional claim for this token type.
fn groups_optional_claim(application: &Application, token_type: TokenType) -> Vec<String> {
    application
        .extra
        .get("optionalClaims")
        .and_then(|claims| claims.get(token_type.optional_claims_key()))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|claim| claim.get("name").and_then(Value::as_str) == Some("groups"))
        .filter_map(|claim| claim.get("additionalProperties"))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// How one group is written in the claim, or `None` when the chosen format does not apply to it.
///
/// Microsoft: the on-premises formats are "Available for groups synchronized from Active
/// Directory", and "If the application is configured to get group attributes that are synced
/// from Active Directory and a group doesn't contain those attributes, it won't be included in
/// the claims." `cloud_displayname` "will work only when `groupMembershipClaims` is set to
/// `ApplicationGroup`".
fn group_value(group: &Group, options: &[String], setting: &str) -> Option<String> {
    let attribute = |name: &str| {
        group
            .extra
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let sam = || attribute("onPremisesSamAccountName");

    // "only one of ... is required. If more than one is present, the first is used".
    let on_premises = options.iter().find(|option| {
        matches!(
            option.as_str(),
            "sam_account_name"
                | "dns_domain_and_sam_account_name"
                | "netbios_domain_and_sam_account_name"
        )
    });
    match on_premises.map(String::as_str) {
        Some("sam_account_name") => return sam(),
        Some("dns_domain_and_sam_account_name") => {
            return Some(format!(
                "{}\\{}",
                attribute("onPremisesDomainName")?,
                sam()?
            ));
        }
        Some("netbios_domain_and_sam_account_name") => {
            return Some(format!(
                "{}\\{}",
                attribute("onPremisesNetBiosName")?,
                sam()?
            ));
        }
        _ => {}
    }
    if setting == "applicationgroup"
        && options.iter().any(|option| option == "cloud_displayname")
        && sam().is_none()
    {
        return Some(group.display_name.clone());
    }
    Some(group.id.clone())
}

/// Optional claims for one token, from the `optionalClaims` of the application it is issued for.
#[derive(Debug, Default)]
pub struct OptionalClaims {
    pub claims: Map<String, Value>,
    /// The `aud` optional claim with `use_guid`: "Emits the client ID of the resource (API) in
    /// GUID format as the `aud` claim always", in v1.0 access tokens only.
    pub aud_use_guid: bool,
}

/// The optional claims an application's registration asks for in a token of `token_type` and
/// `version` for `user`, given the OpenID Connect scopes the sign-in asked for.
///
/// Only claims the simulator holds data for are supported, and a claim with no value is left
/// out: "Claims are present only if a value exists to fill it." The rules per claim are from
/// Microsoft's optional claims reference and ID token claims reference.
pub fn optional_claims(
    registration: Option<&Application>,
    token_type: TokenType,
    version: crate::store::TokenVersion,
    user: &crate::store::model::User,
    oidc_scopes: &[String],
    mfa: bool,
) -> OptionalClaims {
    use crate::store::TokenVersion;

    let mut result = OptionalClaims::default();
    let requested: Vec<(String, Vec<String>)> = registration
        .and_then(|application| application.extra.get("optionalClaims"))
        .and_then(|claims| claims.get(token_type.optional_claims_key()))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|claim| {
            let name = claim.get("name")?.as_str()?.to_string();
            let properties = claim
                .get("additionalProperties")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            Some((name, properties))
        })
        .collect();
    let asked = |name: &str| requested.iter().find(|(claim, _)| claim == name);
    let has_scope = |scope: &str| oidc_scopes.iter().any(|known| known == scope);
    let guest = user
        .user_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("Guest"));
    let v2 = version == TokenVersion::V2;
    let mut set = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            result.claims.insert(name.to_string(), value);
        }
    };

    // email: "Present by default for guest accounts that have an email address. Your app can
    // request the email claim for managed users ... using the email optional claim", and "On the
    // v2.0 endpoint, your app can also request the email OpenID Connect scope".
    let email_by_scope = token_type == TokenType::Id && has_scope("email");
    if guest || asked("email").is_some() || email_by_scope {
        set("email", user.mail.clone().map(Value::from));
    }
    // given_name, family_name and upn are v1.0 claims; in a v2.0 token they are optional claims
    // that "Requires the profile scope". The simulator's v1.0 access tokens carry them already.
    if v2 && has_scope("profile") {
        if asked("given_name").is_some() {
            set("given_name", user.given_name.clone().map(Value::from));
        }
        if asked("family_name").is_some() {
            set("family_name", user.surname.clone().map(Value::from));
        }
        if asked("upn").is_some() {
            set("upn", Some(Value::from(user.user_principal_name.clone())));
        }
    }
    // preferred_username: "Provides the preferred username claim within v1 tokens."
    if !v2 && asked("preferred_username").is_some() {
        set(
            "preferred_username",
            Some(Value::from(user.user_principal_name.clone())),
        );
    }
    // acct: "If the user is a member of the tenant, the value is 0. If they're a guest, the
    // value is 1."
    if asked("acct").is_some() {
        set("acct", Some(json!(if guest { 1 } else { 0 })));
    }
    // amr is one of the claims "always included in v1.0 tokens, but not included in v2.0 tokens
    // unless requested".
    if v2 && asked("amr").is_some() {
        set("amr", Some(json!(crate::auth::token::amr(mfa))));
    }
    // xms_pl: "The user's preferred language, if set."
    if asked("xms_pl").is_some() {
        set("xms_pl", user.extra.get("preferredLanguage").cloned());
    }
    if token_type == TokenType::Access {
        // idtyp with include_user_token: "Emits the idtyp claim for users token."
        if asked("idtyp").is_some_and(|(_, properties)| {
            properties
                .iter()
                .any(|property| property == "include_user_token")
        }) {
            set("idtyp", Some(Value::from("user")));
        }
        result.aud_use_guid = !v2
            && asked("aud").is_some_and(|(_, properties)| {
                properties.iter().any(|property| property == "use_guid")
            });
    }
    result
}
