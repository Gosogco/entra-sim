//! Reading a `scope` parameter: which API each permission belongs to.
//!
//! Entra lets a client name a permission as `{resource}/{value}`, where the resource is an API's
//! application ID URI or its `appId`, or as a bare value, which means Microsoft Graph.
//! `{resource}/.default` asks for every permission already granted on that API.

use crate::store::Directory;
use crate::store::model::ServicePrincipal;

/// Scopes OpenID Connect defines, which govern what is issued rather than naming a permission
/// on an API.
pub const OIDC_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

pub fn is_oidc_scope(scope: &str) -> bool {
    OIDC_SCOPES.contains(&scope)
}

/// The permissions a request names on one API, in the spelling the client used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedResource {
    /// The resource as written, or `None` for bare values, which belong to Microsoft Graph.
    pub resource: Option<String>,
    /// Permission values without the resource prefix. `.default` is kept as a value.
    pub values: Vec<String>,
}

/// Split a scope parameter into its OpenID Connect scopes and its permissions per API, keeping
/// the order in which each API first appears.
pub fn parse(scope: &str) -> (Vec<String>, Vec<NamedResource>) {
    let mut oidc = Vec::new();
    let mut named: Vec<NamedResource> = Vec::new();

    for entry in scope.split_whitespace() {
        if is_oidc_scope(entry) {
            oidc.push(entry.to_string());
            continue;
        }
        let (resource, value) = match entry.rsplit_once('/') {
            Some((resource, value)) if !resource.is_empty() => {
                (Some(resource.to_string()), value.to_string())
            }
            _ => (None, entry.to_string()),
        };
        match named.iter_mut().find(|known| known.resource == resource) {
            Some(known) => {
                if !known.values.contains(&value) {
                    known.values.push(value);
                }
            }
            None => named.push(NamedResource {
                resource,
                values: vec![value],
            }),
        }
    }
    (oidc, named)
}

/// One API a request names, found in the directory.
#[derive(Debug, Clone)]
pub struct RequestedResource {
    /// Object ID of the API's service principal.
    pub principal_id: String,
    /// The API's `appId`.
    pub app_id: String,
    /// The resource as the client wrote it, or `None` when it named Graph by bare values.
    pub requested_as: Option<String>,
    /// Permission values, `.default` included.
    pub values: Vec<String>,
}

impl RequestedResource {
    pub fn wants_default(&self) -> bool {
        self.values.iter().any(|value| value == ".default")
    }

    /// The permission values that are scopes, without `.default`.
    pub fn named_scopes(&self) -> impl Iterator<Item = &String> {
        self.values.iter().filter(|value| *value != ".default")
    }

    pub fn is_graph(&self) -> bool {
        self.app_id == crate::store::model::MICROSOFT_GRAPH_APP_ID
    }

    /// Write a granted permission back the way Entra reports it in a token response: bare for
    /// Graph, and prefixed with the resource for any other API.
    pub fn qualify(&self, value: &str) -> String {
        match (&self.requested_as, self.is_graph()) {
            (Some(resource), false) => format!("{resource}/{value}"),
            _ => value.to_string(),
        }
    }
}

/// Find every API a parsed scope names, merging two spellings of the same API.
///
/// A name that matches no API is returned as the error, because Entra refuses the request
/// rather than ignoring the permission.
pub fn resolve(
    directory: &Directory,
    simulator_base_url: &str,
    named: &[NamedResource],
) -> Result<Vec<RequestedResource>, String> {
    let mut resolved: Vec<RequestedResource> = Vec::new();
    for entry in named {
        let principal: Option<&ServicePrincipal> = match &entry.resource {
            Some(name) => directory.resource_for(name, simulator_base_url),
            None => directory.graph_service_principal(),
        };
        let Some(principal) = principal else {
            return Err(entry.resource.clone().unwrap_or_default());
        };

        match resolved
            .iter_mut()
            .find(|known| known.principal_id == principal.id)
        {
            Some(known) => {
                for value in &entry.values {
                    if !known.values.contains(value) {
                        known.values.push(value.clone());
                    }
                }
            }
            None => resolved.push(RequestedResource {
                principal_id: principal.id.clone(),
                app_id: principal.app_id.clone(),
                requested_as: entry.resource.clone(),
                values: entry.values.clone(),
            }),
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_scope_belongs_to_graph() {
        let (oidc, named) = parse("openid offline_access User.Read");
        assert_eq!(oidc, ["openid", "offline_access"]);
        assert_eq!(
            named,
            [NamedResource {
                resource: None,
                values: vec!["User.Read".to_string()]
            }]
        );
    }

    #[test]
    fn a_qualified_scope_names_its_resource() {
        let (_, named) = parse("api://orders/Orders.Read https://graph.microsoft.com/.default");
        assert_eq!(
            named,
            [
                NamedResource {
                    resource: Some("api://orders".to_string()),
                    values: vec!["Orders.Read".to_string()]
                },
                NamedResource {
                    resource: Some("https://graph.microsoft.com".to_string()),
                    values: vec![".default".to_string()]
                },
            ]
        );
    }

    #[test]
    fn an_identifier_uri_with_a_path_keeps_its_path() {
        let (_, named) = parse("https://contoso.example/orders/Orders.Read");
        assert_eq!(
            named[0].resource.as_deref(),
            Some("https://contoso.example/orders")
        );
        assert_eq!(named[0].values, ["Orders.Read"]);
    }

    #[test]
    fn a_bare_default_scope_belongs_to_graph() {
        // Entra: "when a resource isn't identified, it defaults to Microsoft Graph".
        let (_, named) = parse(".default");
        assert_eq!(named[0].resource, None);
        assert_eq!(named[0].values, [".default"]);
    }

    #[test]
    fn repeated_values_for_one_resource_are_merged() {
        let (_, named) = parse("api://orders/A api://orders/B api://orders/A");
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].values, ["A", "B"]);
    }
}
