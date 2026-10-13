//! Delta queries: what changed in a collection since the last round.
//!
//! The behaviour follows Microsoft's "Use delta query to track changes" overview and the group
//! delta reference:
//!
//! - The first call returns every current object and an `@odata.deltaLink` whose `$deltatoken`
//!   stands for that state. Calling the link returns what changed since, and a new link.
//! - "`$deltatoken=latest`" returns only a delta link.
//! - Deleted objects come back as their `id` with an `@removed` object. Group membership changes
//!   come back in `members@delta`, which "includes the ids of member objects in the group", and
//!   is present without `$select`, as in Microsoft's first example.
//! - `$select` limits what is tracked: "If a change occurs to a property that isn't selected, the
//!   resource ... doesn't appear in the delta response". The only `$filter` is by `id`, at most
//!   50 of them. `$expand`, `$top` and `$orderby` are refused for users and groups.
//! - `Prefer: return=minimal` returns "only the object properties that have changed".
//!
//! Each token keeps a snapshot of the tracked objects, and a round compares the directory with
//! it. The simulator deletes objects outright rather than moving them to deleted items, so a
//! removal's reason is `deleted`, which Microsoft describes as "the item is deleted and can't be
//! restored". Every round fits in one page, so there is no `@odata.nextLink`.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{OriginalUri, Query, State};
use axum::http::HeaderMap;
use serde_json::{Map, Value, json};

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::state::AppState;
use crate::store::{Directory, ObjectKind};

/// Microsoft: "There is a limit of 50 filtered objects."
const MAX_FILTERED_IDS: usize = 50;

/// A collection that supports delta queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collection {
    Users,
    Groups,
    Applications,
    ServicePrincipals,
    DirectoryRoles,
    OAuth2PermissionGrants,
}

impl Collection {
    fn path(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Groups => "groups",
            Self::Applications => "applications",
            Self::ServicePrincipals => "servicePrincipals",
            Self::DirectoryRoles => "directoryRoles",
            Self::OAuth2PermissionGrants => "oauth2PermissionGrants",
        }
    }

    /// Whether the collection has a `members` relationship to track.
    fn has_members(self) -> bool {
        matches!(self, Self::Groups | Self::DirectoryRoles)
    }

    /// Microsoft lists `$expand`, `$top` and `$orderby` as unsupported "For the user and group
    /// resources".
    fn refuses_paging_and_expansion(self) -> bool {
        matches!(self, Self::Users | Self::Groups)
    }
}

/// What a delta token stands for: the query that started the round and the state it saw.
#[derive(Debug, Clone)]
pub struct DeltaState {
    pub collection: Collection,
    select: Option<Vec<String>>,
    filter_ids: Option<Vec<String>>,
    /// Tracked properties by object ID, with `members` as a list of member IDs.
    objects: BTreeMap<String, Map<String, Value>>,
}

pub async fn users(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(state, caller, uri, headers, query, Collection::Users).await
}

pub async fn groups(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(state, caller, uri, headers, query, Collection::Groups).await
}

pub async fn applications(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(state, caller, uri, headers, query, Collection::Applications).await
}

pub async fn service_principals(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(
        state,
        caller,
        uri,
        headers,
        query,
        Collection::ServicePrincipals,
    )
    .await
}

pub async fn directory_roles(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(
        state,
        caller,
        uri,
        headers,
        query,
        Collection::DirectoryRoles,
    )
    .await
}

pub async fn oauth2_permission_grants(
    state: State<AppState>,
    caller: Caller,
    uri: OriginalUri,
    headers: HeaderMap,
    query: Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, GraphError> {
    delta(
        state,
        caller,
        uri,
        headers,
        query,
        Collection::OAuth2PermissionGrants,
    )
    .await
}

async fn delta(
    State(state): State<AppState>,
    _caller: Caller,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    collection: Collection,
) -> Result<Json<Value>, GraphError> {
    let version = if uri.path().starts_with("/beta") {
        "/beta"
    } else {
        "/v1.0"
    };
    let minimal = headers
        .get_all("prefer")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.contains("return=minimal"));

    let previous = match query.get("$deltatoken").map(String::as_str) {
        None => None,
        Some("latest") => {
            // "Append `$deltatoken=latest` to the delta function and the response contains a
            // `@odata.deltaLink` and no resource data."
            let (select, filter_ids) = round_parameters(&query, collection)?;
            let directory = state.store.read().await;
            let snapshot = snapshot(&directory, collection, &select, &filter_ids);
            drop(directory);
            let token = state.sessions.lock().await.store_delta_state(DeltaState {
                collection,
                select,
                filter_ids,
                objects: snapshot,
            });
            return Ok(Json(page(&state, version, collection, Vec::new(), &token)));
        }
        Some(token) => {
            let found = state.sessions.lock().await.delta_state(token);
            match found {
                Some(found) if found.collection == collection => Some(found),
                _ => {
                    return Err(GraphError::invalid_request(
                        "The delta token is not valid for this collection. Start a new round \
                         without one.",
                    ));
                }
            }
        }
    };

    let (select, filter_ids) = match &previous {
        // "don't modify subsequent delta query requests to repeat these query parameters".
        Some(previous) => (previous.select.clone(), previous.filter_ids.clone()),
        None => round_parameters(&query, collection)?,
    };

    let directory = state.store.read().await;
    let current = snapshot(&directory, collection, &select, &filter_ids);
    let mut value = Vec::new();
    match &previous {
        None => {
            for (id, properties) in &current {
                value.push(present(&directory, collection, id, properties, None, false));
            }
        }
        Some(previous) => {
            for (id, properties) in &current {
                match previous.objects.get(id) {
                    Some(before) if before == properties => {}
                    before => value.push(present(
                        &directory, collection, id, properties, before, minimal,
                    )),
                }
            }
            for id in previous.objects.keys() {
                if !current.contains_key(id) {
                    value.push(json!({ "id": id, "@removed": { "reason": "deleted" } }));
                }
            }
        }
    }
    drop(directory);

    let token = state.sessions.lock().await.store_delta_state(DeltaState {
        collection,
        select,
        filter_ids,
        objects: current,
    });
    Ok(Json(page(&state, version, collection, value, &token)))
}

/// Read and check the query parameters that start a round.
#[allow(clippy::type_complexity)]
fn round_parameters(
    query: &BTreeMap<String, String>,
    collection: Collection,
) -> Result<(Option<Vec<String>>, Option<Vec<String>>), GraphError> {
    if collection.refuses_paging_and_expansion() {
        for refused in ["$expand", "$top", "$orderby"] {
            if query.contains_key(refused) {
                return Err(GraphError::invalid_request(format!(
                    "{refused} is not supported with delta queries on {}.",
                    collection.path()
                )));
            }
        }
    }
    let select = query.get("$select").map(|select| {
        select
            .split(',')
            .map(|property| property.trim().to_string())
            .filter(|property| !property.is_empty())
            .collect()
    });
    let filter_ids = query
        .get("$filter")
        .map(|filter| id_filter(filter))
        .transpose()?;
    Ok((select, filter_ids))
}

/// Parse the only supported filter: `id eq '...'`, joined with `or`.
fn id_filter(filter: &str) -> Result<Vec<String>, GraphError> {
    let unsupported = || {
        GraphError::invalid_request(
            "The only $filter supported with delta queries is on id: id eq '{value}', joined \
             with or.",
        )
    };
    let ids = filter
        .split(" or ")
        .map(|clause| {
            let value = clause
                .trim()
                .strip_prefix("id eq ")
                .ok_or_else(unsupported)?
                .trim();
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .map(str::to_string)
                .ok_or_else(unsupported)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_FILTERED_IDS {
        return Err(GraphError::invalid_request(format!(
            "A delta query can filter on at most {MAX_FILTERED_IDS} objects."
        )));
    }
    Ok(ids)
}

/// The tracked state of every object in the collection the round covers.
fn snapshot(
    directory: &Directory,
    collection: Collection,
    select: &Option<Vec<String>>,
    filter_ids: &Option<Vec<String>>,
) -> BTreeMap<String, Map<String, Value>> {
    let entries: Vec<(String, Value, Option<Vec<String>>)> = match collection {
        Collection::Users => directory
            .users
            .values()
            .map(|user| (user.id.clone(), to_value(user), None))
            .collect(),
        Collection::Groups => directory
            .groups
            .values()
            .map(|group| {
                (
                    group.id.clone(),
                    to_value(group),
                    Some(group.members.clone()),
                )
            })
            .collect(),
        Collection::Applications => directory
            .applications
            .values()
            .map(|application| (application.id.clone(), to_value(application), None))
            .collect(),
        Collection::ServicePrincipals => directory
            .service_principals
            .values()
            .map(|principal| (principal.id.clone(), to_value(principal), None))
            .collect(),
        Collection::DirectoryRoles => directory
            .directory_roles
            .values()
            .map(|role| (role.id.clone(), to_value(role), Some(role.members.clone())))
            .collect(),
        Collection::OAuth2PermissionGrants => directory
            .oauth2_permission_grants
            .values()
            .map(|grant| (grant.id.clone(), to_value(grant), None))
            .collect(),
    };

    entries
        .into_iter()
        .filter(|(id, _, _)| {
            filter_ids
                .as_ref()
                .is_none_or(|wanted| wanted.iter().any(|wanted| wanted == id))
        })
        .map(|(id, value, members)| {
            let mut properties = value.as_object().cloned().unwrap_or_default();
            if let Some(selected) = select {
                // "The id property is always returned."
                properties.retain(|name, _| name == "id" || selected.contains(name));
            }
            let track_members = collection.has_members()
                && select
                    .as_ref()
                    .is_none_or(|selected| selected.iter().any(|name| name == "members"));
            if track_members && let Some(mut members) = members {
                members.sort();
                properties.insert("members".to_string(), json!(members));
            }
            (id, properties)
        })
        .collect()
}

fn to_value<T: serde::Serialize>(object: &T) -> Value {
    serde_json::to_value(object).unwrap_or(Value::Null)
}

/// One object as a round reports it: the properties, or only the changed ones when the client
/// asked for minimal responses, and membership changes in `members@delta`.
fn present(
    directory: &Directory,
    collection: Collection,
    id: &str,
    properties: &Map<String, Value>,
    before: Option<&Map<String, Value>>,
    minimal: bool,
) -> Value {
    let mut out = Map::new();
    out.insert("id".to_string(), json!(id));
    for (name, value) in properties {
        if name == "id" || name == "members" {
            continue;
        }
        let changed = before.is_none_or(|before| before.get(name) != Some(value));
        if !minimal || changed {
            out.insert(name.clone(), value.clone());
        }
    }
    // A property that disappeared was set to null, and Microsoft includes "properties being set
    // to null value".
    if let Some(before) = before {
        for name in before.keys() {
            if name != "members" && !properties.contains_key(name) {
                out.insert(name.clone(), Value::Null);
            }
        }
    }

    if collection.has_members()
        && let Some(members) = properties.get("members").and_then(Value::as_array)
    {
        let current: Vec<&str> = members.iter().filter_map(Value::as_str).collect();
        let earlier: Vec<&str> = before
            .and_then(|before| before.get("members"))
            .and_then(Value::as_array)
            .map(|members| members.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut changes: Vec<Value> = current
            .iter()
            .filter(|member| !earlier.contains(member))
            .map(|member| member_entry(directory, member, false))
            .collect();
        changes.extend(
            earlier
                .iter()
                .filter(|member| !current.contains(member))
                .map(|member| member_entry(directory, member, true)),
        );
        if before.is_none() || !changes.is_empty() {
            out.insert("members@delta".to_string(), Value::Array(changes));
        }
    }
    Value::Object(out)
}

fn member_entry(directory: &Directory, id: &str, removed: bool) -> Value {
    let mut entry = Map::new();
    if let Some((kind, _)) = directory.object(id) {
        entry.insert("@odata.type".to_string(), json!(kind.odata_type()));
    } else if removed {
        // A member that was deleted outright is no longer there to name its type.
        entry.insert(
            "@odata.type".to_string(),
            json!(ObjectKind::User.odata_type()),
        );
    }
    entry.insert("id".to_string(), json!(id));
    if removed {
        entry.insert("@removed".to_string(), json!({ "reason": "deleted" }));
    }
    Value::Object(entry)
}

fn page(
    state: &AppState,
    version: &str,
    collection: Collection,
    value: Vec<Value>,
    token: &str,
) -> Value {
    let base = state.config.public_base_url();
    json!({
        "@odata.context": format!("{base}{version}/$metadata#{}", collection.path()),
        "@odata.deltaLink": format!(
            "{base}{version}/{}/delta?$deltatoken={token}",
            collection.path()
        ),
        "value": value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_id_filter_accepts_one_or_several_ids() {
        assert_eq!(id_filter("id eq 'a'").unwrap(), ["a"]);
        assert_eq!(id_filter("id eq 'a' or id eq 'b'").unwrap(), ["a", "b"]);
        assert!(id_filter("displayName eq 'a'").is_err());
    }
}
