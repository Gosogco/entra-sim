//! The `/groups` collection, including membership and ownership.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::Directory;
use crate::store::model::Group;

/// Which navigation property a request addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Link {
    Members,
    Owners,
}

impl Link {
    fn of(group: &Group) -> [(Self, &Vec<String>); 2] {
        [
            (Self::Members, &group.members),
            (Self::Owners, &group.owners),
        ]
    }

    fn name(self) -> &'static str {
        match self {
            Self::Members => "members",
            Self::Owners => "owners",
        }
    }

    fn list_mut(self, group: &mut Group) -> &mut Vec<String> {
        match self {
            Self::Members => &mut group.members,
            Self::Owners => &mut group.owners,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/groups", get(list).post(create))
        .route(
            "/groups/{id}",
            get(read).patch(update).put(update).delete(delete),
        )
        .route("/groups/{id}/members", get(members))
        .route("/groups/{id}/members/$ref", get(members).post(add_member))
        .route(
            "/groups/{id}/members/{member_id}/$ref",
            axum::routing::delete(remove_member),
        )
        .route("/groups/{id}/owners", get(owners))
        .route("/groups/{id}/owners/$ref", get(owners).post(add_owner))
        .route(
            "/groups/{id}/owners/{owner_id}/$ref",
            axum::routing::delete(remove_owner),
        )
        .route("/groups/{id}/transitiveMembers", get(transitive_members))
        .route("/groups/{id}/memberOf", get(group_member_of))
        .route("/users/{id}/memberOf", get(user_member_of))
        // Graph exposes this as an action rather than a navigation property.
        .route("/directoryObjects/getByIds", post(get_by_ids))
}

async fn list(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;

    let mut objects = Vec::new();
    for group in directory.groups.values() {
        objects.push(expand(&directory, group, &query.expand)?);
    }
    Ok(collection_response(&state, objects, &query, "groups"))
}

async fn read(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let group = directory
        .groups
        .get(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let object = expand(&directory, group, &query.expand)?;
    Ok(object_response(&state, object, &query, "groups"))
}

async fn create(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;

    let display_name = fields
        .get("displayName")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GraphError::invalid_request(
                "The property \"displayName\" is required and must be a string.",
            )
        })?
        .to_string();

    // Graph requires both of these on create and rejects the request without them, rather than
    // picking a default, because the combination decides what kind of group results.
    let mail_enabled = fields
        .get("mailEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            GraphError::invalid_request(
                "The property \"mailEnabled\" is required and must be a boolean.",
            )
        })?;
    let security_enabled = fields
        .get("securityEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            GraphError::invalid_request(
                "The property \"securityEnabled\" is required and must be a boolean.",
            )
        })?;

    let mut directory = state.store.write().await;

    // Members and owners may be supplied on create as @odata.bind references.
    let members = bound_references(fields, "members@odata.bind", &directory)?;
    let owners = bound_references(fields, "owners@odata.bind", &directory)?;

    let mut extra = fields.clone();
    for key in [
        "id",
        "displayName",
        "description",
        "mailNickname",
        "mail",
        "mailEnabled",
        "securityEnabled",
        "groupTypes",
        "createdDateTime",
        "members@odata.bind",
        "owners@odata.bind",
    ] {
        extra.remove(key);
    }

    let group = Group {
        id: Uuid::new_v4().to_string(),
        display_name,
        description: fields
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        mail_nickname: fields
            .get("mailNickname")
            .and_then(Value::as_str)
            .map(str::to_string),
        mail: fields
            .get("mail")
            .and_then(Value::as_str)
            .map(str::to_string),
        mail_enabled,
        security_enabled,
        group_types: fields
            .get("groupTypes")
            .and_then(Value::as_array)
            .map(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        created_date_time: OffsetDateTime::now_utc(),
        members,
        owners,
        extra,
    };

    let body = serialise(&group)?;
    directory.groups.insert(group.id.clone(), group);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn update(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<StatusCode, GraphError> {
    let patch = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;

    let mut directory = state.store.write().await;
    if !directory.groups.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }

    // Resolve references before taking a mutable borrow of the group itself.
    let members = bound_references(patch, "members@odata.bind", &directory)?;
    let owners = bound_references(patch, "owners@odata.bind", &directory)?;

    let group = directory.groups.get_mut(&id).expect("checked above");
    for (property, value) in patch {
        match property.as_str() {
            "id" => {
                return Err(GraphError::invalid_request(
                    "The property 'id' is read-only and cannot be modified.",
                ));
            }
            "displayName" => {
                group.display_name = value
                    .as_str()
                    .ok_or_else(|| GraphError::invalid_property("displayName"))?
                    .to_string();
            }
            "description" => group.description = value.as_str().map(str::to_string),
            "mailNickname" => group.mail_nickname = value.as_str().map(str::to_string),
            "mail" => group.mail = value.as_str().map(str::to_string),
            "mailEnabled" => {
                group.mail_enabled = value
                    .as_bool()
                    .ok_or_else(|| GraphError::invalid_property("mailEnabled"))?;
            }
            "securityEnabled" => {
                group.security_enabled = value
                    .as_bool()
                    .ok_or_else(|| GraphError::invalid_property("securityEnabled"))?;
            }
            "groupTypes" => {
                group.group_types = value
                    .as_array()
                    .ok_or_else(|| GraphError::invalid_property("groupTypes"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
            // A bind on PATCH replaces the whole collection, unlike a POST to /$ref.
            "members@odata.bind" => group.members = members.clone(),
            "owners@odata.bind" => group.owners = owners.clone(),
            other => {
                if value.is_null() {
                    group.extra.remove(other);
                } else {
                    group.extra.insert(other.to_string(), value.clone());
                }
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    if directory.groups.remove(&id).is_none() {
        return Err(GraphError::resource_not_found(&id));
    }
    // A deleted group must stop appearing in other groups' membership.
    for group in directory.groups.values_mut() {
        group.members.retain(|member| member != &id);
        group.owners.retain(|owner| owner != &id);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn members(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    linked_objects(state, caller, path, query, Link::Members).await
}

async fn owners(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    linked_objects(state, caller, path, query, Link::Owners).await
}

async fn linked_objects(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
    link: Link,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let group = directory
        .groups
        .get(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let ids = Link::of(group)
        .into_iter()
        .find(|(candidate, _)| *candidate == link)
        .map(|(_, ids)| ids.clone())
        .unwrap_or_default();

    let objects = resolve_all(&directory, &ids);
    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("groups('{id}')/{}", link.name()),
    ))
}

async fn transitive_members(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    if !directory.groups.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }

    let objects = resolve_all(&directory, &directory.transitive_members(&id));
    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("groups('{id}')/transitiveMembers"),
    ))
}

async fn group_member_of(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    member_of(state, caller, path, query, "groups").await
}

async fn user_member_of(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    member_of(state, caller, path, query, "users").await
}

async fn member_of(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
    entity_set: &str,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    if !directory.contains_object(&id) {
        return Err(GraphError::resource_not_found(&id));
    }

    let objects = directory
        .groups_containing(&id)
        .into_iter()
        .filter_map(|group| directory.object(&group.id).map(|(_, value)| value))
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("{entity_set}('{id}')/memberOf"),
    ))
}

#[derive(Debug, Deserialize)]
struct ReferenceBody {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

async fn add_member(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    body: Json<ReferenceBody>,
) -> Result<StatusCode, GraphError> {
    add_reference(state, caller, path, body, Link::Members).await
}

async fn add_owner(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    body: Json<ReferenceBody>,
) -> Result<StatusCode, GraphError> {
    add_reference(state, caller, path, body, Link::Owners).await
}

async fn add_reference(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<ReferenceBody>,
    link: Link,
) -> Result<StatusCode, GraphError> {
    let referenced = object_id_from_odata_id(&body.odata_id)?;

    let mut directory = state.store.write().await;
    if !directory.groups.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }
    if !directory.contains_object(&referenced) {
        return Err(GraphError::resource_not_found(&referenced));
    }

    let group = directory.groups.get_mut(&id).expect("checked above");
    let list = link.list_mut(group);
    if list.iter().any(|existing| existing == &referenced) {
        // Graph refuses a duplicate rather than treating the add as idempotent.
        return Err(GraphError::new(
            StatusCode::BAD_REQUEST,
            "Request_BadRequest",
            format!(
                "One or more added object references already exist for the following modified \
                 properties: '{}'.",
                link.name()
            ),
        ));
    }
    list.push(referenced);
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    state: State<AppState>,
    caller: Caller,
    path: Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    remove_reference(state, caller, path, Link::Members).await
}

async fn remove_owner(
    state: State<AppState>,
    caller: Caller,
    path: Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    remove_reference(state, caller, path, Link::Owners).await
}

async fn remove_reference(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, referenced)): Path<(String, String)>,
    link: Link,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let group = directory
        .groups
        .get_mut(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let list = link.list_mut(group);
    let before = list.len();
    list.retain(|existing| existing != &referenced);
    if list.len() == before {
        return Err(GraphError::resource_not_found(&referenced));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct GetByIdsBody {
    ids: Vec<String>,
    #[serde(default)]
    types: Vec<String>,
}

/// `POST /directoryObjects/getByIds` resolves a batch of IDs to objects, skipping any that do
/// not exist rather than failing the whole call.
async fn get_by_ids(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<GetByIdsBody>,
) -> Result<impl IntoResponse, GraphError> {
    let directory = state.store.read().await;
    let wanted: Vec<&str> = body.types.iter().map(String::as_str).collect();

    let objects = body
        .ids
        .iter()
        .filter_map(|id| directory.object(id))
        .filter(|(kind, _)| {
            wanted.is_empty()
                || wanted.iter().any(|name| {
                    // Callers pass short type names such as "user" or "group".
                    kind.odata_type().trim_start_matches("#microsoft.graph.")
                        == name.trim_start_matches("microsoft.graph.")
                })
        })
        .map(|(_, value)| value)
        .collect();

    let query = RawQuery::default().validate()?;
    Ok(collection_response(
        &state,
        objects,
        &query,
        "directoryObjects",
    ))
}

/// Resolve object IDs to objects, dropping any that no longer exist.
fn resolve_all(directory: &Directory, ids: &[String]) -> Vec<Value> {
    let mut objects: Vec<Value> = ids
        .iter()
        .filter_map(|id| directory.object(id).map(|(_, value)| value))
        .collect();
    // The store yields collections ordered by ID, and paging depends on that ordering.
    objects.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    objects
}

/// Add `$expand`ed navigation properties to a group's body.
fn expand(directory: &Directory, group: &Group, expand: &[String]) -> Result<Value, GraphError> {
    let mut object = serialise(group)?;
    if expand.is_empty() {
        return Ok(object);
    }

    let fields = object
        .as_object_mut()
        .expect("a group serialises to an object");
    for requested in expand {
        // Graph accepts `members($select=id)`; only the property name matters here.
        let property = requested
            .split_once('(')
            .map_or(requested.as_str(), |(name, _)| name)
            .trim();
        let Some((_, ids)) = Link::of(group)
            .into_iter()
            .find(|(link, _)| link.name() == property)
        else {
            return Err(GraphError::new(
                StatusCode::BAD_REQUEST,
                "Request_UnsupportedQuery",
                format!("Could not find a property named {property:?} to expand."),
            ));
        };
        fields.insert(
            property.to_string(),
            Value::Array(resolve_all(directory, ids)),
        );
    }
    Ok(object)
}

/// Pull the object ID out of an `@odata.id` reference.
///
/// Clients send an absolute URL naming the real Graph host, so only the last path segment can
/// be trusted.
fn object_id_from_odata_id(odata_id: &str) -> Result<String, GraphError> {
    let trimmed = odata_id.trim().trim_end_matches('/');
    let candidate = trimmed.rsplit('/').next().unwrap_or_default();
    if candidate.is_empty() {
        return Err(GraphError::invalid_request(format!(
            "The @odata.id value {odata_id:?} does not name a directory object."
        )));
    }
    Ok(candidate.to_string())
}

/// Resolve an `@odata.bind` array supplied on create or update.
fn bound_references(
    fields: &Map<String, Value>,
    property: &str,
    directory: &Directory,
) -> Result<Vec<String>, GraphError> {
    let Some(values) = fields.get(property) else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| GraphError::invalid_property(property))?;

    let mut ids = Vec::new();
    for value in values {
        let reference = value
            .as_str()
            .ok_or_else(|| GraphError::invalid_property(property))?;
        let id = object_id_from_odata_id(reference)?;
        if !directory.contains_object(&id) {
            return Err(GraphError::resource_not_found(&id));
        }
        ids.push(id);
    }
    Ok(ids)
}

fn serialise(group: &Group) -> Result<Value, GraphError> {
    serde_json::to_value(group)
        .map_err(|error| GraphError::internal(format!("serialising a group: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_odata_id_reference_yields_the_trailing_object_id() {
        // Clients send an absolute URL naming the real Graph host.
        assert_eq!(
            object_id_from_odata_id("https://graph.microsoft.com/v1.0/directoryObjects/0a1b-2c3d")
                .unwrap(),
            "0a1b-2c3d"
        );
        assert_eq!(
            object_id_from_odata_id("https://graph.microsoft.com/v1.0/users/0a1b/").unwrap(),
            "0a1b"
        );
        assert!(object_id_from_odata_id("   ").is_err());
    }
}
