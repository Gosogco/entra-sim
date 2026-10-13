//! Administrative units: containers of users and groups that a directory role can be scoped to.
//!
//! Per Microsoft's administrativeUnit and scopedRoleMembership resources, a unit has `members`
//! (users and groups) and `scopedRoleMembers`, each naming an activated directory role and the
//! user who holds it over the unit's members. A role held over a unit applies to the unit's
//! direct members only: Microsoft's administrative units overview says adding a group brings
//! "the group itself into the management scope of the administrative unit, but **not** the
//! members of the group".
//!
//! v1.0 serves units under `/directory/administrativeUnits`, and beta also at `/administrativeUnits`,
//! which the azuread provider deletes through. Units and memberships are kept as Graph's JSON.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tracing::info;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::directory_roles::templates;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_id_from_odata_id, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::ObjectKind;

const ENTITY_SET: &str = "directory/administrativeUnits";
const PROPERTIES: [&str; 7] = [
    "displayName",
    "description",
    "visibility",
    "isMemberManagementRestricted",
    "membershipType",
    "membershipRule",
    "membershipRuleProcessingState",
];

/// Microsoft's "Roles that can be assigned with administrative unit scope".
const SCOPABLE_ROLES: [&str; 14] = [
    "Authentication Administrator",
    "Attribute Assignment Administrator",
    "Attribute Assignment Reader",
    "Cloud Device Administrator",
    "Groups Administrator",
    "Helpdesk Administrator",
    "License Administrator",
    "Password Administrator",
    "Printer Administrator",
    "Privileged Authentication Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Teams Devices Administrator",
    "User Administrator",
];

pub fn router() -> Router<AppState> {
    let mut router = Router::new();
    for prefix in ["/directory/administrativeUnits", "/administrativeUnits"] {
        router = router
            .route(prefix, get(list).post(create))
            .route(
                &format!("{prefix}/{{id}}"),
                get(read).patch(update).delete(remove),
            )
            .route(&format!("{prefix}/{{id}}/members"), get(members))
            .route(&format!("{prefix}/{{id}}/members/$ref"), post(add_member))
            .route(
                &format!("{prefix}/{{id}}/members/{{member_id}}/$ref"),
                delete(remove_member),
            )
            .route(
                &format!("{prefix}/{{id}}/scopedRoleMembers"),
                get(scoped_role_members).post(add_scoped_role_member),
            )
            .route(
                &format!("{prefix}/{{id}}/scopedRoleMembers/{{membership_id}}"),
                get(read_scoped_role_member).delete(remove_scoped_role_member),
            );
    }
    router
}

async fn list(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let objects = directory.administrative_units.values().cloned().collect();
    Ok(collection_response(&state, objects, &query, ENTITY_SET))
}

async fn read(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let unit = directory
        .administrative_units
        .get(&id)
        .cloned()
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(&state, unit, &query, ENTITY_SET))
}

async fn create(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;
    if fields.get("displayName").and_then(Value::as_str).is_none() {
        return Err(GraphError::invalid_request(
            "The property 'displayName' is required.",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let mut unit = Map::new();
    unit.insert("id".to_string(), json!(id));
    unit.insert("deletedDateTime".to_string(), Value::Null);
    for property in PROPERTIES {
        unit.insert(property.to_string(), Value::Null);
    }
    apply(&mut unit, fields, true)?;

    let unit = Value::Object(unit);
    let mut directory = state.store.write().await;
    directory
        .administrative_units
        .insert(id.clone(), unit.clone());
    directory
        .administrative_unit_members
        .insert(id.clone(), Vec::new());
    info!(unit_id = %id, "created administrative unit");
    Ok((StatusCode::CREATED, Json(unit)))
}

async fn update(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<StatusCode, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;
    let mut directory = state.store.write().await;
    let unit = directory
        .administrative_units
        .get_mut(&id)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    apply(unit, fields, false)?;
    info!(unit_id = %id, "updated administrative unit");
    Ok(StatusCode::NO_CONTENT)
}

async fn remove(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    if directory.administrative_units.remove(&id).is_none() {
        return Err(GraphError::resource_not_found(&id));
    }
    directory.administrative_unit_members.remove(&id);
    directory
        .scoped_role_memberships
        .retain(|_, membership| membership["administrativeUnitId"] != id.as_str());
    info!(unit_id = %id, "deleted administrative unit");
    Ok(StatusCode::NO_CONTENT)
}

/// Write a create or update body onto a unit.
fn apply(
    unit: &mut Map<String, Value>,
    fields: &Map<String, Value>,
    creating: bool,
) -> Result<(), GraphError> {
    for (name, value) in fields {
        if crate::graph::is_write_only_annotation(name) || name == "id" {
            continue;
        }
        if !PROPERTIES.contains(&name.as_str()) {
            return Err(GraphError::invalid_request(format!(
                "Property '{name}' does not exist on type 'microsoft.graph.administrativeUnit'."
            )));
        }
        // Microsoft: isMemberManagementRestricted "is immutable and can't be changed later".
        if name == "isMemberManagementRestricted" && !creating && unit.get(name) != Some(value) {
            return Err(GraphError::invalid_property(name));
        }
        if name == "visibility"
            && !value.is_null()
            && !matches!(value.as_str(), Some("Public" | "HiddenMembership"))
        {
            return Err(GraphError::invalid_property(name));
        }
        unit.insert(name.clone(), value.clone());
    }
    Ok(())
}

async fn members(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let members = directory
        .administrative_unit_members
        .get(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    let objects = members
        .iter()
        .filter_map(|member| directory.object(member).map(|(_, value)| value))
        .collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("directory/administrativeUnits('{id}')/members"),
    ))
}

#[derive(Debug, Deserialize)]
struct ReferenceBody {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

async fn add_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<ReferenceBody>,
) -> Result<StatusCode, GraphError> {
    let referenced = object_id_from_odata_id(&body.odata_id)?;
    let mut directory = state.store.write().await;
    if !directory.administrative_units.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }
    // Microsoft: members are "Users and groups".
    match directory.object(&referenced) {
        Some((ObjectKind::User | ObjectKind::Group, _)) => {}
        Some(_) => {
            return Err(GraphError::invalid_request(
                "Only users and groups can be members of an administrative unit.",
            ));
        }
        None => return Err(GraphError::resource_not_found(&referenced)),
    }
    let members = directory
        .administrative_unit_members
        .entry(id.clone())
        .or_default();
    if members.contains(&referenced) {
        return Err(GraphError::new(
            StatusCode::BAD_REQUEST,
            "Request_BadRequest",
            "One or more added object references already exist for the following modified \
             properties: 'members'.",
        ));
    }
    members.push(referenced.clone());
    info!(unit_id = %id, member_id = %referenced, "added an administrative unit member");
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, member_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let members = directory
        .administrative_unit_members
        .get_mut(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    let before = members.len();
    members.retain(|member| member != &member_id);
    if members.len() == before {
        return Err(GraphError::resource_not_found(&member_id));
    }
    info!(unit_id = %id, member_id = %member_id, "removed an administrative unit member");
    Ok(StatusCode::NO_CONTENT)
}

async fn scoped_role_members(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    if !directory.administrative_units.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }
    let objects = directory
        .scoped_role_memberships
        .values()
        .filter(|membership| membership["administrativeUnitId"] == id.as_str())
        .cloned()
        .collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("directory/administrativeUnits('{id}')/scopedRoleMembers"),
    ))
}

async fn read_scoped_role_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, membership_id)): Path<(String, String)>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let membership = directory
        .scoped_role_memberships
        .get(&membership_id)
        .filter(|membership| membership["administrativeUnitId"] == id.as_str())
        .cloned()
        .ok_or_else(|| GraphError::resource_not_found(&membership_id))?;
    Ok(object_response(
        &state,
        membership,
        &query,
        &format!("directory/administrativeUnits('{id}')/scopedRoleMembers"),
    ))
}

async fn add_scoped_role_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let role_id = body["roleId"]
        .as_str()
        .ok_or_else(|| GraphError::invalid_request("'roleId' is required."))?;
    let member_id = body["roleMemberInfo"]["id"]
        .as_str()
        .ok_or_else(|| GraphError::invalid_request("'roleMemberInfo.id' is required."))?;

    let mut directory = state.store.write().await;
    if !directory.administrative_units.contains_key(&id) {
        return Err(GraphError::resource_not_found(&id));
    }
    // `roleId` names an activated directory role object.
    let role = directory
        .directory_roles
        .get(role_id)
        .ok_or_else(|| GraphError::resource_not_found(role_id))?;
    let scopable = templates().into_iter().any(|template| {
        template.id == role.role_template_id
            && SCOPABLE_ROLES.contains(&template.display_name.as_str())
    });
    if !scopable {
        return Err(GraphError::invalid_request(format!(
            "The role {:?} cannot be assigned with administrative unit scope.",
            role.display_name
        )));
    }
    let display_name = match directory.object(member_id) {
        Some((ObjectKind::User | ObjectKind::Group, value)) => value["displayName"].clone(),
        Some(_) => {
            return Err(GraphError::invalid_request(
                "Only a user or a group can hold a role over an administrative unit.",
            ));
        }
        None => return Err(GraphError::resource_not_found(member_id)),
    };
    if directory.scoped_role_memberships.values().any(|existing| {
        existing["administrativeUnitId"] == id.as_str()
            && existing["roleId"] == role_id
            && existing["roleMemberInfo"]["id"] == member_id
    }) {
        return Err(GraphError::object_conflict(
            "A conflicting object with one or more of the specified property values is present \
             in the directory.",
        ));
    }

    let membership_id = Uuid::new_v4().to_string();
    let membership = json!({
        "id": membership_id,
        "administrativeUnitId": id,
        "roleId": role_id,
        "roleMemberInfo": { "id": member_id, "displayName": display_name }
    });
    directory
        .scoped_role_memberships
        .insert(membership_id.clone(), membership.clone());
    info!(unit_id = %id, role_id = %role_id, member_id = %member_id, "added a scoped role member");
    Ok((StatusCode::CREATED, Json(membership)))
}

async fn remove_scoped_role_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, membership_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let found = directory
        .scoped_role_memberships
        .get(&membership_id)
        .is_some_and(|membership| membership["administrativeUnitId"] == id.as_str());
    if !found {
        return Err(GraphError::resource_not_found(&membership_id));
    }
    directory.scoped_role_memberships.remove(&membership_id);
    info!(unit_id = %id, membership_id = %membership_id, "removed a scoped role member");
    Ok(StatusCode::NO_CONTENT)
}
