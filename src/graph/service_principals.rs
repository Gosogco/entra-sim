//! The `/servicePrincipals` collection.
//!
//! A service principal is what an application becomes inside a tenant: assignments are made
//! against it, and an issued token represents it rather than the registration.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_id_from_odata_id, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::Directory;
use crate::store::model::ServicePrincipal;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/servicePrincipals", get(list).post(create))
        .route(
            "/servicePrincipals/{id}",
            get(read).patch(update).put(update).delete(delete),
        )
        .route("/servicePrincipals/{id}/owners", get(owners))
        .route("/servicePrincipals/{id}/owners/$ref", post(add_owner))
        .route(
            "/servicePrincipals/{id}/owners/{owner_id}/$ref",
            axum::routing::delete(remove_owner),
        )
        .route("/servicePrincipals/{id}/memberOf", get(member_of))
}

async fn list(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let objects = directory
        .service_principals
        .values()
        .map(serialise)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(collection_response(
        &state,
        objects,
        &query,
        "servicePrincipals",
    ))
}

async fn read(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let principal = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(
        &state,
        serialise(principal)?,
        &query,
        "servicePrincipals",
    ))
}

async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;

    // Graph accepts either name for the client identifier, and the azuread provider sends
    // `clientId` on newer versions and `appId` on older ones.
    let app_id = fields
        .get("appId")
        .or_else(|| fields.get("clientId"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GraphError::invalid_request("The property \"appId\" is required and must be a string.")
        })?
        .to_string();

    let mut directory = state.store.write().await;

    let application = directory
        .application_by_app_id(&app_id)
        .ok_or_else(|| {
            // Entra refuses to create a principal for an application it does not know.
            GraphError::new(
                StatusCode::BAD_REQUEST,
                "Request_BadRequest",
                format!("The appId {app_id:?} does not refer to an application in this directory."),
            )
        })?
        .clone();

    if directory.service_principal_by_app_id(&app_id).is_some() {
        return Err(GraphError::object_conflict(format!(
            "A service principal for appId {app_id:?} already exists in this directory."
        )));
    }

    let mut principal = ServicePrincipal::for_application(Uuid::new_v4().to_string(), &application);
    // As with an application, Entra makes the creating identity the initial owner, and the
    // azuread provider removes it when the configuration declares no owners.
    principal.owners = vec![caller.claims.oid.clone()];
    apply_all(&mut principal, fields)?;

    let body = serialise(&principal)?;
    directory
        .service_principals
        .insert(principal.id.clone(), principal);
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
    let key = lookup(&directory, &id)
        .map(|principal| principal.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let principal = directory
        .service_principals
        .get_mut(&key)
        .expect("key came from lookup");
    apply_all(principal, patch)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|principal| principal.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    directory.service_principals.remove(&key);

    // A deleted principal must stop appearing in group membership.
    for group in directory.groups.values_mut() {
        group.members.retain(|member| member != &key);
        group.owners.retain(|owner| owner != &key);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn apply_all(
    principal: &mut ServicePrincipal,
    fields: &Map<String, Value>,
) -> Result<(), GraphError> {
    for (property, value) in fields {
        match property.as_str() {
            // Entra owns the object ID, and the application link cannot be retargeted.
            "id" | "appId" | "clientId" => {
                if property == "id" {
                    return Err(GraphError::invalid_request(
                        "The property 'id' is read-only and cannot be modified.",
                    ));
                }
            }
            "displayName" => {
                principal.display_name = value
                    .as_str()
                    .ok_or_else(|| GraphError::invalid_property("displayName"))?
                    .to_string();
            }
            "appRoleAssignmentRequired" => {
                principal.app_role_assignment_required = value
                    .as_bool()
                    .ok_or_else(|| GraphError::invalid_property("appRoleAssignmentRequired"))?;
            }
            "tags" => {
                principal.tags = value
                    .as_array()
                    .ok_or_else(|| GraphError::invalid_property("tags"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
            "servicePrincipalNames" => {
                principal.service_principal_names = value
                    .as_array()
                    .ok_or_else(|| GraphError::invalid_property("servicePrincipalNames"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
            // Permissions are defined on the application, not here.
            "appRoles" | "oauth2PermissionScopes" | "createdDateTime" => {}
            other if crate::graph::is_write_only_annotation(other) => {}
            other => {
                // An explicit null is stored rather than removed, so a read echoes `null` as
                // Graph does.
                principal.extra.insert(other.to_string(), value.clone());
            }
        }
    }
    Ok(())
}

async fn owners(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let principal = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    let mut objects: Vec<Value> = principal
        .owners
        .iter()
        .filter_map(|owner| directory.object(owner).map(|(_, value)| value))
        .collect();
    objects.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("servicePrincipals('{id}')/owners"),
    ))
}

#[derive(Debug, Deserialize)]
struct ReferenceBody {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

async fn add_owner(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<ReferenceBody>,
) -> Result<StatusCode, GraphError> {
    let referenced = object_id_from_odata_id(&body.odata_id)?;

    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|principal| principal.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    if !directory.contains_object(&referenced) {
        return Err(GraphError::resource_not_found(&referenced));
    }

    let owners = &mut directory
        .service_principals
        .get_mut(&key)
        .expect("key came from lookup")
        .owners;
    if owners.iter().any(|owner| owner == &referenced) {
        return Err(GraphError::new(
            StatusCode::BAD_REQUEST,
            "Request_BadRequest",
            "One or more added object references already exist for the following modified \
             properties: 'owners'.",
        ));
    }
    owners.push(referenced);
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_owner(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, owner_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|principal| principal.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let owners = &mut directory
        .service_principals
        .get_mut(&key)
        .expect("key came from lookup")
        .owners;
    let before = owners.len();
    owners.retain(|owner| owner != &owner_id);
    if owners.len() == before {
        return Err(GraphError::resource_not_found(&owner_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn member_of(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let principal = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    let objects = directory
        .groups_containing(&principal.id)
        .into_iter()
        .filter_map(|group| directory.object(&group.id).map(|(_, value)| value))
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("servicePrincipals('{id}')/memberOf"),
    ))
}

/// Look up by object ID, or by `appId`, which is how most clients address a principal.
fn lookup<'a>(directory: &'a Directory, id: &str) -> Option<&'a ServicePrincipal> {
    directory
        .service_principals
        .get(id)
        .or_else(|| directory.service_principal_by_app_id(id))
}

fn serialise(principal: &ServicePrincipal) -> Result<Value, GraphError> {
    serde_json::to_value(principal)
        .map_err(|error| GraphError::internal(format!("serialising a service principal: {error}")))
}
