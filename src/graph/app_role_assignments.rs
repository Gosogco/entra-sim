//! App role assignments.
//!
//! Graph exposes the same objects from both ends, and the distinction matters:
//!
//! - `appRoleAssignedTo` on a service principal lists assignments where that principal is the
//!   **resource** defining the role, which is how you ask "who has access to this API?".
//! - `appRoleAssignments` on a principal lists assignments where it is the **recipient**, which
//!   is how you ask "what can this identity do?".
//!
//! An assignment is what puts a value in an app-only token's `roles` claim, so creating one
//! here changes what the token endpoint issues next.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::collection_response;
use crate::graph::error::GraphError;
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::model::AppRoleAssignment;
use crate::store::{Directory, ObjectKind};

/// Entra uses the all-zero GUID to grant access to an application without granting a role.
const NO_ROLE: &str = "00000000-0000-0000-0000-000000000000";

/// Which side of the relationship a request is looking from.
#[derive(Debug, Clone, Copy)]
enum Side {
    /// The path names the resource defining the role.
    Resource,
    /// The path names the principal receiving the role.
    Principal,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/servicePrincipals/{id}/appRoleAssignedTo",
            get(list_assigned_to).post(create_assigned_to),
        )
        .route(
            "/servicePrincipals/{id}/appRoleAssignedTo/{assignment_id}",
            axum::routing::delete(delete_assignment),
        )
        .route(
            "/servicePrincipals/{id}/appRoleAssignments",
            get(list_assignments).post(create_assignment),
        )
        .route(
            "/servicePrincipals/{id}/appRoleAssignments/{assignment_id}",
            axum::routing::delete(delete_assignment),
        )
        .route(
            "/users/{id}/appRoleAssignments",
            get(list_assignments).post(create_assignment),
        )
        .route(
            "/users/{id}/appRoleAssignments/{assignment_id}",
            axum::routing::delete(delete_assignment),
        )
        .route("/groups/{id}/appRoleAssignments", get(list_assignments))
        .route(
            "/oauth2PermissionGrants",
            get(list_grants).post(create_grant),
        )
        .route(
            "/oauth2PermissionGrants/{id}",
            get(read_grant).patch(update_grant).delete(delete_grant),
        )
        .route(
            "/servicePrincipals/{id}/oauth2PermissionGrants",
            get(list_principal_grants),
        )
        // Graph exposes this only as an action on the service principal.
        .route(
            "/servicePrincipals/{id}/appRoleAssignedTo/$ref",
            post(create_assigned_to),
        )
}

async fn list_assigned_to(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    list_side(state, caller, path, query, Side::Resource).await
}

async fn list_assignments(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    query: AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    list_side(state, caller, path, query, Side::Principal).await
}

async fn list_side(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
    side: Side,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;

    // The path may name a service principal by appId, so resolve to an object ID first.
    let subject = resolve_subject(&directory, &id)?;

    let objects = directory
        .app_role_assignments
        .values()
        .filter(|assignment| match side {
            Side::Resource => assignment.resource_id == subject,
            Side::Principal => assignment.principal_id == subject,
        })
        .map(|assignment| serde_json::to_value(assignment).unwrap_or(Value::Null))
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        "appRoleAssignments",
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentRequest {
    #[serde(default)]
    app_role_id: Option<String>,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    resource_id: Option<String>,
}

async fn create_assigned_to(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    body: Json<AssignmentRequest>,
) -> Result<impl IntoResponse, GraphError> {
    create_side(state, caller, path, body, Side::Resource).await
}

async fn create_assignment(
    state: State<AppState>,
    caller: Caller,
    path: Path<String>,
    body: Json<AssignmentRequest>,
) -> Result<impl IntoResponse, GraphError> {
    create_side(state, caller, path, body, Side::Principal).await
}

async fn create_side(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<AssignmentRequest>,
    side: Side,
) -> Result<impl IntoResponse, GraphError> {
    let mut directory = state.store.write().await;
    let subject = resolve_subject(&directory, &id)?;

    // The path fixes one end of the relationship; the body supplies the other.
    let (principal_id, resource_id) = match side {
        Side::Resource => (
            body.principal_id.clone().ok_or_else(|| {
                GraphError::invalid_request(
                    "The property \"principalId\" is required and must be a string.",
                )
            })?,
            subject,
        ),
        Side::Principal => (
            subject,
            body.resource_id.clone().ok_or_else(|| {
                GraphError::invalid_request(
                    "The property \"resourceId\" is required and must be a string.",
                )
            })?,
        ),
    };

    let app_role_id = body
        .app_role_id
        .clone()
        .unwrap_or_else(|| NO_ROLE.to_string());

    let (principal_kind, principal) = directory
        .object(&principal_id)
        .ok_or_else(|| GraphError::resource_not_found(&principal_id))?;

    let resource = directory
        .service_principals
        .get(&resource_id)
        .ok_or_else(|| GraphError::resource_not_found(&resource_id))?;

    // An assignment naming a role the resource does not define would grant nothing, so refuse
    // it rather than store something inert.
    if app_role_id != NO_ROLE && !resource.app_roles.iter().any(|role| role.id == app_role_id) {
        return Err(GraphError::invalid_request(format!(
            "The appRoleId {app_role_id:?} is not defined by the resource service principal \
             {resource_id:?}."
        )));
    }

    let already_granted = directory.app_role_assignments.values().any(|assignment| {
        assignment.principal_id == principal_id
            && assignment.resource_id == resource_id
            && assignment.app_role_id == app_role_id
    });
    if already_granted {
        return Err(GraphError::object_conflict(
            "Permission being assigned already exists on the object.",
        ));
    }

    let assignment = AppRoleAssignment {
        id: Uuid::new_v4().to_string(),
        app_role_id,
        principal_id,
        principal_display_name: principal["displayName"].as_str().map(str::to_string),
        principal_type: principal_type_name(principal_kind).to_string(),
        resource_id,
        resource_display_name: Some(resource.display_name.clone()),
        created_date_time: OffsetDateTime::now_utc(),
    };

    let body = serde_json::to_value(&assignment)
        .map_err(|error| GraphError::internal(format!("serialising an assignment: {error}")))?;
    directory
        .app_role_assignments
        .insert(assignment.id.clone(), assignment);

    Ok((StatusCode::CREATED, Json(body)))
}

async fn delete_assignment(
    State(state): State<AppState>,
    _caller: Caller,
    Path((_id, assignment_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    if directory
        .app_role_assignments
        .remove(&assignment_id)
        .is_none()
    {
        return Err(GraphError::resource_not_found(&assignment_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_grants(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let objects = directory
        .oauth2_permission_grants
        .values()
        .map(|grant| serde_json::to_value(grant).unwrap_or(Value::Null))
        .collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        "oauth2PermissionGrants",
    ))
}

async fn list_principal_grants(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let subject = resolve_subject(&directory, &id)?;

    let objects = directory
        .oauth2_permission_grants
        .values()
        .filter(|grant| grant.client_id == subject)
        .map(|grant| serde_json::to_value(grant).unwrap_or(Value::Null))
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        "oauth2PermissionGrants",
    ))
}

async fn read_grant(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, GraphError> {
    let directory = state.store.read().await;
    let grant = directory
        .oauth2_permission_grants
        .get(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(Json(serde_json::to_value(grant).unwrap_or(Value::Null)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantRequest {
    client_id: String,
    #[serde(default)]
    consent_type: Option<String>,
    #[serde(default)]
    principal_id: Option<String>,
    resource_id: String,
    #[serde(default)]
    scope: Option<String>,
}

async fn create_grant(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<GrantRequest>,
) -> Result<impl IntoResponse, GraphError> {
    let consent_type = body
        .consent_type
        .clone()
        .unwrap_or_else(|| "AllPrincipals".to_string());

    // Graph requires a principal for per-user consent and forbids one for tenant-wide consent,
    // because the two mean different things and silently accepting either would hide a mistake.
    match consent_type.as_str() {
        "AllPrincipals" if body.principal_id.is_some() => {
            return Err(GraphError::invalid_request(
                "principalId must not be set when consentType is 'AllPrincipals'.",
            ));
        }
        "Principal" if body.principal_id.is_none() => {
            return Err(GraphError::invalid_request(
                "principalId is required when consentType is 'Principal'.",
            ));
        }
        "AllPrincipals" | "Principal" => {}
        other => {
            return Err(GraphError::invalid_request(format!(
                "The consentType {other:?} is not valid; expected 'AllPrincipals' or 'Principal'."
            )));
        }
    }

    let mut directory = state.store.write().await;
    for (property, id) in [
        ("clientId", &body.client_id),
        ("resourceId", &body.resource_id),
    ] {
        if !directory.service_principals.contains_key(id) {
            return Err(GraphError::invalid_request(format!(
                "The {property} {id:?} does not refer to a service principal in this directory."
            )));
        }
    }
    if let Some(principal_id) = &body.principal_id
        && !directory.contains_object(principal_id)
    {
        return Err(GraphError::resource_not_found(principal_id));
    }

    let grant = crate::store::model::OAuth2PermissionGrant {
        id: Uuid::new_v4().to_string(),
        client_id: body.client_id,
        consent_type,
        principal_id: body.principal_id,
        resource_id: body.resource_id,
        scope: body.scope.unwrap_or_default(),
    };

    let value = serde_json::to_value(&grant)
        .map_err(|error| GraphError::internal(format!("serialising a grant: {error}")))?;
    directory
        .oauth2_permission_grants
        .insert(grant.id.clone(), grant);
    Ok((StatusCode::CREATED, Json(value)))
}

async fn update_grant(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let grant = directory
        .oauth2_permission_grants
        .get_mut(&id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    // `scope` is the only property Graph lets a client change on an existing grant.
    if let Some(scope) = body.get("scope") {
        grant.scope = scope
            .as_str()
            .ok_or_else(|| GraphError::invalid_property("scope"))?
            .to_string();
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_grant(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    if directory.oauth2_permission_grants.remove(&id).is_none() {
        return Err(GraphError::resource_not_found(&id));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Resolve the object named in the path, accepting a service principal's `appId` as Graph does.
fn resolve_subject(directory: &Directory, id: &str) -> Result<String, GraphError> {
    if directory.contains_object(id) {
        return Ok(id.to_string());
    }
    directory
        .service_principal_by_app_id(id)
        .map(|principal| principal.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(id))
}

fn principal_type_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::User => "User",
        ObjectKind::Group => "Group",
        ObjectKind::ServicePrincipal => "ServicePrincipal",
    }
}
