//! Directory roles, their built-in templates, and the `roleManagement` view of the same thing.
//!
//! Entra ships a fixed set of role templates. A template is inert until it is activated in the
//! tenant, at which point it becomes a `directoryRole` with its own object ID that principals
//! can be made members of. `azuread_directory_role` activates by template ID, so the real
//! template identifiers have to be the ones Microsoft publishes.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_id_from_odata_id, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::model::{DirectoryRole, DirectoryRoleTemplate};

const TEMPLATES: &str = include_str!("directory_roles.json");

/// The built-in role templates, generated from Microsoft's published role reference by
/// `scripts/generate-directory-roles.py`.
pub fn templates() -> Vec<DirectoryRoleTemplate> {
    serde_json::from_str(TEMPLATES)
        .expect("the embedded directory role template catalogue should parse")
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/directoryRoleTemplates", get(list_templates))
        .route("/directoryRoleTemplates/{id}", get(read_template))
        .route("/directoryRoles", get(list).post(activate))
        .route("/directoryRoles/{id}", get(read))
        .route("/directoryRoles/{id}/members", get(members))
        .route("/directoryRoles/{id}/members/$ref", post(add_member))
        .route(
            "/directoryRoles/{id}/members/{member_id}/$ref",
            axum::routing::delete(remove_member),
        )
        // roleManagement is the newer view over the same built-in roles.
        .route(
            "/roleManagement/directory/roleDefinitions",
            get(list_role_definitions),
        )
        .route(
            "/roleManagement/directory/roleDefinitions/{id}",
            get(read_role_definition),
        )
        .route(
            "/roleManagement/directory/roleAssignments",
            get(list_role_assignments).post(create_role_assignment),
        )
        .route(
            "/roleManagement/directory/roleAssignments/{id}",
            get(read_role_assignment).delete(delete_role_assignment),
        )
}

async fn list_templates(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let objects = templates()
        .iter()
        .map(|template| serde_json::to_value(template).unwrap_or(Value::Null))
        .collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        "directoryRoleTemplates",
    ))
}

async fn read_template(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let template = templates()
        .into_iter()
        .find(|template| template.id == id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(
        &state,
        serde_json::to_value(&template).unwrap_or(Value::Null),
        &query,
        "directoryRoleTemplates",
    ))
}

async fn list(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    // Only activated roles appear here; a template that has never been activated does not.
    let objects = directory
        .directory_roles
        .values()
        .map(|role| serde_json::to_value(role).unwrap_or(Value::Null))
        .collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        "directoryRoles",
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
    let role = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(
        &state,
        serde_json::to_value(role).unwrap_or(Value::Null),
        &query,
        "directoryRoles",
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivateRequest {
    role_template_id: String,
}

async fn activate(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<ActivateRequest>,
) -> Result<impl IntoResponse, GraphError> {
    let template = templates()
        .into_iter()
        .find(|template| template.id == body.role_template_id)
        .ok_or_else(|| {
            GraphError::invalid_request(format!(
                "The roleTemplateId {:?} does not name a built-in directory role.",
                body.role_template_id
            ))
        })?;

    let mut directory = state.store.write().await;
    if let Some(existing) = directory
        .directory_roles
        .values()
        .find(|role| role.role_template_id == template.id)
    {
        // Activating an already-active role is a conflict in Graph, not a no-op, and clients
        // rely on the distinction to decide whether they activated it.
        return Err(GraphError::object_conflict(format!(
            "A conflicting object with one or more of the specified property values is present \
             in the directory. The role {:?} is already activated as {:?}.",
            template.display_name, existing.id
        )));
    }

    let role = DirectoryRole {
        id: Uuid::new_v4().to_string(),
        role_template_id: template.id,
        display_name: template.display_name,
        description: template.description,
        members: Vec::new(),
    };

    let value = serde_json::to_value(&role)
        .map_err(|error| GraphError::internal(format!("serialising a directory role: {error}")))?;
    directory.directory_roles.insert(role.id.clone(), role);
    Ok((StatusCode::CREATED, Json(value)))
}

async fn members(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let role = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    let mut objects: Vec<Value> = role
        .members
        .iter()
        .filter_map(|member| directory.object(member).map(|(_, value)| value))
        .collect();
    objects.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("directoryRoles('{id}')/members"),
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
    let key = lookup(&directory, &id)
        .map(|role| role.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    if !directory.contains_object(&referenced) {
        return Err(GraphError::resource_not_found(&referenced));
    }

    let members = &mut directory
        .directory_roles
        .get_mut(&key)
        .expect("key came from lookup")
        .members;
    if members.iter().any(|member| member == &referenced) {
        return Err(GraphError::new(
            StatusCode::BAD_REQUEST,
            "Request_BadRequest",
            "One or more added object references already exist for the following modified \
             properties: 'members'.",
        ));
    }
    members.push(referenced);
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, member_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|role| role.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let members = &mut directory
        .directory_roles
        .get_mut(&key)
        .expect("key came from lookup")
        .members;
    let before = members.len();
    members.retain(|member| member != &member_id);
    if members.len() == before {
        return Err(GraphError::resource_not_found(&member_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `roleManagement` reports every built-in role as a definition, whether activated or not.
async fn list_role_definitions(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let objects = templates().iter().map(role_definition).collect();
    Ok(collection_response(
        &state,
        objects,
        &query,
        "roleManagement/directory/roleDefinitions",
    ))
}

async fn read_role_definition(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let template = templates()
        .into_iter()
        .find(|template| template.id == id)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(
        &state,
        role_definition(&template),
        &query,
        "roleManagement/directory/roleDefinitions",
    ))
}

/// A built-in role as a `unifiedRoleDefinition`.
fn role_definition(template: &DirectoryRoleTemplate) -> Value {
    serde_json::json!({
        "id": template.id,
        "templateId": template.id,
        "displayName": template.display_name,
        "description": template.description,
        // Built-in roles are not editable and have no tenant-specific version.
        "isBuiltIn": true,
        "isEnabled": true,
        "version": "1",
        "rolePermissions": [],
    })
}

async fn list_role_assignments(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;

    // A directory role's membership is the same relationship roleManagement calls an
    // assignment, so it is reported from one place rather than stored twice.
    let objects = directory
        .directory_roles
        .values()
        .flat_map(|role| {
            role.members.iter().map(move |member| {
                serde_json::json!({
                    "id": unified_assignment_id(&role.role_template_id, member),
                    "roleDefinitionId": role.role_template_id,
                    "principalId": member,
                    "directoryScopeId": "/",
                })
            })
        })
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        "roleManagement/directory/roleAssignments",
    ))
}

async fn read_role_assignment(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, GraphError> {
    let directory = state.store.read().await;
    let found = directory.directory_roles.values().find_map(|role| {
        role.members
            .iter()
            .find(|member| unified_assignment_id(&role.role_template_id, member) == id)
            .map(|member| {
                serde_json::json!({
                    "id": id,
                    "roleDefinitionId": role.role_template_id,
                    "principalId": member,
                    "directoryScopeId": "/",
                })
            })
    });
    found
        .map(Json)
        .ok_or_else(|| GraphError::resource_not_found(&id))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleAssignmentRequest {
    role_definition_id: String,
    principal_id: String,
}

async fn create_role_assignment(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<RoleAssignmentRequest>,
) -> Result<impl IntoResponse, GraphError> {
    let template = templates()
        .into_iter()
        .find(|template| template.id == body.role_definition_id)
        .ok_or_else(|| {
            GraphError::invalid_request(format!(
                "The roleDefinitionId {:?} does not name a built-in directory role.",
                body.role_definition_id
            ))
        })?;

    let mut directory = state.store.write().await;
    if !directory.contains_object(&body.principal_id) {
        return Err(GraphError::resource_not_found(&body.principal_id));
    }

    // Assigning through roleManagement activates the role if it is not active yet, which is
    // what Entra does; requiring a separate activation call would be a surprise.
    let key = match directory
        .directory_roles
        .values()
        .find(|role| role.role_template_id == template.id)
    {
        Some(existing) => existing.id.clone(),
        None => {
            let role = DirectoryRole {
                id: Uuid::new_v4().to_string(),
                role_template_id: template.id.clone(),
                display_name: template.display_name.clone(),
                description: template.description.clone(),
                members: Vec::new(),
            };
            let key = role.id.clone();
            directory.directory_roles.insert(key.clone(), role);
            key
        }
    };

    let role = directory
        .directory_roles
        .get_mut(&key)
        .expect("just inserted or found");
    if role
        .members
        .iter()
        .any(|member| member == &body.principal_id)
    {
        return Err(GraphError::object_conflict(
            "A conflicting object with one or more of the specified property values is present \
             in the directory.",
        ));
    }
    role.members.push(body.principal_id.clone());

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": unified_assignment_id(&template.id, &body.principal_id),
            "roleDefinitionId": template.id,
            "principalId": body.principal_id,
            "directoryScopeId": "/",
        })),
    ))
}

async fn delete_role_assignment(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;

    let target = directory.directory_roles.values().find_map(|role| {
        role.members
            .iter()
            .find(|member| unified_assignment_id(&role.role_template_id, member) == id)
            .map(|member| (role.id.clone(), member.clone()))
    });
    let Some((role_id, member)) = target else {
        return Err(GraphError::resource_not_found(&id));
    };

    directory
        .directory_roles
        .get_mut(&role_id)
        .expect("role came from the search above")
        .members
        .retain(|existing| existing != &member);
    Ok(StatusCode::NO_CONTENT)
}

/// The identifier `roleManagement` uses for an assignment.
///
/// Derived from the pair it describes rather than stored, because the underlying relationship is
/// the role's membership list and inventing a second identity for it would let the two diverge.
fn unified_assignment_id(role_definition_id: &str, principal_id: &str) -> String {
    format!("{role_definition_id}_{principal_id}")
}

/// Look up an activated role by object ID or by the template it came from.
fn lookup<'a>(directory: &'a crate::store::Directory, id: &str) -> Option<&'a DirectoryRole> {
    directory.directory_roles.get(id).or_else(|| {
        directory
            .directory_roles
            .values()
            .find(|role| role.role_template_id == id)
    })
}
