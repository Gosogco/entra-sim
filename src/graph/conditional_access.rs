//! Conditional access policies, at `/identity/conditionalAccess/policies`.
//!
//! A policy is kept as Graph's JSON, because its condition and control types are many and the
//! simulator stores them to echo them back and to evaluate the parts it can (see
//! `auth::conditional_access`). Per Microsoft's conditionalAccessPolicy resource, `conditions` and
//! `state` are required, `state` is `enabled`, `disabled` or `enabledForReportingButNotEnforced`,
//! and `id`, `createdDateTime` and `modifiedDateTime` are read-only.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::info;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;

const ENTITY_SET: &str = "identity/conditionalAccess/policies";
const STATES: [&str; 3] = ["enabled", "disabled", "enabledForReportingButNotEnforced"];
const READ_ONLY: [&str; 3] = ["id", "createdDateTime", "modifiedDateTime"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/identity/conditionalAccess/policies",
            get(list).post(create),
        )
        .route(
            "/identity/conditionalAccess/policies/{id}",
            get(read).patch(update).delete(delete),
        )
}

async fn list(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let objects = directory
        .conditional_access_policies
        .values()
        .cloned()
        .collect();
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
    let policy = directory
        .conditional_access_policies
        .get(&id)
        .cloned()
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(&state, policy, &query, ENTITY_SET))
}

async fn create(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;
    for required in ["displayName", "state", "conditions"] {
        if fields.get(required).is_none_or(Value::is_null) {
            return Err(GraphError::invalid_request(format!(
                "The property '{required}' is required."
            )));
        }
    }

    let mut policy = Map::new();
    let id = Uuid::new_v4().to_string();
    policy.insert("id".to_string(), json!(id));
    policy.insert("templateId".to_string(), Value::Null);
    policy.insert("createdDateTime".to_string(), json!(now()));
    policy.insert("modifiedDateTime".to_string(), Value::Null);
    apply(&mut policy, fields)?;

    let policy = Value::Object(policy);
    state
        .store
        .write()
        .await
        .conditional_access_policies
        .insert(id.clone(), policy.clone());
    info!(policy_id = %id, "created conditional access policy");
    Ok((StatusCode::CREATED, Json(policy)))
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
    let policy = directory
        .conditional_access_policies
        .get_mut(&id)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    apply(policy, fields)?;
    policy.insert("modifiedDateTime".to_string(), json!(now()));
    info!(policy_id = %id, "updated conditional access policy");
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let removed = state
        .store
        .write()
        .await
        .conditional_access_policies
        .remove(&id);
    if removed.is_none() {
        return Err(GraphError::resource_not_found(&id));
    }
    info!(policy_id = %id, "deleted conditional access policy");
    Ok(StatusCode::NO_CONTENT)
}

/// Write a create or update body onto a policy. A complex property is replaced whole, which is
/// how the azuread provider sends one.
fn apply(policy: &mut Map<String, Value>, fields: &Map<String, Value>) -> Result<(), GraphError> {
    for (name, value) in fields {
        if READ_ONLY.contains(&name.as_str()) || crate::graph::is_write_only_annotation(name) {
            continue;
        }
        if name == "state" && !value.as_str().is_some_and(|state| STATES.contains(&state)) {
            return Err(GraphError::invalid_property("state"));
        }
        policy.insert(name.clone(), value.clone());
    }
    Ok(())
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
