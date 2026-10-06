//! The `/users` collection.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::model::User;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me", get(me))
        .route("/users", get(list).post(create))
        .route(
            "/users/{id}",
            get(read).patch(update).put(update).delete(delete),
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
        .users
        .values()
        .map(serialise)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(collection_response(&state, objects, &query, "users"))
}

/// `GET /me` returns the signed-in user.
///
/// Refused for an app-only token. `/me` means "whoever is signed in", and an app-only token has
/// no user. Real Graph refuses it for the same reason, and a simulator that answered would hide
/// a client that had asked for the wrong kind of token.
async fn me(
    State(state): State<AppState>,
    caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;

    if caller.claims.scp.is_none() {
        return Err(GraphError::invalid_request(
            "/me request is only valid with delegated authentication flow.",
        ));
    }

    let directory = state.store.read().await;
    // The token's `oid` names the user it was issued for.
    let user = directory
        .users
        .get(&caller.claims.oid)
        .ok_or_else(|| GraphError::resource_not_found(&caller.claims.oid))?;

    Ok(object_response(&state, serialise(user)?, &query, "users"))
}

async fn read(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let user = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    Ok(object_response(&state, serialise(user)?, &query, "users"))
}

async fn create(
    State(state): State<AppState>,
    _caller: Caller,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, GraphError> {
    let fields = body
        .as_object()
        .ok_or_else(|| GraphError::invalid_request("The request body must be a JSON object."))?;

    let user_principal_name = required_string(fields, "userPrincipalName")?;
    let display_name = required_string(fields, "displayName")?;

    let mut directory = state.store.write().await;
    if directory
        .user_by_principal_name(&user_principal_name)
        .is_some()
    {
        return Err(GraphError::object_conflict(format!(
            "Another object with the same value for property userPrincipalName already exists. \
             Value: {user_principal_name:?}"
        )));
    }

    let mut extra = fields.clone();
    extra.retain(|property, _| !crate::graph::is_write_only_annotation(property));
    // Consume the properties the simulator models explicitly so they are not duplicated in the
    // flattened remainder, where they would serialise twice.
    for key in [
        "id",
        "userPrincipalName",
        "displayName",
        "accountEnabled",
        "mailNickname",
        "givenName",
        "surname",
        "jobTitle",
        "mail",
        "userType",
        "createdDateTime",
        "passwordProfile",
    ] {
        extra.remove(key);
    }

    let user = User {
        id: Uuid::new_v4().to_string(),
        user_principal_name,
        display_name,
        // Graph defaults a new user to enabled only when asked; the property is required in
        // practice, so default to disabled rather than silently enabling an account.
        account_enabled: fields
            .get("accountEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        mail_nickname: optional_string(fields, "mailNickname"),
        given_name: optional_string(fields, "givenName"),
        surname: optional_string(fields, "surname"),
        job_title: optional_string(fields, "jobTitle"),
        mail: optional_string(fields, "mail"),
        user_type: optional_string(fields, "userType").or_else(|| Some("Member".to_string())),
        created_date_time: OffsetDateTime::now_utc(),
        password: password_from_profile(fields),
        extra,
    };

    let body = serialise(&user)?;
    directory.users.insert(user.id.clone(), user);
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
    let key = lookup_key(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;
    let user = directory.users.get_mut(&key).expect("key came from lookup");

    for (property, value) in patch {
        apply(user, property, value)?;
    }

    // Graph answers a successful PATCH with no body.
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup_key(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;
    directory.users.remove(&key);
    Ok(StatusCode::NO_CONTENT)
}

/// Apply one property from a PATCH body.
fn apply(user: &mut User, property: &str, value: &Value) -> Result<(), GraphError> {
    let as_string = || value.as_str().map(str::to_string);
    match property {
        // Graph rejects an attempt to change an object's identity.
        "id" => {
            return Err(GraphError::invalid_request(
                "The property 'id' is read-only and cannot be modified.",
            ));
        }
        "userPrincipalName" => {
            user.user_principal_name = value
                .as_str()
                .ok_or_else(|| GraphError::invalid_property("userPrincipalName"))?
                .to_string();
        }
        "displayName" => {
            user.display_name = value
                .as_str()
                .ok_or_else(|| GraphError::invalid_property("displayName"))?
                .to_string();
        }
        "accountEnabled" => {
            user.account_enabled = value
                .as_bool()
                .ok_or_else(|| GraphError::invalid_property("accountEnabled"))?;
        }
        "mailNickname" => user.mail_nickname = as_string(),
        "givenName" => user.given_name = as_string(),
        "surname" => user.surname = as_string(),
        "jobTitle" => user.job_title = as_string(),
        "mail" => user.mail = as_string(),
        "userType" => user.user_type = as_string(),
        "passwordProfile" => {
            if let Some(password) = value.get("password").and_then(Value::as_str) {
                user.password = Some(password.to_string());
            }
        }
        // Directives and annotations describe the request, not the user, so storing one would
        // echo it back on every read.
        other if crate::graph::is_write_only_annotation(other) => {}
        // Anything the simulator has no opinion about is kept verbatim, so it round-trips and
        // does not show up as a perpetual Terraform diff. An explicit null is stored rather
        // than removed, so a read echoes `null` the way Graph does.
        other => {
            user.extra.insert(other.to_string(), value.clone());
        }
    }
    Ok(())
}

/// Look up by object ID, or by user principal name, which Graph also accepts in the path.
fn lookup<'a>(directory: &'a crate::store::Directory, id: &str) -> Option<&'a User> {
    directory
        .users
        .get(id)
        .or_else(|| directory.user_by_principal_name(id))
}

fn lookup_key(directory: &crate::store::Directory, id: &str) -> Option<String> {
    lookup(directory, id).map(|user| user.id.clone())
}

fn serialise(user: &User) -> Result<Value, GraphError> {
    serde_json::to_value(user)
        .map_err(|error| GraphError::internal(format!("serialising a user: {error}")))
}

fn required_string(fields: &Map<String, Value>, property: &str) -> Result<String, GraphError> {
    fields
        .get(property)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            GraphError::invalid_request(format!(
                "The property {property:?} is required and must be a string."
            ))
        })
}

fn optional_string(fields: &Map<String, Value>, property: &str) -> Option<String> {
    fields.get(property)?.as_str().map(str::to_string)
}

/// Graph accepts a password only inside `passwordProfile` and never reads it back.
fn password_from_profile(fields: &Map<String, Value>) -> Option<String> {
    fields
        .get("passwordProfile")?
        .get("password")?
        .as_str()
        .map(str::to_string)
}
