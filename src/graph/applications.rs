//! The `/applications` collection and its credential actions.

use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::serde::rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;
use crate::store::model::{
    Application, FederatedIdentityCredential, KeyCredential, PasswordCredential,
};

/// Entra's default lifetime for a secret created without an explicit end date.
const DEFAULT_SECRET_MONTHS: i64 = 6;

/// Properties the simulator models explicitly and therefore must not also keep in `extra`,
/// where they would serialise a second time.
const MODELLED: [&str; 11] = [
    "id",
    "appId",
    "displayName",
    "identifierUris",
    "appRoles",
    "requiredResourceAccess",
    "signInAudience",
    "passwordCredentials",
    "keyCredentials",
    "createdDateTime",
    "api",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/applications", get(list).post(create))
        .route(
            "/applications/{id}",
            get(read).patch(update).put(update).delete(delete),
        )
        .route("/applications/{id}/addPassword", post(add_password))
        .route("/applications/{id}/removePassword", post(remove_password))
        .route("/applications/{id}/addKey", post(add_key))
        .route("/applications/{id}/removeKey", post(remove_key))
        .route("/applications/{id}/owners", get(owners))
        .route("/applications/{id}/owners/$ref", post(add_owner))
        .route(
            "/applications/{id}/owners/{owner_id}/$ref",
            axum::routing::delete(remove_owner),
        )
        .route(
            "/applications/{id}/federatedIdentityCredentials",
            get(list_federated).post(create_federated),
        )
        .route(
            "/applications/{id}/federatedIdentityCredentials/{credential_id}",
            get(read_federated).delete(delete_federated),
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
        .applications
        .values()
        .map(serialise)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(collection_response(&state, objects, &query, "applications"))
}

async fn read(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let application = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;
    Ok(object_response(
        &state,
        serialise(application)?,
        &query,
        "applications",
    ))
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

    // Entra assigns both identifiers; a client cannot choose them.
    let mut application = Application::new(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        display_name,
    );
    apply_all(&mut application, fields)?;

    let mut directory = state.store.write().await;
    let body = serialise(&application)?;
    directory
        .applications
        .insert(application.id.clone(), application);
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
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let application = directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup");
    apply_all(application, patch)?;

    // Keep the principal's copy of the permissions in step, so an assignment made after the
    // application gained a role still resolves.
    let roles = application.app_roles.clone();
    let scopes = application.oauth2_permission_scopes.clone();
    let app_id = application.app_id.clone();
    if let Some(principal) = directory
        .service_principals
        .values_mut()
        .find(|principal| principal.app_id == app_id)
    {
        principal.app_roles = roles;
        principal.oauth2_permission_scopes = scopes;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    directory.applications.remove(&key);
    Ok(StatusCode::NO_CONTENT)
}

/// Apply every property in a create or update body.
fn apply_all(application: &mut Application, fields: &Map<String, Value>) -> Result<(), GraphError> {
    for (property, value) in fields {
        match property.as_str() {
            // Entra owns both identifiers.
            "id" | "appId" => {
                return Err(GraphError::invalid_request(format!(
                    "The property '{property}' is read-only and cannot be modified."
                )));
            }
            "displayName" => {
                application.display_name = value
                    .as_str()
                    .ok_or_else(|| GraphError::invalid_property("displayName"))?
                    .to_string();
            }
            "identifierUris" => {
                application.identifier_uris = string_array(value, "identifierUris")?;
            }
            "signInAudience" => application.sign_in_audience = value.as_str().map(str::to_string),
            "appRoles" => {
                application.app_roles = serde_json::from_value(value.clone())
                    .map_err(|_| GraphError::invalid_property("appRoles"))?;
            }
            "requiredResourceAccess" => {
                application.required_resource_access = serde_json::from_value(value.clone())
                    .map_err(|_| GraphError::invalid_property("requiredResourceAccess"))?;
            }
            "api" => {
                // Delegated permissions live under `api`, which also carries properties the
                // simulator has no opinion about, so the block is kept whole as well.
                if let Some(scopes) = value.get("oauth2PermissionScopes") {
                    application.oauth2_permission_scopes = serde_json::from_value(scopes.clone())
                        .map_err(|_| {
                        GraphError::invalid_property("api/oauth2PermissionScopes")
                    })?;
                }
                application.extra.insert("api".to_string(), value.clone());
            }
            // Credentials are managed through addPassword and addKey, which is also how Entra
            // behaves: a secret written directly here would have no secretText to return.
            "passwordCredentials" | "keyCredentials" => {}
            other => {
                if value.is_null() {
                    application.extra.remove(other);
                } else {
                    application.extra.insert(other.to_string(), value.clone());
                }
            }
        }
    }

    // `api` is stored whole, so drop the duplicate the loop may have left behind.
    for property in MODELLED {
        if property != "api" {
            application.extra.remove(property);
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddPasswordBody {
    #[serde(default)]
    password_credential: Option<PasswordCredentialRequest>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordCredentialRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default, with = "rfc3339::option")]
    start_date_time: Option<OffsetDateTime>,
    #[serde(default, with = "rfc3339::option")]
    end_date_time: Option<OffsetDateTime>,
}

/// The `addPassword` response, which is the only time Graph discloses `secretText`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AddPasswordResponse {
    key_id: String,
    display_name: Option<String>,
    hint: String,
    #[serde(with = "rfc3339")]
    start_date_time: OffsetDateTime,
    #[serde(with = "rfc3339")]
    end_date_time: OffsetDateTime,
    secret_text: String,
}

async fn add_password(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    body: Option<Json<AddPasswordBody>>,
) -> Result<impl IntoResponse, GraphError> {
    let requested = body
        .and_then(|Json(body)| body.password_credential)
        .unwrap_or_default();

    let now = OffsetDateTime::now_utc();
    let start = requested.start_date_time.unwrap_or(now);
    let end = requested
        .end_date_time
        .unwrap_or_else(|| start + Duration::days(30 * DEFAULT_SECRET_MONTHS));
    if end <= start {
        return Err(GraphError::invalid_request(
            "The credential's endDateTime must be later than its startDateTime.",
        ));
    }

    // Entra generates the secret; a client cannot supply one.
    let secret = generate_secret();

    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let credential = PasswordCredential {
        key_id: Uuid::new_v4().to_string(),
        display_name: requested.display_name.clone(),
        hint: Some(secret.chars().take(3).collect()),
        start_date_time: start,
        end_date_time: end,
        secret_text: secret.clone(),
    };
    let response = AddPasswordResponse {
        key_id: credential.key_id.clone(),
        display_name: credential.display_name.clone(),
        hint: credential.hint.clone().unwrap_or_default(),
        start_date_time: start,
        end_date_time: end,
        secret_text: secret,
    };

    directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .password_credentials
        .push(credential);

    Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveCredentialBody {
    key_id: String,
}

async fn remove_password(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<RemoveCredentialBody>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let credentials = &mut directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .password_credentials;
    let before = credentials.len();
    credentials.retain(|credential| credential.key_id != body.key_id);
    if credentials.len() == before {
        return Err(GraphError::resource_not_found(&body.key_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddKeyBody {
    key_credential: KeyCredentialRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyCredentialRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    usage: String,
    key: String,
    #[serde(default, with = "rfc3339::option")]
    start_date_time: Option<OffsetDateTime>,
    #[serde(default, with = "rfc3339::option")]
    end_date_time: Option<OffsetDateTime>,
}

async fn add_key(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<AddKeyBody>,
) -> Result<impl IntoResponse, GraphError> {
    let requested = body.key_credential;
    let now = OffsetDateTime::now_utc();
    let start = requested.start_date_time.unwrap_or(now);
    let end = requested
        .end_date_time
        .unwrap_or_else(|| start + Duration::days(365));

    let credential = KeyCredential {
        key_id: Uuid::new_v4().to_string(),
        display_name: requested.display_name,
        kind: requested.kind,
        usage: requested.usage,
        key: Some(requested.key),
        start_date_time: start,
        end_date_time: end,
    };

    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .key_credentials
        .push(credential.clone());

    Ok((StatusCode::OK, Json(credential)))
}

async fn remove_key(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<RemoveCredentialBody>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let credentials = &mut directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .key_credentials;
    let before = credentials.len();
    credentials.retain(|credential| credential.key_id != body.key_id);
    if credentials.len() == before {
        return Err(GraphError::resource_not_found(&body.key_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn owners(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let application = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    let mut objects: Vec<Value> = application
        .owners
        .iter()
        .filter_map(|owner| directory.object(owner).map(|(_, value)| value))
        .collect();
    objects.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("applications('{id}')/owners"),
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
    let referenced = crate::graph::object_id_from_odata_id(&body.odata_id)?;

    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;
    if !directory.contains_object(&referenced) {
        return Err(GraphError::resource_not_found(&referenced));
    }

    let owners = &mut directory
        .applications
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
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let owners = &mut directory
        .applications
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

async fn list_federated(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    let directory = state.store.read().await;
    let application = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    let objects = application
        .federated_identity_credentials
        .iter()
        .map(|credential| serde_json::to_value(credential).unwrap_or(Value::Null))
        .collect();

    Ok(collection_response(
        &state,
        objects,
        &query,
        &format!("applications('{id}')/federatedIdentityCredentials"),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FederatedCredentialRequest {
    name: String,
    issuer: String,
    subject: String,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    description: Option<String>,
}

async fn create_federated(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    Json(body): Json<FederatedCredentialRequest>,
) -> Result<impl IntoResponse, GraphError> {
    let credential = FederatedIdentityCredential {
        id: Uuid::new_v4().to_string(),
        name: body.name,
        issuer: body.issuer,
        subject: body.subject,
        audiences: if body.audiences.is_empty() {
            // Entra's default audience for a federated credential.
            vec!["api://AzureADTokenExchange".to_string()]
        } else {
            body.audiences
        },
        description: body.description,
    };

    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let credentials = &mut directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .federated_identity_credentials;
    if credentials
        .iter()
        .any(|existing| existing.name == credential.name)
    {
        return Err(GraphError::object_conflict(format!(
            "A federated identity credential named {:?} already exists on this application.",
            credential.name
        )));
    }
    credentials.push(credential.clone());

    Ok((StatusCode::CREATED, Json(credential)))
}

async fn read_federated(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, credential_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, GraphError> {
    let directory = state.store.read().await;
    let application = lookup(&directory, &id).ok_or_else(|| GraphError::resource_not_found(&id))?;

    // Graph accepts either the credential's ID or its name here.
    let credential = application
        .federated_identity_credentials
        .iter()
        .find(|credential| credential.id == credential_id || credential.name == credential_id)
        .ok_or_else(|| GraphError::resource_not_found(&credential_id))?;

    Ok(Json(
        serde_json::to_value(credential).unwrap_or(Value::Null),
    ))
}

async fn delete_federated(
    State(state): State<AppState>,
    _caller: Caller,
    Path((id, credential_id)): Path<(String, String)>,
) -> Result<StatusCode, GraphError> {
    let mut directory = state.store.write().await;
    let key = lookup(&directory, &id)
        .map(|application| application.id.clone())
        .ok_or_else(|| GraphError::resource_not_found(&id))?;

    let credentials = &mut directory
        .applications
        .get_mut(&key)
        .expect("key came from lookup")
        .federated_identity_credentials;
    let before = credentials.len();
    credentials
        .retain(|credential| credential.id != credential_id && credential.name != credential_id);
    if credentials.len() == before {
        return Err(GraphError::resource_not_found(&credential_id));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Look up by object ID, or by `appId`, which clients also use to address an application.
fn lookup<'a>(directory: &'a crate::store::Directory, id: &str) -> Option<&'a Application> {
    directory
        .applications
        .get(id)
        .or_else(|| directory.application_by_app_id(id))
}

fn serialise(application: &Application) -> Result<Value, GraphError> {
    serde_json::to_value(application)
        .map_err(|error| GraphError::internal(format!("serialising an application: {error}")))
}

fn string_array(value: &Value, property: &str) -> Result<Vec<String>, GraphError> {
    value
        .as_array()
        .ok_or_else(|| GraphError::invalid_property(property))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| GraphError::invalid_property(property))
        })
        .collect()
}

/// Generate a secret shaped like one Entra issues: opaque, URL-safe and long enough that it is
/// obviously not a password.
fn generate_secret() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;

    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
