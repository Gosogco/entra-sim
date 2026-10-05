//! The Azure cloud metadata document, at `GET /metadata/endpoints`.
//!
//! This is the single hook that lets the Terraform `azuread` provider talk to the simulator with
//! no code changes: setting `metadata_host` (or `ARM_METADATA_HOSTNAME`) makes the provider call
//! `environments.FromEndpoint`, which fetches this document and reconfigures every endpoint from
//! it.
//!
//! Field requirements come from `go-azure-sdk`:
//!
//! - `name`, `resourceManager` and `microsoftGraphResourceId` are mandatory; the provider fails
//!   to configure if any is empty (`sdk/environments/from_endpoint.go`). `resourceManager` is a
//!   placeholder here, because `azuread` never calls Azure Resource Manager but still refuses to
//!   start without the field.
//! - `microsoftGraphResourceId` serves as both the Graph base URL and the token resource, so the
//!   scope the provider requests is `{microsoftGraphResourceId}/.default`
//!   (`sdk/environments/helpers.go`, `sdk/environments/scopes.go`).
//! - Endpoints are right-trimmed of `/`, but `authentication.loginEndpoint` is not, and the token
//!   URL is built by concatenation, so it must not end in a slash.

use axum::Json;
use axum::extract::State;
use axum::routing::get;
use axum::{Router, http::header};
use serde::Serialize;

use crate::state::AppState;

/// The 2022-09-01 metadata schema, limited to the fields a client can act on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudMetadata {
    pub portal: String,
    pub authentication: Authentication,
    pub name: String,
    pub resource_manager: String,
    pub microsoft_graph_resource_id: String,
    pub suffixes: Suffixes,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub login_endpoint: String,
    pub audiences: Vec<String>,
    pub tenant: String,
    pub identity_provider: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Suffixes {
    pub storage: String,
    pub key_vault_dns: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/metadata/endpoints", get(endpoints))
}

/// Build the document advertised for `base_url`, which must not end in a slash.
pub fn document(base_url: &str) -> CloudMetadata {
    CloudMetadata {
        portal: format!("{base_url}/portal"),
        authentication: Authentication {
            login_endpoint: base_url.to_string(),
            audiences: vec![base_url.to_string()],
            // `common` keeps the provider's default tenant handling working; the simulator
            // treats it as an alias for the single tenant it serves.
            tenant: "common".to_string(),
            identity_provider: "AAD".to_string(),
        },
        name: "EntraSim".to_string(),
        resource_manager: format!("{base_url}/arm"),
        microsoft_graph_resource_id: base_url.to_string(),
        suffixes: Suffixes {
            storage: "core.windows.net".to_string(),
            key_vault_dns: "vault.azure.net".to_string(),
        },
    }
}

async fn endpoints(
    State(state): State<AppState>,
) -> ([(header::HeaderName, &'static str); 1], Json<CloudMetadata>) {
    (
        // The SDK trims a UTF-8 BOM but does not check the content type; be explicit anyway.
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        Json(document(&state.config.public_base_url())),
    )
}
