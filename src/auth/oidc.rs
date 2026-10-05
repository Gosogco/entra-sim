//! OpenID Connect discovery and the JWKS endpoint.
//!
//! Shaped after the live document at
//! `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`, limited to
//! the fields that describe behaviour the simulator actually has. Advertising an endpoint the
//! simulator does not serve would be worse than omitting it, because clients pick flows from
//! this document.

use axum::Json;
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Router, http::header};
use serde::Serialize;

use crate::auth::keys::Jwks;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub request_uri_parameter_supported: bool,
    pub tenant_region_scope: Option<String>,
    pub cloud_instance_name: String,
    pub msgraph_host: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/{tenant}/v2.0/.well-known/openid-configuration",
            get(configuration),
        )
        .route("/{tenant}/discovery/v2.0/keys", get(keys))
}

/// Build the discovery document for `tenant` as advertised at `base_url`.
pub fn document(base_url: &str, tenant: &str) -> OpenIdConfiguration {
    // Both of these name a host rather than a URL. In real Entra they differ; here the
    // simulator is its own identity provider and its own Graph.
    let host = base_url.trim_start_matches("https://").to_string();
    OpenIdConfiguration {
        // Entra's issuer always names the concrete tenant, never `common`, so that tokens from
        // different tenants are distinguishable.
        issuer: format!("{base_url}/{tenant}/v2.0"),
        authorization_endpoint: format!("{base_url}/{tenant}/oauth2/v2.0/authorize"),
        token_endpoint: format!("{base_url}/{tenant}/oauth2/v2.0/token"),
        jwks_uri: format!("{base_url}/{tenant}/discovery/v2.0/keys"),
        end_session_endpoint: format!("{base_url}/{tenant}/oauth2/v2.0/logout"),
        response_types_supported: vec!["code"],
        response_modes_supported: vec!["query", "fragment", "form_post"],
        grant_types_supported: vec!["authorization_code", "refresh_token", "client_credentials"],
        subject_types_supported: vec!["pairwise"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post",
            "client_secret_basic",
            "private_key_jwt",
        ],
        code_challenge_methods_supported: vec!["S256", "plain"],
        scopes_supported: vec!["openid", "profile", "email", "offline_access"],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "name",
            "preferred_username",
            "oid",
            "tid",
            "ver",
            "nonce",
        ],
        request_uri_parameter_supported: false,
        tenant_region_scope: None,
        cloud_instance_name: host.clone(),
        msgraph_host: host,
    }
}

/// Discovery responses are cacheable but short-lived, so a client picks up a new signing key
/// reasonably quickly after a restart.
const CACHE_CONTROL: (header::HeaderName, &str) =
    (header::CACHE_CONTROL, "public, max-age=60, must-revalidate");

async fn configuration(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
) -> (
    [(header::HeaderName, &'static str); 1],
    Json<OpenIdConfiguration>,
) {
    let tenant = state.config.resolve_tenant(&tenant);
    (
        [CACHE_CONTROL],
        Json(document(&state.config.public_base_url(), &tenant)),
    )
}

async fn keys(
    State(state): State<AppState>,
) -> ([(header::HeaderName, &'static str); 1], Json<Jwks>) {
    ([CACHE_CONTROL], Json(state.signing_key.jwks()))
}
