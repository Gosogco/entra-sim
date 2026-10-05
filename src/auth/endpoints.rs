//! The OAuth 2.0 token endpoint.

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::warn;

use crate::auth::oauth_error::{self, OAuthFailure};
use crate::auth::token::{AppTokenRequest, issue_app_token};
use crate::state::AppState;

/// A token request. Fields are shared across grant types, so all are optional here and the
/// handler for each grant enforces what it needs.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token_type: &'static str,
    pub expires_in: u64,
    /// Seconds until the token should be refreshed. Entra returns this alongside `expires_in`.
    pub ext_expires_in: u64,
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/{tenant}/oauth2/v2.0/token", post(token))
}

async fn token(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let tenant = state.config.resolve_tenant(&tenant);
    if tenant != state.config.tenant_id {
        return Err(oauth_error::unknown_client(&tenant));
    }

    match request.grant_type.as_deref() {
        Some("client_credentials") => client_credentials(&state, &tenant, &headers, &request).await,
        Some(other) => Err(oauth_error::unsupported_grant_type(other)),
        None => Err(oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'grant_type'.",
        )),
    }
}

async fn client_credentials(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let (client_id, client_secret) = client_credentials_from(headers, request)?;

    // The app-only flow is always `{resource}/.default`: it asks for every app role already
    // granted, because there is no user present to consent to anything narrower.
    let scope = request.scope.as_deref().unwrap_or_default();
    let resource = resource_from_scope(scope)
        .ok_or_else(|| oauth_error::invalid_scope(scope))?
        .to_string();

    let advertised = state.config.public_base_url();
    if resource != advertised {
        return Err(oauth_error::invalid_scope(scope));
    }

    let now = OffsetDateTime::now_utc();
    let directory = state.store.read().await;

    let Some(application) = directory.application_by_app_id(&client_id) else {
        return Err(oauth_error::unknown_client(&client_id));
    };
    if directory
        .matching_credential(&client_id, &client_secret, now)
        .is_none()
    {
        warn!(client_id = %client_id, "rejected a token request with an invalid secret");
        return Err(oauth_error::invalid_client_secret());
    }

    // The token represents the service principal, not the application registration.
    let Some(principal) = directory.service_principal_by_app_id(&client_id) else {
        return Err(oauth_error::no_grant(format!(
            "AADSTS65001: The application {client_id:?} has no service principal in the \
             directory. Create one before requesting a token."
        )));
    };

    let issuer = format!("{advertised}/{tenant}/v2.0");
    let (access_token, expires_in) = issue_app_token(
        &state.signing_key,
        AppTokenRequest {
            audience: &resource,
            issuer: &issuer,
            tenant_id: tenant,
            client_id: &client_id,
            principal_id: &principal.id,
            display_name: Some(&application.display_name),
            roles: principal.granted_app_roles.clone(),
            ttl_seconds: state.config.token_ttl_seconds,
        },
        now,
    )
    .map_err(|error| oauth_error::server_error(error.to_string()))?;

    Ok(Json(TokenResponse {
        token_type: "Bearer",
        expires_in,
        ext_expires_in: expires_in,
        access_token,
        scope: request.scope.clone(),
    }))
}

/// Read the client's credentials from either `client_secret_post` or `client_secret_basic`.
///
/// Body parameters win when both are present, matching Entra, which is lenient here.
fn client_credentials_from(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<(String, String), OAuthFailure> {
    if let (Some(id), Some(secret)) = (&request.client_id, &request.client_secret) {
        return Ok((id.clone(), secret.clone()));
    }

    if let Some(credentials) = basic_auth(headers) {
        return Ok(credentials);
    }

    // `client_assertion` is the remaining documented method, but verifying one needs the
    // client's certificate from its keyCredentials, which arrive with the applications API.
    if request.client_id.is_some() {
        return Err(oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: \
             'client_secret' or 'client_assertion'.",
        ));
    }
    Err(oauth_error::invalid_request(
        "AADSTS900144: The request body must contain the following parameter: 'client_id'.",
    ))
}

/// Decode an HTTP Basic credential pair, which OAuth requires be form-urlencoded before use.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((percent_decode(id), percent_decode(secret)))
}

/// RFC 6749 section 2.3.1 requires the two halves of a Basic credential be form-urlencoded.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

/// Pull the resource out of a `{resource}/.default` scope.
///
/// `go-azure-sdk` builds exactly this from the `microsoftGraphResourceId` in the metadata
/// document, so the resource it names is the simulator's own base URL.
fn resource_from_scope(scope: &str) -> Option<&str> {
    scope
        .split_whitespace()
        .find_map(|entry| entry.strip_suffix("/.default"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    #[test]
    fn resource_is_read_from_a_default_scope() {
        assert_eq!(
            resource_from_scope("https://sim.test/.default"),
            Some("https://sim.test")
        );
        // Entra tolerates additional scopes alongside the resource scope.
        assert_eq!(
            resource_from_scope("openid https://sim.test/.default"),
            Some("https://sim.test")
        );
        assert_eq!(resource_from_scope("User.Read"), None);
        assert_eq!(resource_from_scope(""), None);
    }

    #[test]
    fn basic_credentials_are_decoded_and_unescaped() {
        let mut headers = HeaderMap::new();
        // A secret containing a colon and a space, form-urlencoded as the RFC requires.
        let raw = format!("{}:{}", "my-client", "se%3Acret+with%20space");
        let encoded = STANDARD.encode(raw);
        headers.insert(
            AUTHORIZATION,
            format!("Basic {encoded}").parse().expect("header value"),
        );

        let (id, secret) = basic_auth(&headers).expect("decoding the credentials");
        assert_eq!(id, "my-client");
        assert_eq!(secret, "se:cret with space");
    }

    #[test]
    fn a_non_basic_authorization_header_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer something".parse().unwrap());
        assert!(basic_auth(&headers).is_none());
    }
}
