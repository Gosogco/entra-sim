//! The OAuth 2.0 error response the token endpoint returns.
//!
//! Entra's shape, including the `AADSTS` codes clients and humans grep for. Getting these right
//! matters because client libraries branch on `error`, and operators search for the numeric code.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::OffsetDateTime;
use time::macros::format_description;

#[derive(Debug, Serialize)]
pub struct OAuthError {
    pub error: &'static str,
    pub error_description: String,
    pub error_codes: Vec<u32>,
    pub timestamp: String,
    pub trace_id: String,
    pub correlation_id: String,
}

/// Which HTTP status to pair with the body. Entra answers client-authentication failures with
/// 401 and malformed requests with 400.
pub struct OAuthFailure {
    status: StatusCode,
    /// Boxed to keep the `Err` variant of every token handler small; the body is wide and is
    /// only ever built on the failure path.
    body: Box<OAuthError>,
}

impl OAuthError {
    /// Returns a box, because this only ever lands in the `Err` variant of a handler's
    /// result and the body is wide enough that clippy objects to it inline.
    fn new(error: &'static str, code: u32, description: String) -> Box<Self> {
        // Entra's timestamp format, which is not RFC 3339.
        let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]Z");
        Box::new(Self {
            error,
            error_description: description,
            error_codes: vec![code],
            timestamp: OffsetDateTime::now_utc()
                .format(&format)
                .unwrap_or_default(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
        })
    }
}

/// The request was not a well-formed token request.
pub fn invalid_request(description: impl Into<String>) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::BAD_REQUEST,
        body: OAuthError::new("invalid_request", 900144, description.into()),
    }
}

/// The grant type is not one the simulator implements.
pub fn unsupported_grant_type(grant_type: &str) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::BAD_REQUEST,
        body: OAuthError::new(
            "unsupported_grant_type",
            70003,
            format!(
                "AADSTS70003: The client is not authorized to request a token using this method. \
                 Grant type {grant_type:?} is not supported."
            ),
        ),
    }
}

/// No application is registered with the given client ID.
pub fn unknown_client(client_id: &str) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::UNAUTHORIZED,
        body: OAuthError::new(
            "unauthorized_client",
            700016,
            format!(
                "AADSTS700016: Application with identifier {client_id:?} was not found in the \
                 directory."
            ),
        ),
    }
}

/// The client exists but the secret did not match, or has expired.
pub fn invalid_client_secret() -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::UNAUTHORIZED,
        body: OAuthError::new(
            "invalid_client",
            7000215,
            "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the \
             request is the client secret value, not the client secret ID, for a secret added to \
             the app."
                .to_string(),
        ),
    }
}

/// The requested scope does not name a resource the simulator serves.
pub fn invalid_scope(scope: &str) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::BAD_REQUEST,
        body: OAuthError::new(
            "invalid_scope",
            70011,
            format!(
                "AADSTS70011: The provided request must include a 'scope' input parameter. The \
                 provided value for the input parameter 'scope' {scope:?} is not valid."
            ),
        ),
    }
}

/// The presented grant — a code, a refresh token — is not usable.
pub fn invalid_grant(description: impl Into<String>) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::BAD_REQUEST,
        body: OAuthError::new("invalid_grant", 54005, description.into()),
    }
}

/// The client authenticated but is not entitled to a token for the resource.
pub fn no_grant(description: impl Into<String>) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::BAD_REQUEST,
        body: OAuthError::new("invalid_grant", 65001, description.into()),
    }
}

/// Something failed that is the simulator's own fault.
pub fn server_error(description: impl Into<String>) -> OAuthFailure {
    OAuthFailure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: OAuthError::new("server_error", 90000, description.into()),
    }
}

impl IntoResponse for OAuthFailure {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}
