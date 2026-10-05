//! The Microsoft Graph error envelope.
//!
//! Clients branch on `error.code`, so the codes have to be the real ones. The `innerError`
//! block carries the request identifiers that Graph echoes back and that support requests quote.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Serialize)]
pub struct GraphErrorBody {
    pub error: GraphErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct GraphErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(rename = "innerError")]
    pub inner_error: InnerError,
}

#[derive(Debug, Serialize)]
pub struct InnerError {
    pub date: String,
    #[serde(rename = "request-id")]
    pub request_id: String,
    #[serde(rename = "client-request-id")]
    pub client_request_id: String,
}

/// An error to return from a Graph handler.
#[derive(Debug)]
pub struct GraphError {
    status: StatusCode,
    code: String,
    message: String,
}

impl GraphError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// The caller's token lacks a required permission.
    pub fn authorization_request_denied() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "Authorization_RequestDenied",
            "Insufficient privileges to complete the operation.",
        )
    }

    /// No directory object with the requested identifier exists.
    pub fn resource_not_found(id: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "Request_ResourceNotFound",
            format!(
                "Resource {id:?} does not exist or one of its queried reference-property objects are not present."
            ),
        )
    }
}

impl IntoResponse for GraphError {
    fn into_response(self) -> Response {
        let request_id = uuid::Uuid::new_v4().to_string();
        let body = GraphErrorBody {
            error: GraphErrorDetail {
                code: self.code,
                message: self.message,
                inner_error: InnerError {
                    date: OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .unwrap_or_default(),
                    client_request_id: request_id.clone(),
                    request_id,
                },
            },
        };
        (self.status, Json(body)).into_response()
    }
}
