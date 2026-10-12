//! Records each request the simulator answers, with its headers and both bodies.
//!
//! The studio's own reads are left out. It polls `/__sim__/*` every few seconds and would bury
//! everything else, and recording a read of the log would grow the log with copies of itself.

use std::time::Instant;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use tracing::{Instrument, info_span, warn};

use crate::state::AppState;

/// Marks a response as one of the studio's files, which the log leaves out.
#[derive(Clone, Copy)]
pub struct StudioFile;

pub async fn mark_studio_file(mut response: Response) -> Response {
    response.extensions_mut().insert(StudioFile);
    response
}

pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(log) = state.log.clone() else {
        return next.run(request).await;
    };
    if matches!(*request.method(), Method::GET | Method::HEAD)
        && request.uri().path().starts_with("/__sim__/")
    {
        return next.run(request).await;
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    let time = super::now();
    let started = Instant::now();

    let (parts, body) = request.into_parts();
    let Ok(request_body) = to_bytes(body, usize::MAX).await else {
        return (StatusCode::BAD_REQUEST, "could not read the request body").into_response();
    };
    let method = parts.method.to_string();
    let uri = parts.uri.to_string();
    let request_headers = headers(&parts.headers);

    // Events raised while the request is handled carry this span's ID, which is how the studio
    // shows them under the request.
    let response = next
        .run(Request::from_parts(parts, Body::from(request_body.clone())))
        .instrument(info_span!("request", request_id = %request_id))
        .await;

    let served = response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED;
    if served && response.extensions().get::<StudioFile>().is_some() {
        return response;
    }

    let (parts, body) = response.into_parts();
    let Ok(response_body) = to_bytes(body, usize::MAX).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not read the response body",
        )
            .into_response();
    };

    let entry = json!({
        "time": time,
        "kind": "request",
        "requestId": request_id,
        "method": method,
        "uri": uri,
        "status": parts.status.as_u16(),
        "durationMs": started.elapsed().as_secs_f64() * 1000.0,
        "requestHeaders": request_headers,
        "requestBody": text(&request_body),
        "responseHeaders": headers(&parts.headers),
        "responseBody": text(&response_body),
    });
    if let Err(error) = log.append(&entry) {
        warn!(%error, "could not write a request to the log");
    }

    Response::from_parts(parts, Body::from(response_body))
}

/// Header values by name. A header sent more than once has its values joined, as HTTP allows.
fn headers(headers: &HeaderMap) -> Value {
    let mut map = Map::new();
    for name in headers.keys() {
        let values: Vec<_> = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        map.insert(name.to_string(), values.join(", ").into());
    }
    Value::Object(map)
}

/// A body as text, or null when there is none.
fn text(body: &Bytes) -> Value {
    if body.is_empty() {
        Value::Null
    } else {
        String::from_utf8_lossy(body).into_owned().into()
    }
}
