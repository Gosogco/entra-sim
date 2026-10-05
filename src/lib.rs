//! A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API.
//!
//! Exposed as a library so that the integration tests can start a server in-process on an
//! ephemeral port.

pub mod auth;
pub mod config;
pub mod control;
pub mod metadata;
pub mod state;
pub mod tls;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the complete application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(control::router())
        .merge(metadata::router())
        .merge(auth::oidc::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
