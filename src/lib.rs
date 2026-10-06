//! A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API.
//!
//! Exposed as a library so that the integration tests can start a server in-process on an
//! ephemeral port.

pub mod auth;
pub mod config;
pub mod control;
pub mod cors;
pub mod graph;
pub mod metadata;
pub mod odata;
pub mod state;
pub mod store;
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
        .merge(auth::endpoints::router())
        .merge(auth::authorize::router())
        .merge(graph::router())
        // Outside the routes, so a preflight request is answered without matching one.
        .layer(cors::layer(&state.config))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
