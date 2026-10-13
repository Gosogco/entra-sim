//! A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API.
//!
//! Exposed as a library so that the integration tests can start a server in-process on an
//! ephemeral port.

pub mod auth;
pub mod config;
pub mod control;
pub mod cors;
pub mod graph;
pub mod log;
pub mod metadata;
pub mod odata;
pub mod state;
pub mod store;
pub mod tls;

use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the complete application router.
pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .merge(control::router())
        .merge(metadata::router())
        .merge(auth::oidc::router())
        .merge(auth::endpoints::router())
        .merge(auth::authorize::router())
        .merge(auth::device::router())
        .merge(graph::router());

    // A fallback, so it only answers paths no route claims. The studio keeps its tab in the URL
    // fragment, so there are no client-side paths that would need `index.html` in their place.
    if let Some(dir) = &state.config.studio_dir {
        let studio = Router::new().fallback_service(ServeDir::new(dir)).layer(
            axum::middleware::map_response(log::requests::mark_studio_file),
        );
        router = router.fallback_service(studio);
    }

    router
        // Outside the routes, so a preflight request is answered without matching one.
        .layer(cors::layer(&state.config))
        .layer(TraceLayer::new_for_http())
        // Outermost, so the log sees every request and the response exactly as it was sent.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            log::requests::record,
        ))
        .with_state(state)
}
