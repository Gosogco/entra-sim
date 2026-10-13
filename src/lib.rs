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

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the complete application router.
///
/// Each tenant gets its own copy of the routes, with that tenant's state, and every request is
/// passed to the copy for the tenant it addresses: see `tenant_for`.
pub fn router(state: AppState) -> Router {
    let mut routes: Router<AppState> = Router::new()
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
        routes = routes.fallback_service(studio);
    }

    let by_tenant: Arc<Vec<(String, Router)>> = Arc::new(
        state
            .all_tenants()
            .into_iter()
            .map(|tenant| {
                (
                    tenant.config.tenant_id.clone(),
                    routes.clone().with_state(tenant),
                )
            })
            .collect(),
    );
    let lookup = state.clone();
    let dispatch = tower::service_fn(move |request: Request<Body>| {
        let by_tenant = by_tenant.clone();
        let tenant = tenant_for(&lookup, &request);
        async move {
            let router = by_tenant
                .iter()
                .find(|(id, _)| *id == tenant)
                .map(|(_, router)| router.clone())
                .unwrap_or_else(|| by_tenant[0].1.clone());
            router.oneshot(request).await
        }
    });

    Router::new()
        .fallback_service(dispatch)
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

/// The tenant a request addresses.
///
/// The identity endpoints name it in the first path segment, by ID or domain. Graph and UserInfo
/// take it from the bearer token's `tid`, as a token is only ever valid in the tenant that issued
/// it. Everything else, including the aliases `common` and `organizations`, goes to the primary
/// tenant, which resolves them itself.
fn tenant_for(state: &AppState, request: &Request<Body>) -> String {
    let primary = state.config.tenant_id.clone();
    let first = request
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    if matches!(first, "v1.0" | "beta" | "oidc") {
        return request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' ').map(|(_, token)| token.trim()))
            .and_then(auth::client_auth::peek_claims)
            .and_then(|claims| claims["tid"].as_str().map(str::to_string))
            .and_then(|tid| state.for_tenant(&tid))
            .map(|tenant| tenant.config.tenant_id.clone())
            .unwrap_or(primary);
    }
    state
        .tenant_named(first)
        .map(|tenant| tenant.config.tenant_id.clone())
        .unwrap_or(primary)
}
