//! Endpoints for driving the simulator itself, under a `/__sim__` prefix that cannot collide
//! with a real Graph or identity path.

use axum::Json;
use axum::routing::get;
use axum::{Router, extract::State};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    tenant_id: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/__sim__/health", get(health))
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        tenant_id: state.config.tenant_id.clone(),
    })
}
