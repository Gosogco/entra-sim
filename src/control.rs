//! Endpoints for driving the simulator itself.
//!
//! Under a `/__sim__` prefix, which cannot collide with a real Graph or identity path, so the
//! simulator stays a drop-in replacement: a client pointed at it never sees these.
//!
//! They are unauthenticated. Whoever can reach the simulator can already mint a token for any
//! identity in it, so a token here would be a formality; and a test harness needs to reset
//! state before it has obtained one.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use time::OffsetDateTime;
use time::serde::rfc3339;
use tracing::info;

use crate::auth::sessions::IssuedToken;
use crate::state::AppState;
use crate::store::bootstrap;
use crate::store::snapshot::Snapshot;

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    tenant_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    users: usize,
    groups: usize,
    applications: usize,
    service_principals: usize,
    app_role_assignments: usize,
    oauth2_permission_grants: usize,
    directory_roles: usize,
}

/// Everything issued that the simulator remembers.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Tokens {
    /// The simulator's clock, so a reader judges expiry against it rather than its own.
    #[serde(with = "rfc3339")]
    server_time: OffsetDateTime,
    issued: Vec<IssuedToken>,
    refresh_tokens: Vec<PendingRefreshToken>,
    pending_codes: Vec<PendingCode>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingRefreshToken {
    prefix: String,
    client_id: String,
    user_id: String,
    scope: String,
    #[serde(with = "rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingCode {
    prefix: String,
    client_id: String,
    user_id: String,
    redirect_uri: String,
    scope: String,
    #[serde(with = "rfc3339")]
    expires_at: OffsetDateTime,
}

/// How much of a refresh token or code value is shown: enough to tell two apart, too little to
/// redeem.
const PREFIX_LENGTH: usize = 6;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/__sim__/health", get(health))
        .route("/__sim__/reset", post(reset))
        .route("/__sim__/snapshot", get(dump).post(load))
        .route("/__sim__/tokens", get(tokens))
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        tenant_id: state.config.tenant_id.clone(),
    })
}

/// Return the directory to the state it started in.
///
/// Reinstalls the bootstrap objects and reapplies the seed, so a test suite can reset between
/// cases without restarting the process, and two runs start from identical state.
async fn reset(State(state): State<AppState>) -> Result<impl IntoResponse, Failure> {
    let seeded = state.rebuild_initial_directory().await?;

    let mut directory = state.store.write().await;
    *directory = seeded;
    let counts = counts(&directory);
    drop(directory);

    // Codes and refresh tokens refer to objects that no longer exist, so they go too, along with
    // the log of issued tokens.
    let mut sessions = state.sessions.lock().await;
    *sessions = Default::default();

    info!("reset the directory to its initial state");
    Ok(Json(counts))
}

/// Dump the whole directory, including the secrets an API read would never disclose.
async fn dump(State(state): State<AppState>) -> Json<Snapshot> {
    let directory = state.store.read().await;
    Json(Snapshot::capture(&directory))
}

/// List the tokens issued, the refresh tokens still redeemable and the codes still waiting.
///
/// Refresh tokens and codes are live bearer values, so only a prefix of each is returned. The
/// issued log holds no token values at all.
async fn tokens(State(state): State<AppState>) -> Json<Tokens> {
    let now = OffsetDateTime::now_utc();
    let sessions = state.sessions.lock().await;
    let prefix = |value: &str| value.chars().take(PREFIX_LENGTH).collect::<String>();

    let mut refresh_tokens: Vec<PendingRefreshToken> = sessions
        .refresh_tokens()
        .filter(|(_, token)| token.expires_at > now)
        .map(|(value, token)| PendingRefreshToken {
            prefix: prefix(value),
            client_id: token.client_id.clone(),
            user_id: token.user_id.clone(),
            scope: token.scope.clone(),
            expires_at: token.expires_at,
        })
        .collect();
    refresh_tokens.sort_by_key(|token| token.expires_at);

    let mut pending_codes: Vec<PendingCode> = sessions
        .codes()
        .filter(|(_, code)| code.expires_at > now)
        .map(|(value, code)| PendingCode {
            prefix: prefix(value),
            client_id: code.client_id.clone(),
            user_id: code.user_id.clone(),
            redirect_uri: code.redirect_uri.clone(),
            scope: code.scope.clone(),
            expires_at: code.expires_at,
        })
        .collect();
    pending_codes.sort_by_key(|code| code.expires_at);

    Json(Tokens {
        server_time: now,
        issued: sessions.issued().cloned().collect(),
        refresh_tokens,
        pending_codes,
    })
}

/// Replace the whole directory with the posted snapshot.
async fn load(
    State(state): State<AppState>,
    Json(snapshot): Json<Snapshot>,
) -> Result<impl IntoResponse, Failure> {
    let mut restored = snapshot.restore();

    // The bootstrap objects are reinstalled over the snapshot, so a snapshot taken from a
    // differently configured run cannot leave the simulator with no usable client.
    bootstrap::install(&mut restored, &state.config);

    let mut directory = state.store.write().await;
    *directory = restored;
    let counts = counts(&directory);

    info!("loaded a directory snapshot");
    Ok(Json(counts))
}

fn counts(directory: &crate::store::Directory) -> Counts {
    Counts {
        users: directory.users.len(),
        groups: directory.groups.len(),
        applications: directory.applications.len(),
        service_principals: directory.service_principals.len(),
        app_role_assignments: directory.app_role_assignments.len(),
        oauth2_permission_grants: directory.oauth2_permission_grants.len(),
        directory_roles: directory.directory_roles.len(),
    }
}

/// A control endpoint failure, reported plainly rather than in a Graph error envelope: these are
/// not Graph endpoints and nothing parses them as such.
pub struct Failure(pub String);

impl From<anyhow::Error> for Failure {
    fn from(error: anyhow::Error) -> Self {
        Self(format!("{error:#}"))
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0 })),
        )
            .into_response()
    }
}
