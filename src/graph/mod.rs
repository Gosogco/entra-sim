//! The Microsoft Graph API surface.
//!
//! The same routes are served under both `/v1.0` and `/beta`. That is not optional: the
//! Terraform `azuread` provider reaches for the beta endpoint for several core resources —
//! `azuread_group`, `azuread_application` and the group, user and service principal data
//! sources all use the beta clients from `go-azure-sdk`. A simulator that served only `/v1.0`
//! would fail on the provider's most common resources.
//!
//! The simulator's objects are a superset of both versions, so one set of handlers answers for
//! both; only the `@odata.context` differs, and it is built from the request's own prefix.

pub mod error;
pub mod users;

use axum::Json;
use axum::response::IntoResponse;
use axum::{Router, response::Response};

use crate::odata::{Collection, Query, encode_skiptoken, paginate, project};
use crate::state::AppState;

/// The path prefixes the Graph surface is served under.
pub const VERSIONS: [&str; 2] = ["/v1.0", "/beta"];

pub fn router() -> Router<AppState> {
    let mut router = Router::new();
    for version in VERSIONS {
        router = router.nest(version, resources());
    }
    router
}

fn resources() -> Router<AppState> {
    Router::new().merge(users::router())
}

/// Build a Graph collection response, applying ordering, paging and `$select`.
pub fn collection_response(
    state: &AppState,
    objects: Vec<serde_json::Value>,
    query: &Query,
    entity_set: &str,
) -> Response {
    let base = state.config.public_base_url();
    // `@odata.context` names v1.0 whichever prefix served the request, because the simulator
    // has a single object model rather than two. Clients read this for type discovery, not for
    // routing, so the distinction does not change their behaviour.
    let context = format!("{base}/v1.0/$metadata#{entity_set}");

    let entity_set = entity_set.to_string();
    let collection: Collection = paginate(objects, query, context, |last_id| {
        format!(
            "{base}/v1.0/{entity_set}?$top={}&$skiptoken={}",
            query.top,
            encode_skiptoken(last_id)
        )
    });
    Json(collection).into_response()
}

/// Build a single-object response, applying `$select`.
pub fn object_response(
    state: &AppState,
    mut object: serde_json::Value,
    query: &Query,
    entity_set: &str,
) -> Response {
    if let Some(select) = &query.select {
        object = project(&object, select);
    }
    if let Some(fields) = object.as_object_mut() {
        let base = state.config.public_base_url();
        fields.insert(
            "@odata.context".to_string(),
            serde_json::Value::String(format!("{base}/v1.0/$metadata#{entity_set}/$entity")),
        );
    }
    Json(object).into_response()
}
