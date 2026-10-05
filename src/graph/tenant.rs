//! `/organization` and `/domains`.
//!
//! The provider's own documented example reads `/domains` before creating a user, to build a
//! principal name from the tenant's initial domain, so this is on the critical path for the
//! simplest possible configuration.

use axum::Router;
use axum::extract::{Path, Query as AxumQuery, State};
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::{Value, json};

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::graph::{collection_response, object_response};
use crate::odata::RawQuery;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/organization", get(list_organization))
        .route("/organization/{id}", get(read_organization))
        .route("/domains", get(list_domains))
        .route("/domains/{id}", get(read_domain))
}

async fn list_organization(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    Ok(collection_response(
        &state,
        vec![organization(&state)],
        &query,
        "organization",
    ))
}

async fn read_organization(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    // Graph also accepts the literal `organization` and the tenant ID here.
    if id != state.config.tenant_id && id != "organization" {
        return Err(GraphError::resource_not_found(&id));
    }
    Ok(object_response(
        &state,
        organization(&state),
        &query,
        "organization",
    ))
}

fn organization(state: &AppState) -> Value {
    let domain = state.config.tenant_domain.clone();
    json!({
        // The organization's object ID is the tenant ID.
        "id": state.config.tenant_id,
        "displayName": "entra-sim",
        "tenantType": "AAD",
        "verifiedDomains": [{
            "name": domain,
            "isDefault": true,
            "isInitial": true,
            "type": "Managed",
            "capabilities": "Email, OfficeCommunicationsOnline",
        }],
    })
}

async fn list_domains(
    State(state): State<AppState>,
    _caller: Caller,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    Ok(collection_response(
        &state,
        vec![domain(&state)],
        &query,
        "domains",
    ))
}

async fn read_domain(
    State(state): State<AppState>,
    _caller: Caller,
    Path(id): Path<String>,
    AxumQuery(raw): AxumQuery<RawQuery>,
) -> Result<impl IntoResponse, GraphError> {
    let query = raw.validate()?;
    if id != state.config.tenant_domain {
        return Err(GraphError::resource_not_found(&id));
    }
    Ok(object_response(&state, domain(&state), &query, "domains"))
}

fn domain(state: &AppState) -> Value {
    json!({
        // A domain's object ID is the domain name itself.
        "id": state.config.tenant_domain,
        "isDefault": true,
        "isInitial": true,
        "isVerified": true,
        "authenticationType": "Managed",
        "supportedServices": [],
        "passwordValidityPeriodInDays": 2_147_483_647u32,
        "passwordNotificationWindowInDays": 14,
    })
}
