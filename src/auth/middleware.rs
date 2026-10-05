//! Bearer token validation for the Graph surface.
//!
//! Handlers receive the validated claims as an extractor, so a route cannot accidentally serve
//! an unauthenticated request: asking for `Caller` is what performs the check.

use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

use crate::auth::permissions;
use crate::auth::token::{self, AccessTokenClaims};
use crate::graph::error::GraphError;
use crate::state::AppState;

/// The validated identity behind a Graph request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub claims: AccessTokenClaims,
}

impl Caller {
    /// Whether the caller holds `role` as an application permission.
    pub fn has_role(&self, role: &str) -> bool {
        self.claims.roles.iter().any(|held| held == role)
    }
}

/// Rejection for a request the caller may not make.
pub enum Rejected {
    /// The token was missing or unusable.
    Unauthenticated(GraphError),
    /// The token was valid but lacked a required permission.
    Forbidden(GraphError),
}

impl IntoResponse for Rejected {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated(error) => {
                let mut response = error.into_response();
                // Graph advertises the scheme on a 401 so clients know how to retry.
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    header::HeaderValue::from_static("Bearer"),
                );
                response
            }
            Self::Forbidden(error) => error.into_response(),
        }
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Rejected;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(presented) = bearer_token(&parts.headers) else {
            return Err(Rejected::Unauthenticated(GraphError::new(
                StatusCode::UNAUTHORIZED,
                "InvalidAuthenticationToken",
                "CompactToken parsing failed with error code: 80049217",
            )));
        };

        let audience = state.config.public_base_url();
        let issuer = format!("{}/{}/v2.0", audience, state.config.tenant_id);

        let claims = match token::validate(&state.signing_key, presented, &audience, &issuer) {
            Ok(claims) => claims,
            Err(error) => {
                debug!(%error, "rejected a bearer token");
                return Err(Rejected::Unauthenticated(GraphError::new(
                    StatusCode::UNAUTHORIZED,
                    "InvalidAuthenticationToken",
                    // Graph does not disclose why a token failed, and neither does this.
                    "Access token validation failure. Invalid audience.",
                )));
            }
        };

        let caller = Self { claims };
        authorise(parts, state, &caller)?;
        Ok(caller)
    }
}

/// Check the caller against the endpoint's published permission requirement.
///
/// Done here rather than in each handler so that no route can be served without the check:
/// asking for the caller is what performs it.
fn authorise(parts: &Parts, state: &AppState, caller: &Caller) -> Result<(), Rejected> {
    if !state.config.enforce_permissions {
        return Ok(());
    }

    let Some(matched) = parts.extensions.get::<MatchedPath>() else {
        // Only routes registered on the router reach here, and those always match.
        return Ok(());
    };
    let method = parts.method.as_str();
    let path = matched.as_str();

    let Some(demanded) = permissions::demanded(method, path) else {
        // Allowed rather than refused: a route the generated table does not cover is a gap in
        // the simulator, and failing closed would break a caller that the real service would
        // have served. The warning is what surfaces the gap.
        warn!(
            method,
            path, "no published permission requirement for this route; allowing the request"
        );
        return Ok(());
    };

    if permissions::satisfied(demanded, &caller.claims) {
        return Ok(());
    }

    debug!(
        method,
        path,
        held_roles = ?caller.claims.roles,
        "refused a request for lack of a required permission"
    );
    Err(Rejected::Forbidden(
        GraphError::authorization_request_denied(),
    ))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then_some(token.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bearer_scheme_is_matched_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer abc.def.ghi".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc.def.ghi"));
    }

    #[test]
    fn other_schemes_and_malformed_headers_yield_nothing() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);

        headers.insert(header::AUTHORIZATION, "Bearer".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
