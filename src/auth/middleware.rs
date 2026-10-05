//! Bearer token validation for the Graph surface.
//!
//! Handlers receive the validated claims as an extractor, so a route cannot accidentally serve
//! an unauthenticated request: asking for `Caller` is what performs the check.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::debug;

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

/// Rejection for a request with a missing or unusable token.
pub struct Unauthenticated(GraphError);

impl IntoResponse for Unauthenticated {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        // Graph advertises the scheme on a 401 so clients know how to retry.
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
        response
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Unauthenticated;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(presented) = bearer_token(&parts.headers) else {
            return Err(Unauthenticated(GraphError::new(
                StatusCode::UNAUTHORIZED,
                "InvalidAuthenticationToken",
                "CompactToken parsing failed with error code: 80049217",
            )));
        };

        let audience = state.config.public_base_url();
        let issuer = format!("{}/{}/v2.0", audience, state.config.tenant_id);

        match token::validate(&state.signing_key, presented, &audience, &issuer) {
            Ok(claims) => Ok(Self { claims }),
            Err(error) => {
                debug!(%error, "rejected a bearer token");
                Err(Unauthenticated(GraphError::new(
                    StatusCode::UNAUTHORIZED,
                    "InvalidAuthenticationToken",
                    // Graph does not disclose why a token failed, and neither does this.
                    "Access token validation failure. Invalid audience.",
                )))
            }
        }
    }
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
