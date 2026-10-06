//! Cross-origin headers, so a browser client can reach the simulator.
//!
//! Without these a single-page application cannot use the simulator at all: the browser refuses
//! the request to the token endpoint before it is sent. Terraform and the Azure SDKs never
//! noticed, because neither runs inside a browser.
//!
//! The default is permissive. Two reasons:
//!
//! - The simulator holds no real data and is reached only by whoever is testing it, so there is
//!   nothing for a stricter policy to protect.
//! - MSAL sends a shifting set of `x-client-*`, `client-request-id` and telemetry headers. A
//!   fixed allow-list would break on an MSAL upgrade, and the failure would look like a
//!   simulator fault.
//!
//! Credentials are not allowed, which is correct rather than a limitation: MSAL carries its
//! tokens in the `Authorization` header and uses no cookies.

use axum::http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;

use crate::config::Config;

/// Build the CORS layer for the configured origins.
pub fn layer(config: &Config) -> CorsLayer {
    let permissive = CorsLayer::permissive();

    if config.cors_allow_origin.is_empty() {
        return permissive;
    }

    let origins: Vec<HeaderValue> = config
        .cors_allow_origin
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(_) => {
                // Reported rather than ignored: a typo here presents as an unexplained browser
                // failure, which is hard to trace back to configuration.
                tracing::warn!(origin = %origin, "ignoring an unusable CORS origin");
                None
            }
        })
        .collect();

    info!(origins = ?config.cors_allow_origin, "restricting cross-origin requests");
    permissive.allow_origin(AllowOrigin::list(origins))
}
