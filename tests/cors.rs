//! Tests for the cross-origin headers a browser client depends on.
//!
//! Without these a single-page application cannot use the simulator at all. Terraform and the
//! Azure SDKs never exercised them, because neither runs in a browser.

mod common;

use common::Sim;

/// The headers MSAL actually sends on a token request. A fixed allow-list that missed one would
/// fail in the browser and look like a simulator fault.
const MSAL_HEADERS: &str = "authorization,content-type,x-client-sku,x-client-ver,\
                            x-client-os,x-client-cpu,client-request-id,\
                            x-client-current-telemetry,x-client-last-telemetry";

#[tokio::test]
async fn a_preflight_to_the_token_endpoint_is_answered() {
    let sim = Sim::start().await;

    // The browser sends this before it will send the real POST.
    let response = sim
        .client
        .request(
            reqwest::Method::OPTIONS,
            sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)),
        )
        .header("Origin", "http://localhost:5173")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", MSAL_HEADERS)
        .send()
        .await
        .expect("sending the preflight");

    assert!(
        response.status().is_success(),
        "the preflight should be answered, got {}",
        response.status()
    );

    let headers = response.headers();
    assert!(
        headers.contains_key("access-control-allow-origin"),
        "a preflight answer must allow the origin"
    );
    assert!(
        headers.contains_key("access-control-allow-methods"),
        "a preflight answer must allow the method"
    );
    assert!(
        headers.contains_key("access-control-allow-headers"),
        "a preflight answer must allow the requested headers"
    );
}

#[tokio::test]
async fn a_token_response_carries_the_origin_header() {
    let sim = Sim::start().await;
    let scope = format!("{}/.default", sim.public_base_url);

    let response = sim
        .client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .header("Origin", "http://localhost:5173")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("client_secret", &sim.bootstrap_client_secret),
            ("scope", &scope),
        ])
        .send()
        .await
        .expect("sending the token request");

    assert!(response.status().is_success());
    // Without this the browser discards the answer, even though the server replied.
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin"),
        "the token answer must carry access-control-allow-origin"
    );
}

#[tokio::test]
async fn a_graph_response_carries_the_origin_header() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph
        .get_with_origin("/v1.0/users", "http://localhost:5173")
        .await;
    assert!(response.status().is_success());
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin"),
        "a Graph answer must carry access-control-allow-origin"
    );
}

#[tokio::test]
async fn an_error_response_also_carries_the_origin_header() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // A client must be able to read the error body. Without the header the browser hides a 403
    // behind an opaque network failure, and the real cause is invisible.
    let response = graph
        .get_with_origin("/v1.0/users/missing", "http://localhost:5173")
        .await;
    assert_eq!(response.status(), 404);
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin"),
        "an error answer must carry access-control-allow-origin too"
    );
}

#[tokio::test]
async fn the_allowed_origin_can_be_restricted() {
    let sim = Sim::start_with(|config| {
        config.cors_allow_origin = vec!["http://localhost:5173".to_string()];
    })
    .await;
    let graph = sim.graph().await;

    let allowed = graph
        .get_with_origin("/v1.0/users", "http://localhost:5173")
        .await;
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:5173"
    );

    // A different origin gets no header, so the browser refuses the answer.
    let refused = graph
        .get_with_origin("/v1.0/users", "http://evil.example")
        .await;
    assert!(
        !refused
            .headers()
            .contains_key("access-control-allow-origin"),
        "an origin outside the list must not be allowed"
    );
}
