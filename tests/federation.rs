//! Tests for federated identity credentials: a client authenticating with a token from another
//! identity provider, such as a GitHub Actions job.

mod common;

use std::net::{Ipv4Addr, SocketAddr};

use axum::Json;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Graph, Sim, decode_claims};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const EXCHANGE_AUDIENCE: &str = "api://AzureADTokenExchange";
const SUBJECT: &str = "repo:gosogco/entra-sim:ref:refs/heads/main";
const KEY: &str = include_str!("fixtures/client-key.pem");
const OTHER_KEY: &str = include_str!("fixtures/other-key.pem");

/// Serve an OpenID Connect discovery document and a JWKS publishing `KEY`, the way an external
/// identity provider does, and return its issuer URL.
async fn external_issuer() -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());

    let private = rsa::RsaPrivateKey::from_pkcs8_pem(KEY).unwrap();
    let jwks = json!({ "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "external-key",
        "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
    }] });
    let discovery = json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/keys") });

    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let discovery = discovery.clone();
                async move { Json(discovery) }
            }),
        )
        .route(
            "/keys",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    issuer
}

fn external_token(issuer: &str, subject: &str, audience: &str, key: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("external-key".to_string());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    encode(
        &header,
        &json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "nbf": now - 60,
            "iat": now - 60,
            "exp": now + 600,
        }),
        &EncodingKey::from_rsa_pem(key.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// A client trusting `issuer` for `subject` and `audience`.
async fn federated_client(
    graph: &Graph,
    issuer: &str,
    subject: &str,
    audience: &str,
) -> common::Client {
    let client = graph.register_public_client("Deploy job", json!({})).await;
    graph
        .post_created(
            &format!(
                "/v1.0/applications/{}/federatedIdentityCredentials",
                client.object_id
            ),
            &json!({
                "name": "github-main",
                "issuer": issuer,
                "subject": subject,
                "audiences": [audience]
            }),
        )
        .await;
    client
}

async fn exchange(sim: &Sim, client_id: &str, assertion: &str) -> reqwest::Response {
    sim.token_request(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion),
        ("scope", "https://graph.microsoft.com/.default"),
    ])
    .await
}

#[tokio::test]
async fn an_external_token_matching_the_credential_authenticates_the_client() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let issuer = external_issuer().await;
    let client = federated_client(&graph, &issuer, SUBJECT, EXCHANGE_AUDIENCE).await;

    let response = exchange(
        &sim,
        &client.app_id,
        &external_token(&issuer, SUBJECT, EXCHANGE_AUDIENCE, KEY),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let claims = decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(claims["appid"], client.app_id.as_str());
}

#[tokio::test]
async fn another_subject_has_no_matching_credential() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let issuer = external_issuer().await;
    let client = federated_client(&graph, &issuer, SUBJECT, EXCHANGE_AUDIENCE).await;

    let response = exchange(
        &sim,
        &client.app_id,
        &external_token(
            &issuer,
            "repo:gosogco/entra-sim:pull_request",
            EXCHANGE_AUDIENCE,
            KEY,
        ),
    )
    .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 70021);
}

#[tokio::test]
async fn another_audience_has_no_matching_credential() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let issuer = external_issuer().await;
    let client = federated_client(&graph, &issuer, SUBJECT, EXCHANGE_AUDIENCE).await;

    let response = exchange(
        &sim,
        &client.app_id,
        &external_token(&issuer, SUBJECT, "api://something-else", KEY),
    )
    .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 70021);
}

#[tokio::test]
async fn the_subject_is_matched_case_sensitively() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let issuer = external_issuer().await;
    let client = federated_client(&graph, &issuer, SUBJECT, EXCHANGE_AUDIENCE).await;

    let response = exchange(
        &sim,
        &client.app_id,
        &external_token(&issuer, &SUBJECT.to_uppercase(), EXCHANGE_AUDIENCE, KEY),
    )
    .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_token_not_signed_by_the_issuers_key_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let issuer = external_issuer().await;
    let client = federated_client(&graph, &issuer, SUBJECT, EXCHANGE_AUDIENCE).await;

    let response = exchange(
        &sim,
        &client.app_id,
        &external_token(&issuer, SUBJECT, EXCHANGE_AUDIENCE, OTHER_KEY),
    )
    .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50027);
}

#[tokio::test]
async fn an_entra_user_token_cannot_be_a_federated_assertion() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let exchange_api = graph
        .register_api(
            "Exchange",
            "api://exchange",
            &[],
            &["Exchange.Use"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    let website = graph.register_public_client("Website", json!({})).await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let user_token = sim
        .sign_in_ok(&website.app_id, &bob, "openid api://exchange/Exchange.Use")
        .await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let issuer = format!("{}/{}/v2.0", sim.public_base_url, sim.tenant_id);
    let client = federated_client(&graph, &issuer, &bob, &exchange_api.app_id).await;
    let response = exchange(&sim, &client.app_id, &user_token).await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    // "Only app-only tokens can be used as Federated Identity Credentials for Microsoft Entra
    // issuer."
    assert_eq!(body["error_codes"][0], 700229);
}
