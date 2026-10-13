//! Tests for client authentication with a signed assertion instead of a secret.

mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Graph, Sim, decode_claims};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sha2::Digest;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CERTIFICATE: &str = include_str!("fixtures/client-certificate.pem");
const KEY: &str = include_str!("fixtures/client-key.pem");
const OTHER_KEY: &str = include_str!("fixtures/other-key.pem");

/// The certificate's DER bytes, base64 encoded as Graph stores them.
fn certificate_base64() -> String {
    CERTIFICATE
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

fn certificate_der() -> Vec<u8> {
    STANDARD.decode(certificate_base64()).unwrap()
}

/// Register a confidential client with the test certificate and no secret.
async fn client_with_certificate(graph: &Graph) -> common::Client {
    let client = graph
        .register_public_client("Certificate client", json!({}))
        .await;
    let response = graph
        .patch(
            &format!("/v1.0/applications/{}", client.object_id),
            &json!({ "keyCredentials": [{
                "type": "AsymmetricX509Cert",
                "usage": "Verify",
                "key": certificate_base64(),
                "endDateTime": "2099-01-01T00:00:00Z"
            }] }),
        )
        .await;
    assert_eq!(response.status(), 204);
    client
}

struct Assertion<'a> {
    algorithm: Algorithm,
    key: &'a str,
    /// Name the certificate with `x5t#S256`, or with the older SHA-1 `x5t`.
    sha256: bool,
    audience: String,
    expires_in: i64,
}

impl<'a> Assertion<'a> {
    fn for_sim(sim: &Sim) -> Self {
        Self {
            algorithm: Algorithm::PS256,
            key: KEY,
            sha256: true,
            audience: format!(
                "{}/{}/oauth2/v2.0/token",
                sim.public_base_url, sim.tenant_id
            ),
            expires_in: 600,
        }
    }

    fn sign(&self, client_id: &str) -> String {
        let der = certificate_der();
        let mut header = Header::new(self.algorithm);
        if self.sha256 {
            header.x5t_s256 = Some(URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&der)));
        } else {
            header.x5t = Some(URL_SAFE_NO_PAD.encode(sha1::Sha1::digest(&der)));
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "aud": self.audience,
            "iss": client_id,
            "sub": client_id,
            "jti": uuid::Uuid::new_v4().to_string(),
            "nbf": now - 60,
            "iat": now - 60,
            "exp": now + self.expires_in,
        });
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(self.key.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

async fn app_token(sim: &Sim, client_id: &str, assertion: &str, scope: &str) -> reqwest::Response {
    sim.token_request(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion),
        ("scope", scope),
    ])
    .await
}

#[tokio::test]
async fn a_certificate_assertion_authenticates_the_client() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = client_with_certificate(&graph).await;

    let assertion = Assertion::for_sim(&sim).sign(&client.app_id);
    let response = app_token(
        &sim,
        &client.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    // Microsoft: "When you use a client certificate for authentication, the value is 2."
    assert_eq!(
        decode_claims(body["access_token"].as_str().unwrap())["appidacr"],
        "2"
    );
}

#[tokio::test]
async fn rs256_and_the_sha1_thumbprint_are_accepted_too() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = client_with_certificate(&graph).await;

    let assertion = Assertion {
        algorithm: Algorithm::RS256,
        sha256: false,
        ..Assertion::for_sim(&sim)
    }
    .sign(&client.app_id);
    let response = app_token(
        &sim,
        &client.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn an_assertion_signed_with_another_key_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = client_with_certificate(&graph).await;

    let assertion = Assertion {
        key: OTHER_KEY,
        ..Assertion::for_sim(&sim)
    }
    .sign(&client.app_id);
    let response = app_token(
        &sim,
        &client.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(body["error_codes"][0], 700027);
}

#[tokio::test]
async fn an_assertion_for_another_audience_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = client_with_certificate(&graph).await;

    let assertion = Assertion {
        audience: "https://login.microsoftonline.com/another/oauth2/v2.0/token".to_string(),
        ..Assertion::for_sim(&sim)
    }
    .sign(&client.app_id);
    let response = app_token(
        &sim,
        &client.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50027);
}

#[tokio::test]
async fn an_expired_assertion_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = client_with_certificate(&graph).await;

    let assertion = Assertion {
        expires_in: -600,
        ..Assertion::for_sim(&sim)
    }
    .sign(&client.app_id);
    let response = app_token(
        &sim,
        &client.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50027);
}

#[tokio::test]
async fn an_assertion_from_a_client_without_the_certificate_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let without = graph.register_client("No certificate", json!({})).await;

    let assertion = Assertion::for_sim(&sim).sign(&without.app_id);
    let response = app_token(
        &sim,
        &without.app_id,
        &assertion,
        "https://graph.microsoft.com/.default",
    )
    .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 700027);
}

#[tokio::test]
async fn a_confidential_client_with_no_credential_is_refused() {
    let sim = Sim::start().await;
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    // "The request body must contain the following parameter: 'client_assertion' or
    // 'client_secret'."
    assert_eq!(body["error_codes"][0], 7000218);
}

#[tokio::test]
async fn a_code_redeemed_with_an_assertion_reports_a_certificate() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    let client = client_with_certificate(&graph).await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;

    let redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", client.app_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", "openid api://orders/Orders.Read"),
            ("user_id", bob.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let location = redirect.headers()["location"].to_str().unwrap().to_string();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let assertion = Assertion::for_sim(&sim).sign(&client.app_id);
    let response = sim
        .token_request(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client.app_id),
            ("code", code),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ])
        .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        decode_claims(body["access_token"].as_str().unwrap())["azpacr"],
        "2"
    );
}
