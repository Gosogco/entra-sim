//! Tests for the client credentials grant.

mod common;

use common::Sim;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

/// Validate a token the way a client library would: fetch the JWKS, pick the key named by the
/// token's `kid`, and verify the signature, audience and issuer against it.
async fn claims_validated_against_jwks(sim: &Sim, token: &str) -> Value {
    let discovery = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    let issuer = discovery["issuer"].as_str().unwrap().to_string();
    let jwks_path = discovery["jwks_uri"]
        .as_str()
        .unwrap()
        .strip_prefix(&sim.public_base_url)
        .expect("jwks_uri should sit under the advertised base URL")
        .to_string();

    let header = decode_header(token).expect("decoding the token header");
    let kid = header.kid.expect("the token header should name a key");

    let jwks = sim.get_json(&jwks_path).await;
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"].as_str() == Some(kid.as_str()))
        .expect("the JWKS should publish the key the token was signed with");

    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .expect("building a decoding key from the JWKS entry");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(std::slice::from_ref(&sim.public_base_url));
    validation.set_issuer(&[issuer]);
    decode::<Value>(token, &decoding, &validation)
        .expect("the token should validate against the published key")
        .claims
}

#[tokio::test]
async fn issues_an_app_only_token_that_validates_against_the_published_key() {
    let sim = Sim::start().await;
    let response = sim.client_credentials_token().await;

    assert_eq!(response["token_type"].as_str().unwrap(), "Bearer");
    assert!(response["expires_in"].as_u64().unwrap() > 0);

    let token = response["access_token"].as_str().expect("an access token");
    let claims = claims_validated_against_jwks(&sim, token).await;

    assert_eq!(claims["appid"].as_str().unwrap(), sim.bootstrap_client_id);
    assert_eq!(claims["tid"].as_str().unwrap(), sim.tenant_id);
    assert_eq!(claims["ver"].as_str().unwrap(), "2.0");
    assert_eq!(claims["idtyp"].as_str().unwrap(), "app");
    // An app-only token has no user, so Entra sets `sub` to the service principal's object ID.
    assert_eq!(claims["sub"], claims["oid"]);
}

#[tokio::test]
async fn the_token_carries_an_iat_claim() {
    let sim = Sim::start().await;
    let response = sim.client_credentials_token().await;
    let token = response["access_token"].as_str().unwrap();
    let claims = claims_validated_against_jwks(&sim, token).await;

    // go-azure-sdk parses the access token purely to read `iat`, and fails to cache the token
    // without it.
    let issued_at = claims["iat"].as_i64().expect("iat should be a number");
    let expires = claims["exp"].as_i64().expect("exp should be a number");
    assert!(issued_at > 0);
    assert!(expires > issued_at);
    assert_eq!(claims["nbf"].as_i64().unwrap(), issued_at);
}

#[tokio::test]
async fn the_token_carries_the_granted_app_roles() {
    let sim = Sim::start().await;
    let response = sim.client_credentials_token().await;
    let token = response["access_token"].as_str().unwrap();
    let claims = claims_validated_against_jwks(&sim, token).await;

    let roles: Vec<&str> = claims["roles"]
        .as_array()
        .expect("roles should be present")
        .iter()
        .map(|role| role.as_str().unwrap())
        .collect();
    // The bootstrap client defaults to the permissions the azuread provider needs.
    assert!(
        roles.contains(&"Application.ReadWrite.All"),
        "got {roles:?}"
    );
    assert!(roles.contains(&"Directory.ReadWrite.All"), "got {roles:?}");
}

#[tokio::test]
async fn basic_authentication_is_accepted_as_well_as_form_fields() {
    let sim = Sim::start().await;

    let response = sim
        .client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .basic_auth(&sim.bootstrap_client_id, Some(&sim.bootstrap_client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", &format!("{}/.default", sim.public_base_url)),
        ])
        .send()
        .await
        .expect("sending the token request");

    assert!(
        response.status().is_success(),
        "client_secret_basic should be accepted, got {}",
        response.status()
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn a_wrong_secret_is_rejected_as_invalid_client() {
    let sim = Sim::start().await;
    let scope = format!("{}/.default", sim.public_base_url);
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("client_secret", "definitely-not-the-secret"),
            ("scope", &scope),
        ])
        .await;

    assert_eq!(response.status(), 401);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "invalid_client");
    // Operators search for the numeric code, so it has to be the real one.
    assert_eq!(body["error_codes"][0].as_u64().unwrap(), 7000215);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("AADSTS7000215")
    );
}

#[tokio::test]
async fn an_unknown_client_is_rejected_as_unauthorized_client() {
    let sim = Sim::start().await;
    let scope = format!("{}/.default", sim.public_base_url);
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", "99999999-9999-9999-9999-999999999999"),
            ("client_secret", "whatever"),
            ("scope", &scope),
        ])
        .await;

    assert_eq!(response.status(), 401);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "unauthorized_client");
    assert_eq!(body["error_codes"][0].as_u64().unwrap(), 700016);
}

#[tokio::test]
async fn an_unsupported_grant_type_is_refused() {
    let sim = Sim::start().await;
    let response = sim
        .token_request(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", &sim.bootstrap_client_id),
        ])
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "unsupported_grant_type");
}

#[tokio::test]
async fn a_scope_for_another_resource_is_refused() {
    let sim = Sim::start().await;
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("client_secret", &sim.bootstrap_client_secret),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .await;

    // The simulator is the only resource it can issue tokens for; anything else is a
    // misconfiguration worth surfacing rather than quietly honouring.
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "invalid_scope");
}
