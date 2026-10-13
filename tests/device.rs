//! Tests for the device authorization grant.

mod common;

use common::Sim;
use serde_json::{Value, json};

const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct Fixture {
    client_id: String,
    bob: String,
}

async fn fixture(sim: &Sim) -> Fixture {
    let graph = sim.graph().await;
    Fixture {
        client_id: graph
            .register_public_client("Smart TV", json!({}))
            .await
            .app_id,
        bob: graph.create_user("bob@sim.test", "Bob Example").await,
    }
}

async fn start(sim: &Sim, f: &Fixture) -> Value {
    let response = sim
        .client
        .post(sim.url(&format!("/{}/oauth2/v2.0/devicecode", sim.tenant_id)))
        .form(&[
            ("client_id", f.client_id.as_str()),
            ("scope", "openid offline_access User.Read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

async fn poll(sim: &Sim, client_id: &str, device_code: &str) -> reqwest::Response {
    sim.token_request(&[
        ("grant_type", DEVICE_CODE),
        ("client_id", client_id),
        ("device_code", device_code),
    ])
    .await
}

async fn verify(sim: &Sim, form: &[(&str, &str)]) -> String {
    sim.client
        .post(sim.url("/devicelogin"))
        .form(form)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

async fn error_of(response: reqwest::Response) -> (String, u64) {
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    (
        body["error"].as_str().unwrap().to_string(),
        body["error_codes"][0].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn the_device_code_response_has_microsofts_fields() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let started = start(&sim, &f).await;

    assert!(started["device_code"].as_str().unwrap().len() > 20);
    assert_eq!(started["user_code"].as_str().unwrap().len(), 9);
    assert_eq!(
        started["verification_uri"],
        format!("{}/devicelogin", sim.public_base_url).as_str()
    );
    // "the user has 15 minutes to sign in. This is the default value for expires_in."
    assert_eq!(started["expires_in"], 900);
    assert!(started["interval"].as_u64().unwrap() > 0);
    assert!(
        started["message"]
            .as_str()
            .unwrap()
            .contains(started["user_code"].as_str().unwrap())
    );
}

#[tokio::test]
async fn the_device_gets_tokens_once_the_user_signs_in() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let started = start(&sim, &f).await;
    let device_code = started["device_code"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();

    assert_eq!(
        error_of(poll(&sim, &f.client_id, device_code).await).await,
        ("authorization_pending".to_string(), 70016)
    );

    let page = verify(&sim, &[("user_code", user_code)]).await;
    assert!(page.contains("Smart TV"), "{page}");
    assert!(page.contains("bob@sim.test"), "{page}");
    let done = verify(
        &sim,
        &[("user_code", user_code), ("user_id", f.bob.as_str())],
    )
    .await;
    assert!(done.contains("You have signed in"), "{done}");

    let response = poll(&sim, &f.client_id, device_code).await;
    assert_eq!(response.status(), 200);
    let tokens: Value = response.json().await.unwrap();
    assert!(tokens["id_token"].is_string());
    assert!(tokens["refresh_token"].is_string());
    let claims = common::decode_claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(claims["oid"], f.bob.as_str());
    assert!(claims["scp"].as_str().unwrap().contains("User.Read"));

    // The device code is spent.
    assert_eq!(
        error_of(poll(&sim, &f.client_id, device_code).await).await,
        ("bad_verification_code".to_string(), 70018)
    );
}

#[tokio::test]
async fn a_declined_sign_in_is_reported_to_the_device() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let started = start(&sim, &f).await;
    let user_code = started["user_code"].as_str().unwrap();

    verify(&sim, &[("user_code", user_code), ("decline", "1")]).await;
    assert_eq!(
        error_of(poll(&sim, &f.client_id, started["device_code"].as_str().unwrap()).await).await,
        ("authorization_declined".to_string(), 65004)
    );
}

#[tokio::test]
async fn a_wrong_user_code_is_refused_on_the_page() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    start(&sim, &f).await;

    let page = verify(&sim, &[("user_code", "WRONGCODE")]).await;
    assert!(page.contains("AADSTS70018"), "{page}");
}

#[tokio::test]
async fn an_unknown_device_code_or_another_client_is_refused() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let started = start(&sim, &f).await;

    assert_eq!(
        error_of(poll(&sim, &f.client_id, "not-a-device-code").await).await,
        ("bad_verification_code".to_string(), 70018)
    );
    // Microsoft: client_id "Must match the client_id used in the initial request."
    assert_eq!(
        error_of(
            poll(
                &sim,
                "99999999-9999-9999-9999-999999999999",
                started["device_code"].as_str().unwrap()
            )
            .await
        )
        .await,
        ("bad_verification_code".to_string(), 70018)
    );
}

#[tokio::test]
async fn discovery_names_the_device_endpoint_and_grant() {
    let sim = Sim::start().await;
    let discovery = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    assert_eq!(
        discovery["device_authorization_endpoint"],
        format!(
            "{}/{}/oauth2/v2.0/devicecode",
            sim.public_base_url, sim.tenant_id
        )
        .as_str()
    );
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(DEVICE_CODE))
    );
}
