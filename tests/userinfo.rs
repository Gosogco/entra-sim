//! Tests for the OpenID Connect UserInfo endpoint.

mod common;

use common::Sim;
use serde_json::{Value, json};

/// Carol, with names and a mail address, and a public client to sign her in through.
async fn fixture(sim: &Sim) -> (String, String) {
    let graph = sim.graph().await;
    let client = graph.register_public_client("Website", json!({})).await;
    let carol = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Carol Example",
                "givenName": "Carol",
                "surname": "Example",
                "mail": "carol@mail.example.test",
                "userPrincipalName": "carol@sim.test",
                "mailNickname": "carol",
                "accountEnabled": true,
                "passwordProfile": { "password": "Sup3rSecret!" }
            }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    (client.app_id, carol)
}

async fn userinfo(sim: &Sim, token: &str, post: bool) -> reqwest::Response {
    let url = sim.url("/oidc/userinfo");
    let request = if post {
        sim.client.post(url)
    } else {
        sim.client.get(url)
    };
    request.bearer_auth(token).send().await.unwrap()
}

#[tokio::test]
async fn userinfo_returns_the_claims_the_scopes_allow() {
    let sim = Sim::start().await;
    let (client, carol) = fixture(&sim).await;
    let token = sim
        .sign_in_ok(&client, &carol, "openid profile email User.Read")
        .await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    for post in [false, true] {
        let response = userinfo(&sim, &token, post).await;
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["sub"], carol.as_str());
        assert_eq!(body["name"], "Carol Example");
        assert_eq!(body["given_name"], "Carol");
        assert_eq!(body["family_name"], "Example");
        assert_eq!(body["email"], "carol@mail.example.test");
        assert!(
            body["picture"]
                .as_str()
                .unwrap()
                .ends_with("/v1.0/me/photo/$value")
        );
    }
}

#[tokio::test]
async fn without_profile_and_email_only_the_subject_is_returned() {
    let sim = Sim::start().await;
    let (client, carol) = fixture(&sim).await;
    let token = sim.sign_in_ok(&client, &carol, "openid User.Read").await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let body: Value = userinfo(&sim, &token, false).await.json().await.unwrap();
    assert_eq!(body, json!({ "sub": carol }));
}

#[tokio::test]
async fn an_app_only_token_is_refused() {
    let sim = Sim::start().await;
    let token = sim.client_credentials_token().await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(userinfo(&sim, &token, false).await.status(), 403);
}

#[tokio::test]
async fn a_token_for_another_api_is_refused() {
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
    let (client, carol) = fixture(&sim).await;
    let token = sim
        .sign_in_ok(&client, &carol, "openid api://orders/Orders.Read")
        .await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // UserInfo is a Graph API, so it takes a Graph token only.
    assert_eq!(userinfo(&sim, &token, false).await.status(), 401);
}

#[tokio::test]
async fn discovery_names_the_userinfo_endpoint() {
    let sim = Sim::start().await;
    let discovery = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    assert_eq!(
        discovery["userinfo_endpoint"],
        format!("{}/oidc/userinfo", sim.public_base_url).as_str()
    );
}
