//! Tests for serving more than one tenant from one process.

mod common;

use common::Sim;
use serde_json::{Value, json};

const SECOND: &str = "22222222-2222-2222-2222-222222222222";
const SECOND_DOMAIN: &str = "second.test";

async fn two_tenants() -> Sim {
    Sim::start_with(|config| {
        config.additional_tenants = vec![format!("{SECOND}={SECOND_DOMAIN}")];
    })
    .await
}

/// A bootstrap token from `tenant`, which may be named by ID or domain.
async fn bootstrap_token(sim: &Sim, tenant: &str) -> reqwest::Response {
    sim.client
        .post(sim.url(&format!("/{tenant}/oauth2/v2.0/token")))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", sim.bootstrap_client_id.as_str()),
            ("client_secret", sim.bootstrap_client_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .send()
        .await
        .unwrap()
}

async fn token_for(sim: &Sim, tenant: &str) -> String {
    let response = bootstrap_token(sim, tenant).await;
    assert_eq!(response.status(), 200, "token from {tenant}");
    let body: Value = response.json().await.unwrap();
    body["access_token"].as_str().unwrap().to_string()
}

async fn users(sim: &Sim, token: &str) -> Vec<String> {
    let body: Value = sim
        .client
        .get(sim.url("/v1.0/users"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userPrincipalName"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn each_tenant_issues_its_own_tokens() {
    let sim = two_tenants().await;
    let token = token_for(&sim, SECOND).await;
    let claims = common::decode_claims(&token);
    assert_eq!(claims["tid"], SECOND);
    assert_eq!(
        claims["iss"],
        format!("{}/{SECOND}/v2.0", sim.public_base_url).as_str()
    );
}

#[tokio::test]
async fn a_tenant_can_be_named_by_its_domain() {
    let sim = two_tenants().await;
    let token = token_for(&sim, SECOND_DOMAIN).await;
    assert_eq!(common::decode_claims(&token)["tid"], SECOND);
}

#[tokio::test]
async fn graph_serves_the_directory_of_the_tokens_tenant() {
    let sim = two_tenants().await;
    let first = token_for(&sim, &sim.tenant_id).await;
    let second = token_for(&sim, SECOND).await;

    let created = sim
        .client
        .post(sim.url("/v1.0/users"))
        .bearer_auth(&second)
        .json(&json!({
            "displayName": "Second Only",
            "userPrincipalName": format!("only@{SECOND_DOMAIN}"),
            "mailNickname": "only",
            "accountEnabled": true,
            "passwordProfile": { "password": "Sup3rSecret!" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    assert!(
        users(&sim, &second)
            .await
            .contains(&format!("only@{SECOND_DOMAIN}"))
    );
    assert!(
        !users(&sim, &first)
            .await
            .contains(&format!("only@{SECOND_DOMAIN}"))
    );
}

#[tokio::test]
async fn discovery_names_each_tenants_issuer() {
    let sim = two_tenants().await;
    let discovery = sim
        .get_json(&format!("/{SECOND}/v2.0/.well-known/openid-configuration"))
        .await;
    assert_eq!(
        discovery["issuer"],
        format!("{}/{SECOND}/v2.0", sim.public_base_url).as_str()
    );
    assert_eq!(
        discovery["token_endpoint"],
        format!("{}/{SECOND}/oauth2/v2.0/token", sim.public_base_url).as_str()
    );
}

#[tokio::test]
async fn an_unknown_tenant_is_invalid_tenant() {
    let sim = two_tenants().await;
    let unknown = "33333333-3333-3333-3333-333333333333";

    let response = bootstrap_token(&sim, unknown).await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    // Microsoft's reference: "AADSTS90002 InvalidTenantName".
    assert_eq!(body["error"], "invalid_tenant");
    assert_eq!(body["error_codes"][0], 90002);

    let discovery = sim
        .get(&format!("/{unknown}/v2.0/.well-known/openid-configuration"))
        .await;
    assert_eq!(discovery.status(), 400);
}

#[tokio::test]
async fn a_reset_resets_every_tenant() {
    let sim = two_tenants().await;
    let second = token_for(&sim, SECOND).await;
    sim.client
        .post(sim.url("/v1.0/users"))
        .bearer_auth(&second)
        .json(&json!({
            "displayName": "Temporary",
            "userPrincipalName": format!("temporary@{SECOND_DOMAIN}"),
            "mailNickname": "temporary",
            "accountEnabled": true
        }))
        .send()
        .await
        .unwrap();

    sim.post_json("/__sim__/reset", &json!({})).await;
    let second = token_for(&sim, SECOND).await;
    assert!(users(&sim, &second).await.is_empty());
}

#[tokio::test]
async fn a_malformed_additional_tenant_is_refused_at_startup() {
    let result = Sim::try_start_with(|config| {
        config.additional_tenants = vec!["no-domain".to_string()];
    })
    .await;
    assert!(result.is_err());
}

/// A multitenant public client registered in the primary tenant, and carol in the second.
async fn multitenant_fixture(sim: &Sim) -> (common::Client, String) {
    let primary = sim.graph().await;
    let client = primary
        .register_public_client(
            "Shared app",
            json!({ "signInAudience": "AzureADMultipleOrgs" }),
        )
        .await;
    let second = sim.graph_in(SECOND).await;
    let carol = second
        .create_user(&format!("carol@{SECOND_DOMAIN}"), "Carol Second")
        .await;
    (client, carol)
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Choose `user` on the sign-in page reached through `tenant`, returning the response.
async fn choose(
    sim: &Sim,
    tenant: &str,
    client_id: &str,
    user: &str,
    scope: &str,
) -> reqwest::Response {
    browser()
        .post(sim.url(&format!("/{tenant}/oauth2/v2.0/authorize")))
        .form(&[
            ("client_id", client_id),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", scope),
            ("user_id", user),
        ])
        .send()
        .await
        .unwrap()
}

fn code_of(response: &reqwest::Response) -> String {
    let location = response.headers()["location"].to_str().unwrap();
    location
        .split("code=")
        .nth(1)
        .unwrap_or_else(|| panic!("no code in {location}"))
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

async fn redeem(sim: &Sim, tenant: &str, client_id: &str, code: &str) -> reqwest::Response {
    sim.client
        .post(sim.url(&format!("/{tenant}/oauth2/v2.0/token")))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn common_offers_users_from_every_tenant() {
    let sim = two_tenants().await;
    let (client, _) = multitenant_fixture(&sim).await;
    sim.graph()
        .await
        .create_user("alice@entra-sim.test", "Alice Primary")
        .await;

    let page = browser()
        .get(sim.url("/common/oauth2/v2.0/authorize"))
        .query(&[
            ("client_id", client.app_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", "openid User.Read"),
        ])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("alice@entra-sim.test"), "{page}");
    assert!(page.contains(&format!("carol@{SECOND_DOMAIN}")), "{page}");
}

#[tokio::test]
async fn a_user_from_another_tenant_signs_in_to_their_own_tenant() {
    let sim = two_tenants().await;
    let (client, carol) = multitenant_fixture(&sim).await;

    let response = choose(&sim, "common", &client.app_id, &carol, "openid User.Read").await;
    assert_eq!(response.status(), 302);
    let redeemed = redeem(&sim, "common", &client.app_id, &code_of(&response)).await;
    assert_eq!(redeemed.status(), 200);
    let tokens: Value = redeemed.json().await.unwrap();

    // "When a response returns from the /common endpoint, the issuer value in the token
    // corresponds to the user's tenant."
    let id = common::decode_claims(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["tid"], SECOND);
    assert_eq!(
        id["iss"],
        format!("{}/{SECOND}/v2.0", sim.public_base_url).as_str()
    );

    // "a representation of the application called a service principal is created in the
    // user's tenant".
    let second = sim.graph_in(SECOND).await;
    let principals = second
        .get_ok(&format!(
            "/v1.0/servicePrincipals?$filter=appId%20eq%20'{}'",
            client.app_id
        ))
        .await;
    assert_eq!(principals["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_code_cannot_be_redeemed_against_another_tenant() {
    let sim = two_tenants().await;
    let (client, carol) = multitenant_fixture(&sim).await;
    let response = choose(&sim, "common", &client.app_id, &carol, "openid User.Read").await;

    let redeemed = redeem(&sim, &sim.tenant_id, &client.app_id, &code_of(&response)).await;
    assert_eq!(redeemed.status(), 400);
    let body: Value = redeemed.json().await.unwrap();
    // Microsoft's reference: "AADSTS700005 InvalidGrantRedeemAgainstWrongTenant".
    assert_eq!(body["error_codes"][0], 700005);
}

#[tokio::test]
async fn a_single_tenant_app_is_refused_through_common() {
    let sim = two_tenants().await;
    let primary = sim.graph().await;
    let client = primary.register_public_client("Mine only", json!({})).await;
    let alice = primary.create_user("alice@entra-sim.test", "Alice").await;

    let response = choose(&sim, "common", &client.app_id, &alice, "openid User.Read").await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS50194"));
}

#[tokio::test]
async fn a_tenant_specific_sign_in_refuses_a_user_from_another_tenant() {
    let sim = two_tenants().await;
    let (client, carol) = multitenant_fixture(&sim).await;

    let response = choose(
        &sim,
        &sim.tenant_id,
        &client.app_id,
        &carol,
        "openid User.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS50020"));
}

#[tokio::test]
async fn an_api_missing_from_the_users_tenant_is_refused() {
    let sim = two_tenants().await;
    let (client, carol) = multitenant_fixture(&sim).await;
    sim.graph()
        .await
        .register_api("Orders", "api://orders", &[], &["Orders.Read"], json!({}))
        .await;

    let response = choose(
        &sim,
        "common",
        &client.app_id,
        &carol,
        "openid api://orders/Orders.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS650052"));
}

#[tokio::test]
async fn a_known_clients_api_is_provisioned_in_the_users_tenant() {
    let sim = two_tenants().await;
    let primary = sim.graph().await;
    let client = primary
        .register_public_client(
            "Shared app",
            json!({ "signInAudience": "AzureADMultipleOrgs" }),
        )
        .await;
    let orders = primary
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({
                "signInAudience": "AzureADMultipleOrgs",
                "api": {
                    "requestedAccessTokenVersion": 2,
                    "knownClientApplications": [client.app_id]
                }
            }),
        )
        .await;
    let second = sim.graph_in(SECOND).await;
    let carol = second
        .create_user(&format!("carol@{SECOND_DOMAIN}"), "Carol Second")
        .await;

    // Entra "automatically provisions service principals for both APIs at the same time".
    let response = choose(
        &sim,
        "common",
        &client.app_id,
        &carol,
        "openid api://orders/.default",
    )
    .await;
    assert_eq!(response.status(), 302, "{:?}", response.text().await);
    let redeemed = redeem(&sim, "common", &client.app_id, &code_of(&response)).await;
    assert_eq!(redeemed.status(), 200);
    let tokens: Value = redeemed.json().await.unwrap();
    let access = common::decode_claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["aud"], orders.app_id.as_str());
    assert_eq!(access["tid"], SECOND);
}

#[tokio::test]
async fn a_multitenant_daemon_gets_tokens_in_a_tenant_that_added_it() {
    let sim = two_tenants().await;
    let primary = sim.graph().await;
    let daemon = primary
        .register_client(
            "SaaS daemon",
            json!({ "signInAudience": "AzureADMultipleOrgs" }),
        )
        .await;
    let request = |tenant: String| {
        let sim = &sim;
        let daemon = &daemon;
        async move {
            sim.client
                .post(sim.url(&format!("/{tenant}/oauth2/v2.0/token")))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", daemon.app_id.as_str()),
                    ("client_secret", daemon.secret.as_str()),
                    ("scope", "https://graph.microsoft.com/.default"),
                ])
                .send()
                .await
                .unwrap()
        }
    };

    // Unknown to the second tenant until an administrator adds it there.
    let refused = request(SECOND.to_string()).await;
    assert_eq!(refused.status(), 401);
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 700016);

    let second = sim.graph_in(SECOND).await;
    second
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": daemon.app_id }),
        )
        .await;
    let allowed = request(SECOND.to_string()).await;
    assert_eq!(allowed.status(), 200);
    let body: Value = allowed.json().await.unwrap();
    assert_eq!(
        common::decode_claims(body["access_token"].as_str().unwrap())["tid"],
        SECOND
    );
}

#[tokio::test]
async fn a_single_tenant_app_cannot_be_added_to_another_tenant() {
    let sim = two_tenants().await;
    let primary = sim.graph().await;
    let mine = primary.register_client("Mine only", json!({})).await;

    let second = sim.graph_in(SECOND).await;
    let response = second
        .post("/v1.0/servicePrincipals", &json!({ "appId": mine.app_id }))
        .await;
    assert_eq!(response.status(), 400);
}
