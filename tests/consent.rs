//! Tests for static consent through `.default`, and for knownClientApplications.

mod common;

use common::{Api, Graph, Sim, decode_claims};
use serde_json::{Value, json};

const GRAPH: &str = "00000003-0000-0000-c000-000000000000";
const USER_READ: &str = "e1fe6dd8-ba31-4d61-89e7-88639da4683d";

async fn orders(graph: &Graph, extra: Value) -> Api {
    let mut extra = extra;
    extra
        .as_object_mut()
        .unwrap()
        .entry("api")
        .or_insert(json!({}))
        .as_object_mut()
        .unwrap()
        .insert("requestedAccessTokenVersion".to_string(), json!(2));
    graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read", "Orders.Write"],
            extra,
        )
        .await
}

/// A public client requiring `orders_scopes` on Orders and User.Read on Graph.
async fn client_requiring(
    graph: &Graph,
    orders: &Api,
    orders_scopes: &[&str],
    extra: Value,
) -> common::Client {
    let mut body = json!({
        "requiredResourceAccess": [
            {
                "resourceAppId": orders.app_id,
                "resourceAccess": orders_scopes.iter().map(|scope| json!({
                    "id": orders.scopes[*scope], "type": "Scope"
                })).collect::<Vec<_>>()
            },
            { "resourceAppId": GRAPH, "resourceAccess": [{ "id": USER_READ, "type": "Scope" }] }
        ]
    });
    for (key, value) in extra.as_object().unwrap() {
        body[key] = value.clone();
    }
    graph.register_public_client("Website", body).await
}

fn scp(tokens: &Value) -> String {
    decode_claims(tokens["access_token"].as_str().unwrap())["scp"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn default_consents_every_permission_the_client_requires() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let orders = orders(&graph, json!({})).await;
    let client = client_requiring(&graph, &orders, &["Orders.Read"], json!({})).await;
    let bob = graph.create_user("bob@sim.test", "Bob").await;

    // "a consent prompt is shown for all required permissions configured on the client
    // application registration, for all APIs in the list".
    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid api://orders/.default")
        .await;
    assert_eq!(scp(&tokens), "Orders.Read");

    let grants = graph.get_ok("/v1.0/oauth2PermissionGrants").await;
    let scopes: Vec<&str> = grants["value"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|grant| grant["scope"].as_str())
        .collect();
    assert!(
        scopes.iter().any(|scope| scope.contains("User.Read")),
        "{grants}"
    );
}

#[tokio::test]
async fn default_adds_nothing_once_consent_exists_unless_prompt_is_consent() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let orders = orders(&graph, json!({})).await;
    let client =
        client_requiring(&graph, &orders, &["Orders.Read", "Orders.Write"], json!({})).await;
    let bob = graph.create_user("bob@sim.test", "Bob").await;

    // Consent to one permission dynamically first.
    sim.sign_in_ok(&client.app_id, &bob, "openid api://orders/Orders.Read")
        .await;
    // "If consent exists, the returned token contains all scopes granted for that resource".
    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid api://orders/.default")
        .await;
    assert_eq!(scp(&tokens), "Orders.Read");

    // prompt=consent shows the prompt for all required permissions again.
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", client.app_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", "openid api://orders/.default"),
            ("prompt", "consent"),
            ("user_id", bob.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid api://orders/.default")
        .await;
    let mut granted: Vec<String> = scp(&tokens).split(' ').map(str::to_string).collect();
    granted.sort();
    assert_eq!(granted, ["Orders.Read", "Orders.Write"]);
}

#[tokio::test]
async fn default_cannot_be_combined_with_named_permissions() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = graph.register_public_client("Website", json!({})).await;

    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", client.app_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", "https://graph.microsoft.com/.default Mail.Read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.contains("error=invalid_scope"), "{location}");
    assert!(location.contains("AADSTS70011"), "{location}");
}

#[tokio::test]
async fn a_known_client_consents_for_the_api_too_and_on_behalf_of_works() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let inventory = graph
        .register_api(
            "Inventory",
            "api://inventory",
            &[],
            &["Inventory.Read"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    // Orders requires Inventory.Read for itself; it learns the client's appId afterwards.
    let orders = orders(
        &graph,
        json!({
            "requiredResourceAccess": [{
                "resourceAppId": inventory.app_id,
                "resourceAccess": [{ "id": inventory.scopes["Inventory.Read"], "type": "Scope" }]
            }]
        }),
    )
    .await;
    let client = client_requiring(&graph, &orders, &["Orders.Read"], json!({})).await;
    let patched = graph
        .patch(
            &format!("/v1.0/applications/{}", orders.object_id),
            &json!({ "api": {
                "requestedAccessTokenVersion": 2,
                "knownClientApplications": [client.app_id],
                "oauth2PermissionScopes": [
                    { "id": orders.scopes["Orders.Read"], "value": "Orders.Read",
                      "adminConsentDisplayName": "Orders.Read",
                      "adminConsentDescription": "Orders.Read", "isEnabled": true, "type": "User" },
                    { "id": orders.scopes["Orders.Write"], "value": "Orders.Write",
                      "adminConsentDisplayName": "Orders.Write",
                      "adminConsentDescription": "Orders.Write", "isEnabled": true, "type": "User" }
                ]
            } }),
        )
        .await;
    assert_eq!(patched.status(), 204);
    let orders_secret = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{}/addPassword", orders.object_id),
            &json!({}),
        )
        .await["secretText"]
        .as_str()
        .unwrap()
        .to_string();
    let bob = graph.create_user("bob@sim.test", "Bob").await;

    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid api://orders/.default")
        .await;

    // The single consent covered Orders calling Inventory too, so Orders can exchange bob's
    // token without any administrator consent.
    let exchanged = sim
        .token_request(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", &orders.app_id),
            ("client_secret", &orders_secret),
            ("assertion", tokens["access_token"].as_str().unwrap()),
            ("scope", "api://inventory/.default"),
            ("requested_token_use", "on_behalf_of"),
        ])
        .await;
    assert_eq!(exchanged.status(), 200);
    let body: Value = exchanged.json().await.unwrap();
    assert_eq!(scp(&body), "Inventory.Read");
}
