//! Tests for the authorization code flow, PKCE and refresh tokens.
//!
//! The client here does not follow redirects, so the assertions can inspect the Location header
//! the way a browser-based client's own code would.

mod common;

use base64::Engine;
use common::{Graph, Sim};
use serde_json::json;
use sha2::{Digest, Sha256};

const REDIRECT_URI: &str = "https://app.example.test/callback";
/// A verifier of the minimum length RFC 7636 permits.
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEF";

fn challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A registered public client and a user to sign in as.
struct Fixture {
    client_id: String,
    user_id: String,
    user_principal_name: String,
}

async fn fixture(graph: &Graph) -> Fixture {
    fixture_for(graph, "alice@sim.test", "Alice Example").await
}

/// A separate client and user, for assertions that must not inherit consent recorded by an
/// earlier flow: consent is additive and persists in the directory, as it does in Entra.
async fn fixture_for(graph: &Graph, upn: &str, display_name: &str) -> Fixture {
    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Interactive App",
                "publicClient": { "redirectUris": [REDIRECT_URI] }
            }),
        )
        .await;
    let client_id = application["appId"].as_str().unwrap().to_string();
    graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": client_id.clone() }),
        )
        .await;

    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": display_name,
                "userPrincipalName": upn,
                "accountEnabled": true,
                "passwordProfile": { "password": "Sup3rSecret!" }
            }),
        )
        .await;

    Fixture {
        client_id,
        user_id: user["id"].as_str().unwrap().to_string(),
        user_principal_name: user["userPrincipalName"].as_str().unwrap().to_string(),
    }
}

/// A client that reports redirects rather than following them.
fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("building a client")
}

#[tokio::test]
async fn the_sign_in_page_lists_the_users_and_the_requested_permissions() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid profile User.Read"),
            ("state", "opaque-state"),
        ])
        .send()
        .await
        .expect("sending the authorization request");

    assert_eq!(response.status(), 200);
    let page = response.text().await.unwrap();
    assert!(page.contains("Interactive App"), "got {page}");
    assert!(page.contains("alice@sim.test"));
    // The permissions the client is asking for are shown before consent is given.
    assert!(page.contains("User.Read"));
}

#[tokio::test]
async fn a_client_supplied_value_cannot_inject_markup_into_the_page() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "<script>alert(1)</script>"),
        ])
        .send()
        .await
        .unwrap();

    let page = response.text().await.unwrap();
    assert!(
        !page.contains("<script>alert(1)</script>"),
        "the state parameter was reflected unescaped"
    );
}

/// Drive the whole flow and return the token response.
async fn complete_flow(
    sim: &Sim,
    fixture: &Fixture,
    scope: &str,
    verifier: Option<&str>,
) -> serde_json::Value {
    let client = browser();
    let authorize = sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id));

    let mut form = vec![
        ("client_id", fixture.client_id.clone()),
        ("response_type", "code".to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", scope.to_string()),
        ("state", "opaque-state".to_string()),
        ("nonce", "a-nonce".to_string()),
        ("user_id", fixture.user_id.clone()),
    ];
    if let Some(verifier) = verifier {
        form.push(("code_challenge", challenge(verifier)));
        form.push(("code_challenge_method", "S256".to_string()));
    }

    let redirect = client
        .post(&authorize)
        .form(&form)
        .send()
        .await
        .expect("submitting the sign-in form");
    assert_eq!(
        redirect.status(),
        302,
        "expected a redirect back to the client"
    );

    let location = redirect
        .headers()
        .get("location")
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(REDIRECT_URI), "got {location}");
    // The state is echoed so the client can tie the response to its request.
    assert!(location.contains("state=opaque-state"), "got {location}");

    let code = extract(&location, "code");

    let mut body = vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", fixture.client_id.clone()),
        ("code", code),
        ("redirect_uri", REDIRECT_URI.to_string()),
    ];
    if let Some(verifier) = verifier {
        body.push(("code_verifier", verifier.to_string()));
    }

    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&body)
        .send()
        .await
        .expect("exchanging the code");
    let status = response.status();
    let decoded: serde_json::Value = response.json().await.expect("decoding the token response");
    assert!(
        status.is_success(),
        "the exchange returned {status}: {decoded}"
    );
    decoded
}

/// Pull a query parameter out of a redirect target.
fn extract(location: &str, name: &str) -> String {
    let query = location.split_once('?').expect("a query string").1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} missing from {location}"))
        .to_string()
}

#[tokio::test]
async fn the_full_flow_yields_an_access_token_and_an_id_token() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let tokens = complete_flow(&sim, &fixture, "openid profile User.Read", Some(VERIFIER)).await;
    assert_eq!(tokens["token_type"], "Bearer");

    let access = common::decode_claims(tokens["access_token"].as_str().unwrap());
    // A delegated token describes the user, carries scopes, and carries no roles.
    assert_eq!(access["idtyp"], "user");
    assert_eq!(access["oid"], fixture.user_id);
    assert_eq!(access["sub"], fixture.user_id);
    assert_eq!(access["upn"], fixture.user_principal_name);
    assert_eq!(access["appid"], fixture.client_id);
    assert_eq!(access["scp"], "User.Read");
    assert!(
        access["roles"].is_null(),
        "a delegated token must not carry app roles: {access}"
    );

    let id_token = common::decode_claims(tokens["id_token"].as_str().unwrap());
    // An ID token is addressed to the client, not to a resource.
    assert_eq!(id_token["aud"], fixture.client_id);
    assert_eq!(id_token["preferred_username"], fixture.user_principal_name);
    assert_eq!(id_token["name"], "Alice Example");
    assert_eq!(id_token["nonce"], "a-nonce");
}

#[tokio::test]
async fn the_id_token_validates_against_the_published_key() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let tokens = complete_flow(&sim, &fixture, "openid", Some(VERIFIER)).await;
    let id_token = tokens["id_token"].as_str().unwrap();

    let jwks = sim
        .get_json(&format!("/{}/discovery/v2.0/keys", sim.tenant_id))
        .await;
    let key = &jwks["keys"][0];
    let decoding = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .expect("building a decoding key");

    // A client library validates the ID token's audience against its own client ID.
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(std::slice::from_ref(&fixture.client_id));
    validation.set_issuer(&[format!("{}/{}/v2.0", sim.public_base_url, sim.tenant_id)]);
    jsonwebtoken::decode::<serde_json::Value>(id_token, &decoding, &validation)
        .expect("the ID token should validate");
}

#[tokio::test]
async fn a_delegated_token_is_accepted_by_the_graph_surface() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // User.Read.All is a delegated permission sufficient to list users.
    let tokens = complete_flow(&sim, &fixture, "openid User.Read.All", Some(VERIFIER)).await;
    let access = tokens["access_token"].as_str().unwrap();

    let response = sim
        .client
        .get(sim.url("/v1.0/users"))
        .bearer_auth(access)
        .send()
        .await
        .expect("sending the request");
    assert!(
        response.status().is_success(),
        "a delegated token with User.Read.All should list users, got {}",
        response.status()
    );
}

#[tokio::test]
async fn a_delegated_token_cannot_satisfy_an_app_only_requirement() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // Consenting to a delegated permission must not grant the app-only equivalent: the two are
    // distinct permission sets, and conflating them would let any client escalate by signing a
    // user in.
    let tokens = complete_flow(
        &sim,
        &fixture,
        "openid Application.ReadWrite.All",
        Some(VERIFIER),
    )
    .await;
    let access = tokens["access_token"].as_str().unwrap();
    let claims = common::decode_claims(access);
    assert!(claims["roles"].is_null());

    // The delegated scope does permit the call, since Graph documents it for both.
    let response = sim
        .client
        .post(sim.url("/v1.0/applications"))
        .bearer_auth(access)
        .json(&json!({ "displayName": "By Delegation" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // But a scope Graph does not document for the endpoint is refused. A fresh client is used
    // because the grant above persists and consent accumulates.
    let other = fixture_for(&graph, "bob@sim.test", "Bob Example").await;
    let narrow = complete_flow(&sim, &other, "openid User.Read", Some(VERIFIER)).await;
    let refused = sim
        .client
        .post(sim.url("/v1.0/applications"))
        .bearer_auth(narrow["access_token"].as_str().unwrap())
        .json(&json!({ "displayName": "Refused" }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
}

#[tokio::test]
async fn a_code_can_only_be_redeemed_once() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let redirect = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("user_id", fixture.user_id.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let location = redirect.headers()["location"].to_str().unwrap().to_string();
    let code = extract(&location, "code");

    let exchange = || async {
        client
            .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", fixture.client_id.as_str()),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT_URI),
            ])
            .send()
            .await
            .unwrap()
    };

    assert!(exchange().await.status().is_success());

    // A replayed code finds nothing, which is what makes interception less useful.
    let replay = exchange().await;
    assert_eq!(replay.status(), 400);
    let body: serde_json::Value = replay.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn a_mismatched_code_verifier_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let redirect = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("user_id", fixture.user_id.as_str()),
            ("code_challenge", challenge(VERIFIER).as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let code = extract(redirect.headers()["location"].to_str().unwrap(), "code");

    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", fixture.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            (
                "code_verifier",
                "zyxwvutsrqponmlkjihgfedcba9876543210-._~ABCDEF",
            ),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn a_verifier_is_required_once_pkce_was_used() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let redirect = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("user_id", fixture.user_id.as_str()),
            ("code_challenge", challenge(VERIFIER).as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let code = extract(redirect.headers()["location"].to_str().unwrap(), "code");

    // Omitting the verifier would defeat the point of having bound the code to the client.
    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", fixture.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn the_exchange_must_present_the_same_redirect_uri() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let redirect = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("user_id", fixture.user_id.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let code = extract(redirect.headers()["location"].to_str().unwrap(), "code");

    // A stolen code must not be redeemable towards a different destination.
    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", fixture.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "https://attacker.example/callback"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn an_unregistered_redirect_uri_is_refused_without_redirecting() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // Redirecting the error would send it to an unverified destination, so it is shown instead.
    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", "https://attacker.example/callback"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let page = response.text().await.unwrap();
    assert!(page.contains("AADSTS50011"), "got {page}");
}

#[tokio::test]
async fn an_unknown_client_is_refused_without_redirecting() {
    let sim = Sim::start().await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", "99999999-9999-9999-9999-999999999999"),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS700016"));
}

#[tokio::test]
async fn the_implicit_flow_is_refused_rather_than_half_implemented() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "id_token token"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS70005"));
}

#[tokio::test]
async fn a_refresh_token_is_issued_only_when_asked_for() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let without = complete_flow(&sim, &fixture, "openid User.Read", Some(VERIFIER)).await;
    assert!(without["refresh_token"].is_null());

    let with = complete_flow(
        &sim,
        &fixture,
        "openid offline_access User.Read",
        Some(VERIFIER),
    )
    .await;
    assert!(with["refresh_token"].is_string());
    // offline_access governs what is issued and is not a resource permission, so it does not
    // belong in the access token's scopes.
    assert_eq!(
        with["access_token"].as_str().map(|token| {
            common::decode_claims(token)["scp"]
                .as_str()
                .unwrap()
                .to_string()
        }),
        Some("User.Read".to_string())
    );
}

#[tokio::test]
async fn a_refresh_token_yields_a_fresh_access_token_and_is_rotated() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let first = complete_flow(
        &sim,
        &fixture,
        "openid offline_access User.Read",
        Some(VERIFIER),
    )
    .await;
    let refresh = first["refresh_token"].as_str().unwrap().to_string();

    let redeem = |token: String| {
        let client = client.clone();
        let url = sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id));
        let client_id = fixture.client_id.clone();
        async move {
            client
                .post(url)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", client_id.as_str()),
                    ("refresh_token", token.as_str()),
                ])
                .send()
                .await
                .unwrap()
        }
    };

    let response = redeem(refresh.clone()).await;
    assert!(response.status().is_success());
    let refreshed: serde_json::Value = response.json().await.unwrap();

    let claims = common::decode_claims(refreshed["access_token"].as_str().unwrap());
    assert_eq!(claims["oid"], fixture.user_id);
    // The refresh cannot widen the grant.
    assert_eq!(claims["scp"], "User.Read");

    // Entra rotates refresh tokens, so the presented one is consumed.
    let rotated = refreshed["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated, refresh);
    assert_eq!(redeem(refresh).await.status(), 400);
    assert!(redeem(rotated).await.status().is_success());
}

#[tokio::test]
async fn consent_is_recorded_in_the_directory() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    complete_flow(&sim, &fixture, "openid User.Read", Some(VERIFIER)).await;

    // Entra stores consent in the directory and derives the token's scopes from it, so an
    // administrator can see and revoke what a user agreed to.
    let grants = graph.get_ok("/v1.0/oauth2PermissionGrants").await;
    let found = grants["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["scope"].as_str() == Some("User.Read"))
        .unwrap_or_else(|| panic!("no grant recorded: {grants}"));
    assert_eq!(found["consentType"], "Principal");
    assert_eq!(found["principalId"], fixture.user_id);
}

#[tokio::test]
async fn a_scope_the_resource_does_not_publish_is_not_granted() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // A client cannot widen its own token by inventing a permission.
    let tokens = complete_flow(
        &sim,
        &fixture,
        "openid Nonsense.ReadWrite.All",
        Some(VERIFIER),
    )
    .await;
    let claims = common::decode_claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(
        claims["scp"].as_str().unwrap_or_default(),
        "",
        "an unpublished scope should not be granted: {claims}"
    );
}

#[tokio::test]
async fn the_configured_user_is_signed_in_without_the_picker() {
    let sim = Sim::start_with(|config| {
        config.auto_sign_in_user = Some("alice@sim.test".to_string());
    })
    .await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // For tests that cannot drive a browser.
    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "opaque"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 302);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with(REDIRECT_URI));
    assert!(location.contains("code="));
}

#[tokio::test]
async fn prompt_login_forces_the_picker_even_when_a_user_is_configured() {
    let sim = Sim::start_with(|config| {
        config.auto_sign_in_user = Some("alice@sim.test".to_string());
    })
    .await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("prompt", "login"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        200,
        "prompt=login should show the picker"
    );
}

#[tokio::test]
async fn signing_out_returns_to_the_requested_destination() {
    let sim = Sim::start().await;

    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/logout", sim.tenant_id)))
        .query(&[(
            "post_logout_redirect_uri",
            "https://app.example.test/goodbye",
        )])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()["location"].to_str().unwrap(),
        "https://app.example.test/goodbye"
    );
}

#[tokio::test]
async fn the_code_is_returned_in_the_fragment_when_asked_for() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // msal-browser uses fragment mode and offers no choice, so this is the only path a
    // single-page application can take.
    let redirect = browser()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("state", "opaque-state"),
            ("response_mode", "fragment"),
            ("user_id", fixture.user_id.as_str()),
        ])
        .send()
        .await
        .expect("submitting the sign-in form");

    assert_eq!(redirect.status(), 302);
    let location = redirect.headers()["location"].to_str().unwrap().to_string();

    let (base, response) = location
        .split_once('#')
        .unwrap_or_else(|| panic!("expected a fragment in {location}"));
    assert_eq!(base, REDIRECT_URI);
    assert!(response.contains("code="), "got {response}");
    assert!(response.contains("state=opaque-state"), "got {response}");
    // A fragment is never sent to a server, which is the reason MSAL insists on it.
    assert!(
        !base.contains("code="),
        "the code must not appear in the query string: {location}"
    );
}

#[tokio::test]
async fn a_fragment_code_still_exchanges_normally() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let redirect = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid offline_access User.Read"),
            ("response_mode", "fragment"),
            ("code_challenge", challenge(VERIFIER).as_str()),
            ("code_challenge_method", "S256"),
            ("user_id", fixture.user_id.as_str()),
        ])
        .send()
        .await
        .unwrap();

    let location = redirect.headers()["location"].to_str().unwrap().to_string();
    let fragment = location.split_once('#').expect("a fragment").1;
    let code = fragment
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("a code in the fragment");

    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", fixture.client_id.as_str()),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let tokens: serde_json::Value = response.json().await.unwrap();
    assert!(tokens["access_token"].is_string());
    assert!(tokens["id_token"].is_string());
    assert!(tokens["refresh_token"].is_string());
}

#[tokio::test]
async fn an_unsupported_response_mode_is_still_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // form_post is left out rather than half-implemented.
    let response = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&[
            ("client_id", fixture.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("response_mode", "form_post"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("form_post"));
}

#[tokio::test]
async fn the_me_endpoint_returns_the_signed_in_user() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    let tokens = complete_flow(&sim, &fixture, "openid User.Read", Some(VERIFIER)).await;
    let access = tokens["access_token"].as_str().unwrap();

    let response = sim
        .client
        .get(sim.url("/v1.0/me"))
        .bearer_auth(access)
        .send()
        .await
        .expect("sending the request");
    assert!(
        response.status().is_success(),
        "/me should answer a delegated token, got {}",
        response.status()
    );

    let me: serde_json::Value = response.json().await.unwrap();
    assert_eq!(me["id"], fixture.user_id);
    assert_eq!(me["userPrincipalName"], fixture.user_principal_name);
    assert_eq!(me["displayName"], "Alice Example");
}

#[tokio::test]
async fn the_me_endpoint_refuses_an_app_only_token() {
    let sim = Sim::start().await;

    // An app-only token has no user, so there is nobody for /me to describe. Answering would
    // hide a client that had asked for the wrong kind of token.
    let token = sim.client_credentials_token().await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let response = sim
        .client
        .get(sim.url("/v1.0/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Request_BadRequest");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("delegated"),
        "got {body}"
    );
}

#[tokio::test]
async fn the_me_endpoint_needs_a_user_read_scope() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // Consenting to nothing leaves the token with no scopes, so enforcement refuses the call.
    let tokens = complete_flow(&sim, &fixture, "openid", Some(VERIFIER)).await;
    let response = sim
        .client
        .get(sim.url("/v1.0/me"))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Authorization_RequestDenied");
}

#[tokio::test]
async fn revoking_consent_narrows_a_refreshed_token() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;
    let client = browser();

    let first = complete_flow(
        &sim,
        &fixture,
        "openid offline_access User.Read",
        Some(VERIFIER),
    )
    .await;
    assert_eq!(
        common::decode_claims(first["access_token"].as_str().unwrap())["scp"],
        "User.Read"
    );
    let refresh = first["refresh_token"].as_str().unwrap().to_string();

    // An administrator withdraws the consent the sign-in recorded.
    let grants = graph.get_ok("/v1.0/oauth2PermissionGrants").await;
    let grant_id = grants["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["scope"].as_str() == Some("User.Read"))
        .expect("the sign-in should have recorded a grant")["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        graph
            .delete(&format!("/v1.0/oauth2PermissionGrants/{grant_id}"))
            .await
            .status(),
        204
    );

    // Entra invalidates the refresh token when consent is withdrawn. Re-reading the directory
    // at issue time reaches the same outcome: the refreshed token keeps no permission the
    // directory no longer grants.
    let response = client
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", fixture.client_id.as_str()),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    let refreshed: serde_json::Value = response.json().await.unwrap();
    let claims = common::decode_claims(refreshed["access_token"].as_str().unwrap());
    assert_eq!(
        claims["scp"].as_str().unwrap_or_default(),
        "",
        "a refreshed token must not keep a revoked permission: {claims}"
    );

    // And the narrowed token is then refused by the endpoint that needs the permission.
    let refused = sim
        .client
        .get(sim.url("/v1.0/me"))
        .bearer_auth(refreshed["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
}

#[tokio::test]
async fn a_refresh_keeps_a_permission_that_is_still_consented() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let fixture = fixture(&graph).await;

    // The narrowing must not be over-eager: an untouched grant keeps working.
    let first = complete_flow(
        &sim,
        &fixture,
        "openid offline_access User.Read",
        Some(VERIFIER),
    )
    .await;

    let response = browser()
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", fixture.client_id.as_str()),
            ("refresh_token", first["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();

    let refreshed: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        common::decode_claims(refreshed["access_token"].as_str().unwrap())["scp"],
        "User.Read"
    );
    let _ = graph;
}
