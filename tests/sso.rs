//! Tests for single sign-on: the browser session and the `prompt` and `login_hint` parameters.

mod common;

use common::{SIGN_IN_REDIRECT, Sim};
use serde_json::json;

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

struct Fixture {
    client_id: String,
    alice: String,
    bob: String,
}

async fn fixture(sim: &Sim) -> Fixture {
    let graph = sim.graph().await;
    let client = graph.register_public_client("Website", json!({})).await;
    Fixture {
        client_id: client.app_id,
        alice: graph.create_user("alice@sim.test", "Alice Example").await,
        bob: graph.create_user("bob@sim.test", "Bob Example").await,
    }
}

/// Sign `user` in through the page and return the session cookie it sets.
async fn sign_in(sim: &Sim, f: &Fixture, user: &str, scope: &str) -> String {
    let response = browser()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", f.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", SIGN_IN_REDIRECT),
            ("scope", scope),
            ("user_id", user),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_string();
    cookie.split(';').next().unwrap().to_string()
}

/// GET the authorization endpoint with extra parameters and an optional cookie.
async fn authorize(
    sim: &Sim,
    f: &Fixture,
    scope: &str,
    extra: &[(&str, &str)],
    cookie: Option<&str>,
) -> reqwest::Response {
    let mut query = vec![
        ("client_id", f.client_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", SIGN_IN_REDIRECT),
        ("scope", scope),
    ];
    query.extend_from_slice(extra);
    let mut request = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .query(&query);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    request.send().await.unwrap()
}

fn location(response: &reqwest::Response) -> String {
    response.headers()["location"].to_str().unwrap().to_string()
}

#[tokio::test]
async fn a_signed_in_browser_is_signed_in_again_without_the_page() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let response = authorize(&sim, &f, "openid User.Read", &[], Some(&cookie)).await;
    assert_eq!(response.status(), 302);
    assert!(
        location(&response).contains("code="),
        "{}",
        location(&response)
    );
}

#[tokio::test]
async fn a_new_permission_shows_the_page_even_when_signed_in() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let response = authorize(&sim, &f, "openid Mail.Read", &[], Some(&cookie)).await;
    assert_eq!(
        response.status(),
        200,
        "consent to Mail.Read is still needed"
    );
}

#[tokio::test]
async fn prompt_none_without_a_session_answers_login_required() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;

    let response = authorize(&sim, &f, "openid User.Read", &[("prompt", "none")], None).await;
    assert_eq!(response.status(), 302);
    assert!(
        location(&response).contains("error=login_required"),
        "{}",
        location(&response)
    );
}

#[tokio::test]
async fn prompt_none_with_a_session_returns_a_code() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let response = authorize(
        &sim,
        &f,
        "openid User.Read",
        &[("prompt", "none")],
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), 302);
    assert!(
        location(&response).contains("code="),
        "{}",
        location(&response)
    );
}

#[tokio::test]
async fn prompt_none_without_consent_answers_interaction_required() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let response = authorize(
        &sim,
        &f,
        "openid Mail.Read",
        &[("prompt", "none")],
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), 302);
    assert!(
        location(&response).contains("error=interaction_required"),
        "{}",
        location(&response)
    );
}

#[tokio::test]
async fn select_account_and_consent_show_the_page_even_when_signed_in() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    for prompt in ["select_account", "consent", "login"] {
        let response = authorize(
            &sim,
            &f,
            "openid User.Read",
            &[("prompt", prompt)],
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status(), 200, "prompt={prompt}");
    }
}

#[tokio::test]
async fn a_hint_for_another_user_shows_the_page_with_that_user_first() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let response = authorize(
        &sim,
        &f,
        "openid User.Read",
        &[("login_hint", "bob@sim.test")],
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), 200);
    let page = response.text().await.unwrap();
    let bob = page.find("bob@sim.test").unwrap();
    let alice = page.find("alice@sim.test").unwrap();
    assert!(bob < alice, "the hinted user should be offered first");
    let _ = f.bob;
}

#[tokio::test]
async fn signing_out_ends_the_session() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let cookie = sign_in(&sim, &f, &f.alice, "openid User.Read").await;

    let signed_out = browser()
        .get(sim.url(&format!("/{}/oauth2/v2.0/logout", sim.tenant_id)))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    let cleared = signed_out.headers()["set-cookie"].to_str().unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    let response = authorize(
        &sim,
        &f,
        "openid User.Read",
        &[("prompt", "none")],
        Some(&cookie),
    )
    .await;
    assert!(location(&response).contains("error=login_required"));
}
