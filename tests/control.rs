//! Tests for seeding, snapshots and reset.

mod common;

use common::Sim;
use serde_json::json;

#[tokio::test]
async fn health_reports_the_tenant_it_serves() {
    let sim = Sim::start().await;
    let body = sim.get_json("/__sim__/health").await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["tenantId"].as_str(), None, "field is snake-cased");
    assert_eq!(body["tenant_id"], sim.tenant_id);
}

#[tokio::test]
async fn a_snapshot_round_trips_through_reset() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Alice Example",
                "userPrincipalName": "alice@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let group = graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": "Platform",
                "mailEnabled": false,
                "securityEnabled": true
            }),
        )
        .await;
    let group_id = group["id"].as_str().unwrap().to_string();
    let users = graph.get_ok("/v1.0/users").await;
    let user_id = users["value"][0]["id"].as_str().unwrap().to_string();
    graph
        .post(
            &format!("/v1.0/groups/{group_id}/members/$ref"),
            &json!({
                "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{user_id}")
            }),
        )
        .await;

    let snapshot = sim.get_json("/__sim__/snapshot").await;

    // Reset clears everything the test created.
    let counts = sim.post_json("/__sim__/reset", &json!({})).await;
    assert_eq!(counts["users"], 0);
    assert_eq!(counts["groups"], 0);
    let after_reset = graph.get_ok("/v1.0/users").await;
    assert!(after_reset["value"].as_array().unwrap().is_empty());

    // Loading the snapshot puts it all back, membership included.
    sim.post_json("/__sim__/snapshot", &snapshot).await;
    let restored = graph.get_ok("/v1.0/users").await;
    assert_eq!(restored["value"].as_array().unwrap().len(), 1);
    let members = graph
        .get_ok(&format!("/v1.0/groups/{group_id}/members"))
        .await;
    assert_eq!(
        members["value"][0]["id"], user_id,
        "group membership is a navigation property, so it must be restored separately"
    );
}

#[tokio::test]
async fn a_restored_snapshot_keeps_secrets_usable() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({ "displayName": "Snapshotted" }),
        )
        .await;
    let object_id = application["id"].as_str().unwrap().to_string();
    let client_id = application["appId"].as_str().unwrap().to_string();
    graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": client_id.clone() }),
        )
        .await;
    let secret = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{object_id}/addPassword"),
            &json!({}),
        )
        .await;
    let secret_text = secret["secretText"].as_str().unwrap().to_string();

    let snapshot = sim.get_json("/__sim__/snapshot").await;
    sim.post_json("/__sim__/reset", &json!({})).await;
    sim.post_json("/__sim__/snapshot", &snapshot).await;

    // Graph never discloses a secret on read, so a snapshot that only captured the API's view
    // would restore applications that exist but cannot authenticate.
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &secret_text),
            ("scope", &format!("{}/.default", sim.public_base_url)),
        ])
        .await;
    assert!(
        response.status().is_success(),
        "a restored secret should still authenticate, got {}",
        response.status()
    );
}

#[tokio::test]
async fn reset_leaves_the_bootstrap_client_able_to_authenticate() {
    let sim = Sim::start().await;
    sim.post_json("/__sim__/reset", &json!({})).await;

    // Otherwise a reset would leave the simulator unusable: no client could authenticate in
    // order to create one.
    let graph = sim.graph().await;
    assert_eq!(graph.get("/v1.0/users").await.status(), 200);
}

#[tokio::test]
async fn reset_invalidates_outstanding_authorization_state() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Interactive",
                "publicClient": { "redirectUris": ["https://app.test/cb"] }
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
                "displayName": "Alice",
                "userPrincipalName": "alice@sim.test",
                "accountEnabled": true
            }),
        )
        .await;

    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let redirect = browser
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", "https://app.test/cb"),
            ("scope", "openid"),
            ("user_id", user["id"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    let location = redirect.headers()["location"].to_str().unwrap().to_string();
    let code = location
        .split('?')
        .nth(1)
        .unwrap()
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .unwrap()
        .to_string();

    sim.post_json("/__sim__/reset", &json!({})).await;

    // The code refers to a user and client that no longer exist, so holding onto it would let a
    // stale code mint a token against the new directory.
    let response = browser
        .post(sim.url(&format!("/{}/oauth2/v2.0/token", sim.tenant_id)))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.test/cb"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_seed_file_is_applied_at_startup_and_on_reset() {
    let seed = json!({
        "users": [{
            "id": "11111111-1111-1111-1111-111111111111",
            "userPrincipalName": "seeded@sim.test",
            "displayName": "Seeded User",
            "accountEnabled": true,
            "createdDateTime": "2026-01-01T00:00:00Z"
        }],
        "groups": [{
            "id": "22222222-2222-2222-2222-222222222222",
            "displayName": "Seeded Group",
            "mailEnabled": false,
            "securityEnabled": true,
            "createdDateTime": "2026-01-01T00:00:00Z"
        }],
        "groupLinks": [{
            "groupId": "22222222-2222-2222-2222-222222222222",
            "members": ["11111111-1111-1111-1111-111111111111"]
        }]
    });

    let path = std::env::temp_dir().join(format!("entra-sim-seed-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec_pretty(&seed).unwrap()).expect("writing the seed");

    let sim = Sim::start_with(|config| config.seed = Some(path.clone())).await;
    let graph = sim.graph().await;

    let users = graph.get_ok("/v1.0/users").await;
    assert_eq!(users["value"][0]["userPrincipalName"], "seeded@sim.test");
    let members = graph
        .get_ok("/v1.0/groups/22222222-2222-2222-2222-222222222222/members")
        .await;
    assert_eq!(
        members["value"][0]["id"],
        "11111111-1111-1111-1111-111111111111"
    );

    // A test suite resets between cases and must land back on the seed, not on an empty tenant.
    graph
        .delete("/v1.0/users/11111111-1111-1111-1111-111111111111")
        .await;
    let emptied = graph.get_ok("/v1.0/users").await;
    assert!(emptied["value"].as_array().unwrap().is_empty());

    sim.post_json("/__sim__/reset", &json!({})).await;
    let restored = graph.get_ok("/v1.0/users").await;
    assert_eq!(restored["value"][0]["userPrincipalName"], "seeded@sim.test");

    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn an_unreadable_seed_is_a_startup_failure_not_an_empty_tenant() {
    let path = std::env::temp_dir().join(format!("entra-sim-bad-{}.json", std::process::id()));
    std::fs::write(&path, b"{ not json").expect("writing the seed");

    // Silently starting with an empty tenant would look like a working simulator whose fixtures
    // had vanished, which is far harder to diagnose than a refusal to start.
    let outcome = Sim::try_start_with(|config| config.seed = Some(path.clone())).await;
    let message = match outcome {
        Ok(_) => panic!("a malformed seed should fail startup"),
        Err(error) => format!("{error:#}"),
    };
    assert!(message.contains("seed"), "got {message}");

    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn the_control_prefix_cannot_collide_with_a_graph_path() {
    let sim = Sim::start().await;
    // The simulator stays a drop-in replacement: a client pointed at it never sees these.
    assert_eq!(sim.get("/__sim__/health").await.status(), 200);
    assert_eq!(sim.get("/v1.0/__sim__/health").await.status(), 404);
}

#[tokio::test]
async fn an_issued_token_is_listed_until_a_reset() {
    let sim = Sim::start().await;
    let before = sim.get_json("/__sim__/tokens").await;
    assert_eq!(before["issued"], json!([]));

    let token = sim.client_credentials_token().await;
    let access_token = token["access_token"].as_str().unwrap();
    let claims = common::decode_claims(access_token);

    let listed = sim.get_json("/__sim__/tokens").await;
    let issued = listed["issued"].as_array().unwrap();
    assert_eq!(issued.len(), 1);
    let entry = &issued[0];
    assert_eq!(entry["kind"], "access");
    assert_eq!(entry["grant"], "client_credentials");
    assert_eq!(entry["clientId"], sim.bootstrap_client_id);
    assert_eq!(entry["subjectKind"], "servicePrincipal");
    assert_eq!(entry["subjectId"], claims["oid"]);
    assert_eq!(entry["audience"], claims["aud"]);
    let roles = claims["roles"].as_array().cloned().unwrap_or_default();
    assert_eq!(entry["roles"], json!(roles));

    // The listed expiry is the token's own, so a reader sees what a client would act on.
    let expires_at = time::OffsetDateTime::parse(
        entry["expiresAt"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(expires_at.unix_timestamp(), claims["exp"].as_i64().unwrap());

    // The log describes tokens; it never hands one out.
    assert!(!listed.to_string().contains(access_token));

    sim.post_json("/__sim__/reset", &json!({})).await;
    let after = sim.get_json("/__sim__/tokens").await;
    assert_eq!(after["issued"], json!([]));
}

#[tokio::test]
async fn federated_credentials_survive_a_snapshot_round_trip() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let application = graph
        .post_created("/v1.0/applications", &json!({ "displayName": "Deployer" }))
        .await;
    let id = application["id"].as_str().unwrap().to_string();
    graph
        .post_created(
            &format!("/v1.0/applications/{id}/federatedIdentityCredentials"),
            &json!({
                "name": "github-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:gosogco/entra-sim:ref:refs/heads/main",
                "audiences": ["api://AzureADTokenExchange"]
            }),
        )
        .await;

    let snapshot = sim.get_json("/__sim__/snapshot").await;
    sim.post_json("/__sim__/reset", &json!({})).await;
    sim.post_json("/__sim__/snapshot", &snapshot).await;

    // A seed or a restored snapshot must not quietly lose the trust a deployment relies on.
    let restored = graph
        .get_ok(&format!(
            "/v1.0/applications/{id}/federatedIdentityCredentials"
        ))
        .await;
    let credentials = restored["value"].as_array().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["name"], "github-main");
    assert_eq!(
        credentials[0]["subject"],
        "repo:gosogco/entra-sim:ref:refs/heads/main"
    );
}
