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
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            ),
            ("client_id", &sim.bootstrap_client_id),
        ])
        .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "unsupported_grant_type");
}

#[tokio::test]
async fn graph_can_be_asked_for_by_its_real_name() {
    let sim = Sim::start().await;
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("client_secret", &sim.bootstrap_client_secret),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .await;
    assert_eq!(response.status(), 200);

    // The token is still for the simulator's Graph surface, so Graph accepts it.
    let body: Value = response.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap();
    let claims = claims_validated_against_jwks(&sim, token).await;
    assert_eq!(claims["aud"], sim.public_base_url.as_str());
    let users = sim
        .client
        .get(sim.url("/v1.0/users"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(users.status(), 200);
}

#[tokio::test]
async fn a_scope_for_an_unregistered_api_is_refused() {
    let sim = Sim::start().await;
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &sim.bootstrap_client_id),
            ("client_secret", &sim.bootstrap_client_secret),
            ("scope", "api://nothing-registered/.default"),
        ])
        .await;

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_resource");
    assert_eq!(body["error_codes"][0], 500011);
}

/// Orders defines Reader and Admin; Billing holds Admin on it.
async fn orders_and_billing(sim: &Sim) -> (common::Api, common::Client) {
    let graph = sim.graph().await;
    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader", "Admin"],
            &[],
            serde_json::json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    let billing = graph
        .register_client("Billing job", serde_json::json!({}))
        .await;
    graph
        .assign_role(&billing.principal_id, &orders, "Admin")
        .await;
    (orders, billing)
}

/// Validate a token for a registered API the way that API would: against the published key,
/// with its own appId as the audience.
async fn validated_for_api(sim: &Sim, token: &str, audience: &str) -> Value {
    let discovery = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    let jwks = sim
        .get_json(&format!("/{}/discovery/v2.0/keys", sim.tenant_id))
        .await;
    let key = &jwks["keys"][0];
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[discovery["issuer"].as_str().unwrap()]);
    decode::<Value>(token, &decoding, &validation)
        .expect("the token should validate for the API")
        .claims
}

#[tokio::test]
async fn an_app_gets_a_token_for_a_registered_api_with_its_roles() {
    let sim = Sim::start().await;
    let (orders, billing) = orders_and_billing(&sim).await;

    let response = sim.app_token(&billing, "api://orders/.default").await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let claims =
        validated_for_api(&sim, body["access_token"].as_str().unwrap(), &orders.app_id).await;

    // Microsoft: "In v2.0 tokens, this value is always the client ID of the API."
    assert_eq!(claims["aud"], orders.app_id.as_str());
    assert_eq!(claims["roles"], serde_json::json!(["Admin"]));
    assert_eq!(claims["azp"], billing.app_id.as_str());
    assert_eq!(claims["azpacr"], "1");
    assert_eq!(claims["idtyp"], "app");
    assert_eq!(claims["oid"], billing.principal_id.as_str());
    assert_eq!(claims["ver"], "2.0");
    assert!(claims.get("scp").is_none(), "{claims}");
}

#[tokio::test]
async fn an_api_can_be_named_by_its_app_id() {
    let sim = Sim::start().await;
    let (orders, billing) = orders_and_billing(&sim).await;

    let response = sim
        .app_token(&billing, &format!("{}/.default", orders.app_id))
        .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let claims = common::decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(claims["aud"], orders.app_id.as_str());
}

#[tokio::test]
async fn an_app_without_roles_on_the_api_gets_a_token_without_roles() {
    let sim = Sim::start().await;
    let (_, _) = orders_and_billing(&sim).await;
    let graph = sim.graph().await;
    let other = graph
        .register_client("Other job", serde_json::json!({}))
        .await;

    let response = sim.app_token(&other, "api://orders/.default").await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let claims = common::decode_claims(body["access_token"].as_str().unwrap());
    assert!(claims.get("roles").is_none(), "{claims}");
}

#[tokio::test]
async fn graph_refuses_a_token_for_another_api() {
    let sim = Sim::start().await;
    let (_, billing) = orders_and_billing(&sim).await;

    let body: Value = sim
        .app_token(&billing, "api://orders/.default")
        .await
        .json()
        .await
        .unwrap();
    let response = sim
        .client
        .get(sim.url("/v1.0/users"))
        .bearer_auth(body["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn roles_on_graph_do_not_leak_into_a_token_for_another_api() {
    let sim = Sim::start().await;
    let (orders, _) = orders_and_billing(&sim).await;
    let bootstrap = common::Client {
        object_id: String::new(),
        app_id: sim.bootstrap_client_id.clone(),
        principal_id: String::new(),
        secret: sim.bootstrap_client_secret.clone(),
    };

    // The bootstrap client holds many Graph roles and none on Orders.
    let body: Value = sim
        .app_token(&bootstrap, "api://orders/.default")
        .await
        .json()
        .await
        .unwrap();
    let claims = common::decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(claims["aud"], orders.app_id.as_str());
    assert!(claims.get("roles").is_none(), "{claims}");
}

/// Orders with no token version set, which is the default in Entra and in the azuread provider.
async fn orders_v1_and_billing(
    sim: &Sim,
    extra: serde_json::Value,
) -> (common::Api, common::Client) {
    let graph = sim.graph().await;
    let orders = graph
        .register_api("Orders", "api://orders", &["Admin"], &[], extra)
        .await;
    let billing = graph
        .register_client("Billing job", serde_json::json!({}))
        .await;
    graph
        .assign_role(&billing.principal_id, &orders, "Admin")
        .await;
    (orders, billing)
}

/// Validate a v1.0 token the way an API does: against the v1.0 discovery document's issuer and
/// keys.
async fn validated_as_v1(sim: &Sim, token: &str, audience: &str) -> Value {
    let discovery = sim
        .get_json(&format!(
            "/{}/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    let jwks = sim
        .get_json(
            discovery["jwks_uri"]
                .as_str()
                .unwrap()
                .strip_prefix(&sim.public_base_url)
                .unwrap(),
        )
        .await;
    let header = decode_header(token).unwrap();
    assert_eq!(
        header.x5t, header.kid,
        "a v1.0 token names its key with x5t too"
    );
    let key = &jwks["keys"][0];
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[discovery["issuer"].as_str().unwrap()]);
    decode::<Value>(token, &decoding, &validation)
        .expect("the token should validate against the v1.0 document")
        .claims
}

#[tokio::test]
async fn an_api_without_a_token_version_gets_a_v1_token() {
    let sim = Sim::start().await;
    let (_, billing) = orders_v1_and_billing(&sim, serde_json::json!({})).await;

    let body: Value = sim
        .app_token(&billing, "api://orders/.default")
        .await
        .json()
        .await
        .unwrap();
    // Microsoft: in v1.0 tokens `aud` "can be the client ID or the resource URI used in the
    // request".
    let claims =
        validated_as_v1(&sim, body["access_token"].as_str().unwrap(), "api://orders").await;
    assert_eq!(claims["ver"], "1.0");
    assert_eq!(
        claims["iss"],
        format!("https://sts.windows.net/{}/", sim.tenant_id).as_str()
    );
    assert_eq!(claims["appid"], billing.app_id.as_str());
    assert_eq!(claims["appidacr"], "1");
    assert!(claims.get("azp").is_none(), "{claims}");
    assert_eq!(claims["roles"], serde_json::json!(["Admin"]));
    assert_eq!(claims["idtyp"], "app");
}

#[tokio::test]
async fn token_version_one_gives_a_v1_token_addressed_as_requested() {
    let sim = Sim::start().await;
    let (orders, billing) = orders_v1_and_billing(
        &sim,
        serde_json::json!({ "api": { "requestedAccessTokenVersion": 1 } }),
    )
    .await;

    let body: Value = sim
        .app_token(&billing, &format!("{}/.default", orders.app_id))
        .await
        .json()
        .await
        .unwrap();
    let claims =
        validated_as_v1(&sim, body["access_token"].as_str().unwrap(), &orders.app_id).await;
    assert_eq!(claims["ver"], "1.0");
    assert_eq!(claims["aud"], orders.app_id.as_str());
}

#[tokio::test]
async fn token_version_two_gives_a_v2_token() {
    let sim = Sim::start().await;
    let (orders, billing) = orders_v1_and_billing(
        &sim,
        serde_json::json!({ "api": { "requestedAccessTokenVersion": 2 } }),
    )
    .await;

    let body: Value = sim
        .app_token(&billing, "api://orders/.default")
        .await
        .json()
        .await
        .unwrap();
    let claims =
        validated_for_api(&sim, body["access_token"].as_str().unwrap(), &orders.app_id).await;
    assert_eq!(claims["ver"], "2.0");
    assert!(
        decode_header(body["access_token"].as_str().unwrap())
            .unwrap()
            .x5t
            .is_none()
    );
}
