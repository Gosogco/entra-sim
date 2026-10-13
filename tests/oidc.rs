//! Tests for OpenID Connect discovery and the published signing key.

mod common;

use common::Sim;

#[tokio::test]
async fn discovery_through_an_alias_names_the_issuer_as_a_template() {
    let sim = Sim::start().await;
    let body = sim
        .get_json("/common/v2.0/.well-known/openid-configuration")
        .await;

    // Microsoft: the tenant-independent document "returns an issuer value
    // https://login.microsoftonline.com/{tenantid}/v2.0", and a client "should replace the
    // {tenantid} value in the issuer metadata with the tenant id" of the token.
    assert_eq!(
        body["issuer"].as_str().unwrap(),
        format!("{}/{{tenantid}}/v2.0", sim.public_base_url)
    );
    assert_eq!(
        body["token_endpoint"].as_str().unwrap(),
        format!("{}/common/oauth2/v2.0/token", sim.public_base_url)
    );

    // A tenant's own document names that tenant.
    let own = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;
    assert_eq!(
        own["issuer"].as_str().unwrap(),
        format!("{}/{}/v2.0", sim.public_base_url, sim.tenant_id)
    );
}

#[tokio::test]
async fn discovery_endpoints_are_absolute_and_tenant_scoped() {
    let sim = Sim::start().await;
    let body = sim
        .get_json(&format!(
            "/{}/v2.0/.well-known/openid-configuration",
            sim.tenant_id
        ))
        .await;

    let base = format!("{}/{}", sim.public_base_url, sim.tenant_id);
    assert_eq!(
        body["token_endpoint"].as_str().unwrap(),
        format!("{base}/oauth2/v2.0/token")
    );
    assert_eq!(
        body["authorization_endpoint"].as_str().unwrap(),
        format!("{base}/oauth2/v2.0/authorize")
    );
    assert_eq!(
        body["jwks_uri"].as_str().unwrap(),
        format!("{base}/discovery/v2.0/keys")
    );
}

#[tokio::test]
async fn jwks_publishes_exactly_one_usable_rsa_key() {
    let sim = Sim::start().await;
    let body = sim
        .get_json(&format!("/{}/discovery/v2.0/keys", sim.tenant_id))
        .await;

    let keys = body["keys"].as_array().expect("keys should be an array");
    assert_eq!(keys.len(), 1, "expected a single signing key");

    let key = &keys[0];
    assert_eq!(key["kty"].as_str().unwrap(), "RSA");
    assert_eq!(key["use"].as_str().unwrap(), "sig");
    assert_eq!(key["alg"].as_str().unwrap(), "RS256");
    assert!(!key["kid"].as_str().unwrap().is_empty());

    // A 2048-bit modulus is 256 bytes, which is 342 base64url characters with no padding.
    let modulus = key["n"].as_str().unwrap();
    assert_eq!(modulus.len(), 342, "expected a 2048-bit modulus");
    assert!(
        !modulus.contains('+') && !modulus.contains('/') && !modulus.contains('='),
        "JWKS values must be base64url with no padding"
    );
    // 65537, big-endian, base64url encoded.
    assert_eq!(key["e"].as_str().unwrap(), "AQAB");
}

#[tokio::test]
async fn jwks_key_is_reachable_from_discovery() {
    let sim = Sim::start().await;
    let discovery = sim
        .get_json("/common/v2.0/.well-known/openid-configuration")
        .await;

    // Follow the advertised jwks_uri the way a client library would, rather than assuming the
    // path, so a mismatch between the document and the routes is caught.
    let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
    let path = jwks_uri
        .strip_prefix(&sim.public_base_url)
        .expect("jwks_uri should sit under the advertised base URL");

    let jwks = sim.get_json(path).await;
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_path_without_v2_serves_the_v1_document() {
    let sim = Sim::start().await;

    // Entra serves its v1.0 document there, which an API validating v1.0 tokens reads.
    let v1 = sim
        .get_json("/common/.well-known/openid-configuration")
        .await;
    assert_eq!(v1["issuer"], "https://sts.windows.net/{tenantid}/");
    let jwks_uri = v1["jwks_uri"].as_str().unwrap();
    assert_eq!(
        jwks_uri,
        format!("{}/common/discovery/keys", sim.public_base_url)
    );
    // The v1.0 protocol endpoints are not implemented, so they are not advertised.
    assert!(v1.get("authorization_endpoint").is_none(), "{v1}");
    assert!(v1.get("token_endpoint").is_none(), "{v1}");

    // Both key paths publish the same key, under `kid` and `x5t` alike.
    let v1_keys = sim
        .get_json(jwks_uri.strip_prefix(&sim.public_base_url).unwrap())
        .await;
    let v2_keys = sim
        .get_json(&format!("/{}/discovery/v2.0/keys", sim.tenant_id))
        .await;
    assert_eq!(v1_keys, v2_keys);
    assert_eq!(v1_keys["keys"][0]["x5t"], v1_keys["keys"][0]["kid"]);
}
