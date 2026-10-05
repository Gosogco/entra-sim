//! Tests for the cloud metadata document that the Terraform `azuread` provider consumes.

mod common;

use common::Sim;

#[tokio::test]
async fn serves_every_field_the_provider_requires() {
    let sim = Sim::start().await;
    let body = sim
        .get_json("/metadata/endpoints?api-version=2022-09-01")
        .await;

    // `go-azure-sdk` fails to configure the provider when any of these is missing or empty.
    for field in ["name", "resourceManager", "microsoftGraphResourceId"] {
        let value = body[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} should be a string, got {:?}", body[field]));
        assert!(!value.is_empty(), "{field} should not be empty");
    }
    let login_endpoint = body["authentication"]["loginEndpoint"]
        .as_str()
        .expect("loginEndpoint should be a string");
    assert!(!login_endpoint.is_empty());
}

#[tokio::test]
async fn login_endpoint_has_no_trailing_slash() {
    let sim = Sim::start().await;
    let body = sim.get_json("/metadata/endpoints").await;

    // The SDK builds `{loginEndpoint}/{tenant}/oauth2/v2.0/token` by concatenation without
    // normalising, so a trailing slash here corrupts every token request.
    let login_endpoint = body["authentication"]["loginEndpoint"].as_str().unwrap();
    assert!(
        !login_endpoint.ends_with('/'),
        "loginEndpoint {login_endpoint:?} must not end in a slash"
    );
}

#[tokio::test]
async fn graph_resource_id_is_the_advertised_base_url() {
    let sim = Sim::start().await;
    let body = sim.get_json("/metadata/endpoints").await;

    // This value is used as the Graph base URL and as the token resource, so the scope the
    // provider requests becomes `{value}/.default`.
    assert_eq!(
        body["microsoftGraphResourceId"].as_str().unwrap(),
        sim.public_base_url
    );
    assert!(
        !sim.public_base_url.ends_with('/'),
        "the advertised base URL must not end in a slash"
    );
}

#[tokio::test]
async fn tenant_is_common_so_provider_defaults_keep_working() {
    let sim = Sim::start().await;
    let body = sim.get_json("/metadata/endpoints").await;
    assert_eq!(body["authentication"]["tenant"].as_str().unwrap(), "common");
    assert_eq!(
        body["authentication"]["identityProvider"].as_str().unwrap(),
        "AAD"
    );
}
