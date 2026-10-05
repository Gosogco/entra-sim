//! Tests for /applications, /servicePrincipals and the credential actions.
//!
//! The decisive test here is `a_secret_created_through_graph_authenticates_at_the_token_endpoint`:
//! that round trip is what makes "deploy an app registration with Terraform, then authenticate
//! as it" work, which is the simulator's main purpose.

mod common;

use common::{Graph, Sim};
use serde_json::json;

async fn create_application(graph: &Graph, display_name: &str) -> serde_json::Value {
    graph
        .post_created(
            "/v1.0/applications",
            &json!({ "displayName": display_name }),
        )
        .await
}

#[tokio::test]
async fn a_created_application_gets_both_identifiers() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = create_application(&graph, "My App").await;
    let id = created["id"].as_str().expect("an object ID");
    let app_id = created["appId"].as_str().expect("a client ID");
    assert_ne!(id, app_id, "the object ID and client ID are distinct");
    assert_eq!(created["displayName"], "My App");
    assert_eq!(created["signInAudience"], "AzureADMyOrg");

    // Graph lets an application be addressed by either identifier.
    assert_eq!(
        graph.get_ok(&format!("/v1.0/applications/{id}")).await["appId"],
        app_id
    );
    assert_eq!(
        graph.get_ok(&format!("/v1.0/applications/{app_id}")).await["id"],
        id
    );
}

#[tokio::test]
async fn the_client_identifiers_are_read_only() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_application(&graph, "My App").await;
    let id = created["id"].as_str().unwrap();

    // Entra assigns these; letting a client choose them would let it impersonate another app.
    for property in ["id", "appId"] {
        let response = graph
            .patch(
                &format!("/v1.0/applications/{id}"),
                &json!({ property: "11111111-1111-1111-1111-111111111111" }),
            )
            .await;
        assert_eq!(response.status(), 400, "{property} should be read-only");
    }
}

#[tokio::test]
async fn a_secret_created_through_graph_authenticates_at_the_token_endpoint() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // Register an application and give it a service principal, as Terraform does.
    let application = create_application(&graph, "Deployed App").await;
    let id = application["id"].as_str().unwrap();
    let app_id = application["appId"].as_str().unwrap().to_string();
    graph
        .post_created("/v1.0/servicePrincipals", &json!({ "appId": app_id }))
        .await;

    let secret = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{id}/addPassword"),
            &json!({ "passwordCredential": { "displayName": "deploy" } }),
        )
        .await;
    let secret_text = secret["secretText"]
        .as_str()
        .expect("addPassword should disclose secretText");

    // The whole point: the new credential works for authentication straight away.
    let response = sim
        .token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &app_id),
            ("client_secret", secret_text),
            ("scope", &format!("{}/.default", sim.public_base_url)),
        ])
        .await;
    assert!(
        response.status().is_success(),
        "a secret created through Graph should authenticate, got {}",
        response.status()
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn the_secret_is_disclosed_once_and_never_read_back() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "My App").await;
    let id = application["id"].as_str().unwrap();

    let created = graph
        .post_created_or_ok(&format!("/v1.0/applications/{id}/addPassword"), &json!({}))
        .await;
    let secret_text = created["secretText"].as_str().unwrap().to_string();
    assert_eq!(
        created["hint"].as_str().unwrap(),
        &secret_text[..3],
        "the hint should be the first three characters, as in Graph"
    );

    // Graph discloses secretText only in the addPassword response.
    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    assert!(
        !fetched.to_string().contains(&secret_text),
        "the secret leaked on read: {fetched}"
    );
    let credential = &fetched["passwordCredentials"][0];
    assert!(credential["keyId"].is_string());
    assert!(credential["secretText"].is_null());
    assert_eq!(credential["hint"].as_str().unwrap(), &secret_text[..3]);
}

#[tokio::test]
async fn a_removed_secret_stops_authenticating() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "My App").await;
    let id = application["id"].as_str().unwrap();
    let app_id = application["appId"].as_str().unwrap().to_string();
    graph
        .post_created("/v1.0/servicePrincipals", &json!({ "appId": app_id }))
        .await;

    let secret = graph
        .post_created_or_ok(&format!("/v1.0/applications/{id}/addPassword"), &json!({}))
        .await;
    let secret_text = secret["secretText"].as_str().unwrap().to_string();
    let key_id = secret["keyId"].as_str().unwrap().to_string();

    let scope = format!("{}/.default", sim.public_base_url);
    let acquire = || async {
        sim.token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &app_id),
            ("client_secret", &secret_text),
            ("scope", &scope),
        ])
        .await
        .status()
    };
    assert!(acquire().await.is_success());

    let removed = graph
        .post(
            &format!("/v1.0/applications/{id}/removePassword"),
            &json!({ "keyId": key_id }),
        )
        .await;
    assert_eq!(removed.status(), 204);

    // A revoked credential must stop working, or revocation is cosmetic.
    assert_eq!(acquire().await, 401);
}

#[tokio::test]
async fn removing_an_unknown_secret_is_not_found() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "My App").await;
    let id = application["id"].as_str().unwrap();

    let response = graph
        .post(
            &format!("/v1.0/applications/{id}/removePassword"),
            &json!({ "keyId": "99999999-9999-9999-9999-999999999999" }),
        )
        .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn a_certificate_credential_can_be_added_and_removed() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "My App").await;
    let id = application["id"].as_str().unwrap();

    let added = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{id}/addKey"),
            &json!({
                "keyCredential": {
                    "displayName": "signing cert",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": "MIIB-not-a-real-certificate"
                }
            }),
        )
        .await;
    let key_id = added["keyId"]
        .as_str()
        .expect("a generated key ID")
        .to_string();

    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    assert_eq!(fetched["keyCredentials"][0]["usage"], "Verify");

    assert_eq!(
        graph
            .post(
                &format!("/v1.0/applications/{id}/removeKey"),
                &json!({ "keyId": key_id })
            )
            .await
            .status(),
        204
    );
    let after = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    assert!(
        after["keyCredentials"].is_null() || after["keyCredentials"].as_array().unwrap().is_empty()
    );
}

#[tokio::test]
async fn required_resource_access_round_trips_with_real_graph_identifiers() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // These exact identifiers appear in real Terraform configurations.
    let created = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Permissioned App",
                "requiredResourceAccess": [{
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": [
                        { "id": "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", "type": "Role" },
                        { "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope" }
                    ]
                }]
            }),
        )
        .await;

    let id = created["id"].as_str().unwrap();
    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    let access = &fetched["requiredResourceAccess"][0];
    assert_eq!(
        access["resourceAppId"],
        "00000003-0000-0000-c000-000000000000"
    );
    assert_eq!(
        access["resourceAccess"][0]["id"],
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
    );
    assert_eq!(access["resourceAccess"][1]["type"], "Scope");
}

#[tokio::test]
async fn microsoft_graph_is_registered_with_its_real_permissions() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // `data "azuread_service_principal"` on Graph is a fixture of almost every azuread
    // configuration, and it looks the principal up by this well-known appId.
    let found = graph
        .get_ok(
            "/v1.0/servicePrincipals?$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'",
        )
        .await;
    let principals = found["value"].as_array().unwrap();
    assert_eq!(principals.len(), 1, "got {found}");

    let principal = &principals[0];
    assert_eq!(principal["displayName"], "Microsoft Graph");

    let roles = principal["appRoles"].as_array().expect("appRoles");
    assert!(roles.len() > 500, "only {} app roles", roles.len());

    // The identifier Terraform names for this permission is the real one.
    let app_readwrite = roles
        .iter()
        .find(|role| role["value"] == "Application.ReadWrite.All")
        .expect("Application.ReadWrite.All should be published");
    assert_eq!(app_readwrite["id"], "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9");

    let scopes = principal["oauth2PermissionScopes"]
        .as_array()
        .expect("oauth2PermissionScopes");
    let user_read = scopes
        .iter()
        .find(|scope| scope["value"] == "User.Read")
        .expect("User.Read should be published");
    assert_eq!(user_read["id"], "e1fe6dd8-ba31-4d61-89e7-88639da4683d");
}

#[tokio::test]
async fn a_service_principal_requires_a_known_application() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph
        .post(
            "/v1.0/servicePrincipals",
            &json!({ "appId": "99999999-9999-9999-9999-999999999999" }),
        )
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not refer to an application"),
        "got {body}"
    );
}

#[tokio::test]
async fn a_second_service_principal_for_one_application_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "My App").await;
    let app_id = application["appId"].as_str().unwrap().to_string();

    graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": app_id.clone() }),
        )
        .await;
    let response = graph
        .post("/v1.0/servicePrincipals", &json!({ "appId": app_id }))
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_service_principal_inherits_the_applications_permissions() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Resource App",
                "appRoles": [{
                    "id": "22222222-2222-2222-2222-222222222222",
                    "value": "Widgets.Read",
                    "displayName": "Read widgets",
                    "description": "Read access to widgets",
                    "isEnabled": true,
                    "allowedMemberTypes": ["Application"]
                }]
            }),
        )
        .await;
    let app_id = application["appId"].as_str().unwrap().to_string();

    // Roles are defined on the registration but assigned against the principal, so the
    // principal has to carry them.
    let principal = graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": app_id.clone() }),
        )
        .await;
    assert_eq!(principal["appRoles"][0]["value"], "Widgets.Read");
    assert!(
        principal["servicePrincipalNames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == &app_id),
        "the appId should be a service principal name"
    );
}

#[tokio::test]
async fn a_role_added_to_the_application_reaches_the_principal() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "Resource App").await;
    let id = application["id"].as_str().unwrap();
    let app_id = application["appId"].as_str().unwrap().to_string();
    graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": app_id.clone() }),
        )
        .await;

    // An assignment made after the role was defined still has to resolve, so the principal's
    // copy must be kept in step.
    graph
        .patch(
            &format!("/v1.0/applications/{id}"),
            &json!({
                "appRoles": [{
                    "id": "33333333-3333-3333-3333-333333333333",
                    "value": "Widgets.Write",
                    "displayName": "Write widgets",
                    "description": "Write access to widgets",
                    "isEnabled": true,
                    "allowedMemberTypes": ["Application"]
                }]
            }),
        )
        .await;

    let principal = graph
        .get_ok(&format!("/v1.0/servicePrincipals/{app_id}"))
        .await;
    assert_eq!(principal["appRoles"][0]["value"], "Widgets.Write");
}

#[tokio::test]
async fn delegated_permissions_are_read_from_the_api_block() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Scoped App",
                "api": {
                    "requestedAccessTokenVersion": 2,
                    "oauth2PermissionScopes": [{
                        "id": "44444444-4444-4444-4444-444444444444",
                        "value": "Widgets.Read",
                        "adminConsentDisplayName": "Read widgets",
                        "adminConsentDescription": "Read widgets on behalf of the user",
                        "isEnabled": true,
                        "type": "User"
                    }]
                }
            }),
        )
        .await;
    let id = application["id"].as_str().unwrap();

    // The whole api block round-trips, including properties the simulator has no opinion about.
    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    assert_eq!(fetched["api"]["requestedAccessTokenVersion"], 2);
    assert_eq!(
        fetched["api"]["oauth2PermissionScopes"][0]["value"],
        "Widgets.Read"
    );

    let app_id = application["appId"].as_str().unwrap().to_string();
    let principal = graph
        .post_created("/v1.0/servicePrincipals", &json!({ "appId": app_id }))
        .await;
    assert_eq!(
        principal["oauth2PermissionScopes"][0]["value"],
        "Widgets.Read"
    );
}

#[tokio::test]
async fn a_new_application_is_owned_by_its_creator() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_application(&graph, "Owned App").await;
    let id = created["id"].as_str().unwrap();

    // Entra makes the creating identity the initial owner. Clients depend on it: the azuread
    // provider removes that owner when the configuration declares none, and the removal fails
    // if there was never an owner to remove.
    let owners = graph
        .get_ok(&format!("/v1.0/applications/{id}/owners"))
        .await;
    let found = owners["value"].as_array().unwrap();
    assert_eq!(found.len(), 1, "got {owners}");
    assert_eq!(found[0]["@odata.type"], "#microsoft.graph.servicePrincipal");

    // And it can then be removed, which is exactly what the provider does.
    let owner_id = found[0]["id"].as_str().unwrap();
    assert_eq!(
        graph
            .delete(&format!("/v1.0/applications/{id}/owners/{owner_id}/$ref"))
            .await
            .status(),
        204
    );
    let after = graph
        .get_ok(&format!("/v1.0/applications/{id}/owners"))
        .await;
    assert!(after["value"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn an_application_owner_can_be_added_and_removed() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_application(&graph, "Owned App").await;
    let id = created["id"].as_str().unwrap();

    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Owner",
                "userPrincipalName": "owner@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    assert_eq!(
        graph
            .post(
                &format!("/v1.0/applications/{id}/owners/$ref"),
                &json!({
                    "@odata.id": format!(
                        "https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
                    )
                })
            )
            .await
            .status(),
        204
    );

    // Alongside the creator, who was made the initial owner.
    let owners = graph
        .get_ok(&format!("/v1.0/applications/{id}/owners"))
        .await;
    let ids: Vec<&str> = owners["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|owner| owner["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&user_id.as_str()), "got {ids:?}");
    assert_eq!(ids.len(), 2);

    assert_eq!(
        graph
            .delete(&format!("/v1.0/applications/{id}/owners/{user_id}/$ref"))
            .await
            .status(),
        204
    );
    let after = graph
        .get_ok(&format!("/v1.0/applications/{id}/owners"))
        .await;
    let remaining: Vec<&str> = after["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|owner| owner["id"].as_str().unwrap())
        .collect();
    assert!(!remaining.contains(&user_id.as_str()));
}

#[tokio::test]
async fn owners_can_be_bound_when_the_application_is_created() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Owner",
                "userPrincipalName": "binder@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    // Declaring an owner replaces the creator default rather than adding to it.
    let created = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Bound Owner",
                "owners@odata.bind": [
                    format!("https://graph.microsoft.com/v1.0/directoryObjects/{user_id}")
                ]
            }),
        )
        .await;
    let id = created["id"].as_str().unwrap();

    // The binding directive must not come back as a property of the application.
    assert!(
        created["owners@odata.bind"].is_null(),
        "the write-only directive leaked into the response: {created}"
    );

    let owners = graph
        .get_ok(&format!("/v1.0/applications/{id}/owners"))
        .await;
    let found = owners["value"].as_array().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["id"], user_id);
}

#[tokio::test]
async fn an_explicit_null_is_echoed_rather_than_dropped() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // The azuread provider writes null for properties the configuration leaves unset and then
    // compares what it reads back. Dropping the property changes the shape it sees, which shows
    // up as a permanent diff on every plan.
    let created = graph
        .post_created(
            "/v1.0/applications",
            &json!({ "displayName": "Nulls", "groupMembershipClaims": null }),
        )
        .await;
    let id = created["id"].as_str().unwrap();

    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    let fields = fetched.as_object().unwrap();
    assert!(
        fields.contains_key("groupMembershipClaims"),
        "the property should be present and null, got {fetched}"
    );
    assert!(fields["groupMembershipClaims"].is_null());
}

#[tokio::test]
async fn a_federated_identity_credential_can_be_managed() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let application = create_application(&graph, "Federated App").await;
    let id = application["id"].as_str().unwrap();
    let path = format!("/v1.0/applications/{id}/federatedIdentityCredentials");

    let created = graph
        .post_created(
            &path,
            &json!({
                "name": "github-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:Gosogco/entra-sim:ref:refs/heads/main"
            }),
        )
        .await;
    assert_eq!(created["name"], "github-main");
    // Entra defaults the audience when none is given.
    assert_eq!(created["audiences"][0], "api://AzureADTokenExchange");

    let listed = graph.get_ok(&path).await;
    assert_eq!(listed["value"].as_array().unwrap().len(), 1);

    // Graph addresses one by either its ID or its name.
    let by_name = graph.get_ok(&format!("{path}/github-main")).await;
    assert_eq!(
        by_name["subject"],
        "repo:Gosogco/entra-sim:ref:refs/heads/main"
    );

    let duplicate = graph
        .post(
            &path,
            &json!({
                "name": "github-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:Gosogco/entra-sim:ref:refs/heads/other"
            }),
        )
        .await;
    assert_eq!(
        duplicate.status(),
        400,
        "a duplicate name should be refused"
    );

    assert_eq!(
        graph.delete(&format!("{path}/github-main")).await.status(),
        204
    );
    let after = graph.get_ok(&path).await;
    assert!(after["value"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn applications_are_filterable_by_display_name_and_app_id() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_application(&graph, "Findable").await;
    let app_id = created["appId"].as_str().unwrap();

    let by_name = graph
        .get_ok("/v1.0/applications?$filter=displayName%20eq%20'Findable'")
        .await;
    assert_eq!(by_name["value"].as_array().unwrap().len(), 1);

    let by_app_id = graph
        .get_ok(&format!(
            "/v1.0/applications?$filter=appId%20eq%20'{app_id}'"
        ))
        .await;
    assert_eq!(by_app_id["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn unrecognised_application_properties_round_trip() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // The azuread provider writes web, spa and publicClient blocks among others; dropping any
    // of them would show up as a permanent Terraform diff.
    let created = graph
        .post_created(
            "/v1.0/applications",
            &json!({
                "displayName": "Web App",
                "web": {
                    "redirectUris": ["https://app.example.com/callback"],
                    "implicitGrantSettings": { "enableIdTokenIssuance": true }
                },
                "spa": { "redirectUris": ["https://spa.example.com"] },
                "publicClient": { "redirectUris": ["http://localhost:8400"] },
                "tags": ["managed-by-terraform"]
            }),
        )
        .await;
    let id = created["id"].as_str().unwrap();

    let fetched = graph.get_ok(&format!("/v1.0/applications/{id}")).await;
    assert_eq!(
        fetched["web"]["redirectUris"][0],
        "https://app.example.com/callback"
    );
    assert_eq!(
        fetched["web"]["implicitGrantSettings"]["enableIdTokenIssuance"],
        true
    );
    assert_eq!(fetched["spa"]["redirectUris"][0], "https://spa.example.com");
    assert_eq!(
        fetched["publicClient"]["redirectUris"][0],
        "http://localhost:8400"
    );
    assert_eq!(fetched["tags"][0], "managed-by-terraform");
}

#[tokio::test]
async fn an_application_can_be_deleted() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_application(&graph, "Temporary").await;
    let id = created["id"].as_str().unwrap();

    assert_eq!(
        graph
            .delete(&format!("/v1.0/applications/{id}"))
            .await
            .status(),
        204
    );
    assert_eq!(
        graph
            .get(&format!("/v1.0/applications/{id}"))
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn microsoft_graph_has_no_application_registration() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // In a real tenant Microsoft Graph is a first-party application owned by Microsoft, so only
    // the local service principal exists and GET /applications never returns it.
    let applications = graph.get_ok("/v1.0/applications").await;
    let names: Vec<&str> = applications["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|application| application["displayName"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !names.contains(&"Microsoft Graph"),
        "Microsoft Graph should not appear as an application: {names:?}"
    );

    let by_app_id = graph
        .get_ok("/v1.0/applications?$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'")
        .await;
    assert!(by_app_id["value"].as_array().unwrap().is_empty());
}
