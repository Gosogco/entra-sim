//! Tests for the claims an app registration asks for: group claims and optional claims.

mod common;

use common::{Graph, Sim, decode_claims};
use serde_json::{Value, json};

const USER_ADMINISTRATOR: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";

/// Bob is in a security group, which is itself in a security group, and in a Microsoft 365
/// group. He also holds the User Administrator directory role.
struct Directory {
    bob: String,
    security: String,
    nested: String,
    unified: String,
    role_object: String,
}

async fn directory(graph: &Graph) -> Directory {
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let security = graph.create_group("Order clerks", &[&bob]).await;
    let nested = graph.create_group("All staff", &[&security]).await;

    let unified = graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": "Team",
                "mailEnabled": true,
                "mailNickname": "team",
                "securityEnabled": false,
                "groupTypes": ["Unified"]
            }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    add_member(graph, &unified, &bob).await;

    let role = graph
        .post_created(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": USER_ADMINISTRATOR }),
        )
        .await;
    let role_object = role["id"].as_str().unwrap().to_string();
    let added = graph
        .post(
            &format!("/v1.0/directoryRoles/{role_object}/members/$ref"),
            &json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{bob}") }),
        )
        .await;
    assert!(added.status().is_success());

    Directory {
        bob,
        security,
        nested,
        unified,
        role_object,
    }
}

async fn add_member(graph: &Graph, group: &str, member: &str) {
    let response = graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{member}") }),
        )
        .await;
    assert_eq!(response.status(), 204);
}

/// Sign bob in to Orders, registered with `orders_extra`, through a client registered with
/// `client_extra`, and return the access token's and the ID token's claims.
async fn tokens(
    sim: &Sim,
    graph: &Graph,
    bob: &str,
    orders_extra: Value,
    client_extra: Value,
) -> (Value, Value, common::Api) {
    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader"],
            &["Orders.Read"],
            orders_extra,
        )
        .await;
    let client = graph
        .register_public_client("Orders website", client_extra)
        .await;
    let body = sim
        .sign_in_ok(&client.app_id, bob, "openid api://orders/Orders.Read")
        .await;
    (
        decode_claims(body["access_token"].as_str().unwrap()),
        decode_claims(body["id_token"].as_str().unwrap()),
        orders,
    )
}

fn sorted(values: &[&str]) -> Value {
    let mut values: Vec<&str> = values.to_vec();
    values.sort();
    json!(values)
}

#[tokio::test]
async fn security_group_gives_security_groups_nested_ones_and_role_objects() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let (access, _, _) = tokens(
        &sim,
        &graph,
        &d.bob,
        json!({ "groupMembershipClaims": "SecurityGroup" }),
        json!({}),
    )
    .await;

    // Microsoft: "Emits security groups and Microsoft Entra roles that the user is a member of",
    // and "Group claims in tokens include nested groups".
    assert_eq!(
        access["groups"],
        sorted(&[&d.security, &d.nested, &d.role_object])
    );
    assert!(access.get("wids").is_none(), "{access}");
}

#[tokio::test]
async fn all_gives_every_group_and_the_role_templates() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let (access, _, _) = tokens(
        &sim,
        &graph,
        &d.bob,
        json!({ "groupMembershipClaims": "All" }),
        json!({}),
    )
    .await;

    assert_eq!(
        access["groups"],
        sorted(&[&d.security, &d.nested, &d.unified, &d.role_object])
    );
    assert_eq!(access["wids"], json!([USER_ADMINISTRATOR]));
}

#[tokio::test]
async fn directory_role_gives_only_wids() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let (access, _, _) = tokens(
        &sim,
        &graph,
        &d.bob,
        json!({ "groupMembershipClaims": "DirectoryRole" }),
        json!({}),
    )
    .await;

    assert!(access.get("groups").is_none(), "{access}");
    assert_eq!(access["wids"], json!([USER_ADMINISTRATOR]));
}

#[tokio::test]
async fn application_group_gives_only_assigned_groups_bob_is_directly_in() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader"],
            &["Orders.Read"],
            json!({ "groupMembershipClaims": "ApplicationGroup" }),
        )
        .await;
    // Both groups are assigned, but bob is only a direct member of the first.
    graph.assign_role(&d.security, &orders, "Reader").await;
    graph.assign_role(&d.nested, &orders, "Reader").await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(&client.app_id, &d.bob, "openid api://orders/Orders.Read")
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    // "With this option, nested groups are not included and the user must be a direct member of
    // the group assigned to the application."
    assert_eq!(access["groups"], json!([d.security]));
}

#[tokio::test]
async fn no_setting_gives_no_group_claims() {
    for setting in [json!({}), json!({ "groupMembershipClaims": "None" })] {
        let sim = Sim::start().await;
        let graph = sim.graph().await;
        let d = directory(&graph).await;
        let (access, id, _) = tokens(&sim, &graph, &d.bob, setting, json!({})).await;
        assert!(access.get("groups").is_none(), "{access}");
        assert!(access.get("wids").is_none(), "{access}");
        assert!(id.get("groups").is_none(), "{id}");
    }
}

#[tokio::test]
async fn the_id_token_follows_the_clients_setting_and_the_access_token_the_apis() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let (access, id, _) = tokens(
        &sim,
        &graph,
        &d.bob,
        json!({}),
        json!({ "groupMembershipClaims": "SecurityGroup" }),
    )
    .await;

    assert!(access.get("groups").is_none(), "{access}");
    assert_eq!(
        id["groups"],
        sorted(&[&d.security, &d.nested, &d.role_object])
    );
}

#[tokio::test]
async fn more_than_200_groups_gives_the_overage_claim() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    for index in 0..201 {
        graph.create_group(&format!("Group {index}"), &[&bob]).await;
    }

    let (access, _, _) = tokens(
        &sim,
        &graph,
        &bob,
        json!({ "groupMembershipClaims": "SecurityGroup" }),
        json!({}),
    )
    .await;

    assert!(access.get("groups").is_none(), "{access}");
    assert_eq!(access["_claim_names"], json!({ "groups": "src1" }));
    assert_eq!(
        access["_claim_sources"]["src1"]["endpoint"],
        format!(
            "https://graph.windows.net/{}/users/{bob}/getMemberObjects",
            sim.tenant_id
        )
        .as_str()
    );
}

#[tokio::test]
async fn emit_as_roles_puts_the_groups_in_roles_instead_of_the_app_roles() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader"],
            &["Orders.Read"],
            json!({
                "groupMembershipClaims": "SecurityGroup",
                "optionalClaims": { "accessToken": [
                    { "name": "groups", "additionalProperties": ["emit_as_roles"] }
                ] }
            }),
        )
        .await;
    graph.assign_role(&d.bob, &orders, "Reader").await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(&client.app_id, &d.bob, "openid api://orders/Orders.Read")
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    // "any configured application roles that the user is assigned to will not appear in the
    // role claim."
    assert_eq!(
        access["roles"],
        sorted(&[&d.security, &d.nested, &d.role_object])
    );
    assert!(access.get("groups").is_none(), "{access}");
}

#[tokio::test]
async fn cloud_displayname_names_assigned_groups() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader"],
            &["Orders.Read"],
            json!({
                "groupMembershipClaims": "ApplicationGroup",
                "optionalClaims": { "accessToken": [
                    { "name": "groups", "additionalProperties": ["cloud_displayname"] }
                ] }
            }),
        )
        .await;
    graph.assign_role(&d.security, &orders, "Reader").await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(&client.app_id, &d.bob, "openid api://orders/Orders.Read")
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(access["groups"], json!(["Order clerks"]));
}

#[tokio::test]
async fn an_on_premises_format_leaves_out_cloud_groups() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let d = directory(&graph).await;

    let (access, _, _) = tokens(
        &sim,
        &graph,
        &d.bob,
        json!({
            "groupMembershipClaims": "SecurityGroup",
            "optionalClaims": { "accessToken": [
                { "name": "groups", "additionalProperties": ["sam_account_name"] }
            ] }
        }),
        json!({}),
    )
    .await;

    // "If the application is configured to get group attributes that are synced from Active
    // Directory and a group doesn't contain those attributes, it won't be included".
    let groups = access["groups"].as_array().cloned().unwrap_or_default();
    for cloud_group in [&d.security, &d.nested] {
        assert!(!groups.contains(&json!(cloud_group)), "{access}");
    }
}

#[tokio::test]
async fn the_id_token_carries_the_users_roles_on_the_client() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;

    // A web app that signs users in and defines its own roles.
    let website = graph
        .register_api(
            "Orders website",
            "api://orders-website",
            &["Manager"],
            &[],
            json!({}),
        )
        .await;
    let added = graph
        .patch(
            &format!("/v1.0/applications/{}", website.object_id),
            &json!({ "publicClient": { "redirectUris": [common::SIGN_IN_REDIRECT] } }),
        )
        .await;
    assert_eq!(added.status(), 204);
    graph.assign_role(&bob, &website, "Manager").await;

    // Microsoft: "for an app that signs in users, the roles claims are included in the ID
    // token."
    let body = sim
        .sign_in_ok(&website.app_id, &bob, "openid User.Read")
        .await;
    let id = decode_claims(body["id_token"].as_str().unwrap());
    assert_eq!(id["roles"], json!(["Manager"]));
    // The access token is for Graph, where bob holds no role.
    let access = decode_claims(body["access_token"].as_str().unwrap());
    assert!(access.get("roles").is_none(), "{access}");
}

/// Carol has a mail address, names and a preferred language; `user_type` is Member or Guest.
async fn carol(graph: &Graph, user_type: &str) -> String {
    graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Carol Example",
                "givenName": "Carol",
                "surname": "Example",
                "mail": "carol@mail.example.test",
                "preferredLanguage": "da-DK",
                "userType": user_type,
                "userPrincipalName": "carol@sim.test",
                "mailNickname": "carol",
                "accountEnabled": true,
                "passwordProfile": { "password": "Sup3rSecret!" }
            }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn optional(names: &[&str]) -> Value {
    json!(
        names
            .iter()
            .map(|name| json!({ "name": name }))
            .collect::<Vec<_>>()
    )
}

#[tokio::test]
async fn a_v2_access_token_carries_the_optional_claims_the_api_asks_for() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let carol = carol(&graph, "Member").await;
    graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({
                "api": { "requestedAccessTokenVersion": 2 },
                "optionalClaims": { "accessToken": [
                    { "name": "email" }, { "name": "given_name" }, { "name": "family_name" },
                    { "name": "upn" }, { "name": "acct" }, { "name": "amr" }, { "name": "xms_pl" },
                    { "name": "idtyp", "additionalProperties": ["include_user_token"] }
                ] }
            }),
        )
        .await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(
            &client.app_id,
            &carol,
            "openid profile api://orders/Orders.Read",
        )
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(access["email"], "carol@mail.example.test");
    assert_eq!(access["given_name"], "Carol");
    assert_eq!(access["family_name"], "Example");
    assert_eq!(access["upn"], "carol@sim.test");
    assert_eq!(access["acct"], 0);
    assert_eq!(access["amr"], json!(["pwd"]));
    assert_eq!(access["xms_pl"], "da-DK");
    assert_eq!(access["idtyp"], "user");
}

#[tokio::test]
async fn name_claims_in_a_v2_token_need_the_profile_scope() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let carol = carol(&graph, "Member").await;
    graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({
                "api": { "requestedAccessTokenVersion": 2 },
                "optionalClaims": { "accessToken": optional(&["email", "given_name", "upn"]) }
            }),
        )
        .await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(&client.app_id, &carol, "openid api://orders/Orders.Read")
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    // Microsoft lists given_name and upn as "Requires the profile scope"; email does not.
    assert!(access.get("given_name").is_none(), "{access}");
    assert!(access.get("upn").is_none(), "{access}");
    assert_eq!(access["email"], "carol@mail.example.test");
}

#[tokio::test]
async fn email_is_left_out_unless_asked_for_or_the_user_is_a_guest() {
    for (user_type, expected) in [("Member", None), ("Guest", Some("carol@mail.example.test"))] {
        let sim = Sim::start().await;
        let graph = sim.graph().await;
        let carol = carol(&graph, user_type).await;
        graph
            .register_api(
                "Orders",
                "api://orders",
                &[],
                &["Orders.Read"],
                json!({ "api": { "requestedAccessTokenVersion": 2 } }),
            )
            .await;
        let client = graph
            .register_public_client("Orders website", json!({}))
            .await;

        let body = sim
            .sign_in_ok(&client.app_id, &carol, "openid api://orders/Orders.Read")
            .await;
        let access = decode_claims(body["access_token"].as_str().unwrap());
        // "Present by default for guest accounts that have an email address."
        assert_eq!(
            access.get("email").and_then(Value::as_str),
            expected,
            "{access}"
        );
    }
}

#[tokio::test]
async fn the_id_token_carries_email_for_the_email_scope_or_the_optional_claim() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let carol = carol(&graph, "Member").await;
    let plain = graph.register_public_client("Plain", json!({})).await;
    let asking = graph
        .register_public_client(
            "Asking",
            json!({ "optionalClaims": { "idToken": optional(&["email"]) } }),
        )
        .await;

    let id = |body: Value| decode_claims(body["id_token"].as_str().unwrap());
    // "On the v2.0 endpoint, your app can also request the email OpenID Connect scope".
    let by_scope = id(sim
        .sign_in_ok(&plain.app_id, &carol, "openid email User.Read")
        .await);
    assert_eq!(by_scope["email"], "carol@mail.example.test");
    let neither = id(sim
        .sign_in_ok(&plain.app_id, &carol, "openid User.Read")
        .await);
    assert!(neither.get("email").is_none(), "{neither}");
    let by_claim = id(sim
        .sign_in_ok(&asking.app_id, &carol, "openid User.Read")
        .await);
    assert_eq!(by_claim["email"], "carol@mail.example.test");
}

#[tokio::test]
async fn a_claim_without_a_value_is_left_out() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let dave = graph.create_user("dave@sim.test", "Dave Example").await;
    graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({
                "api": { "requestedAccessTokenVersion": 2 },
                "optionalClaims": { "accessToken": optional(&["email", "given_name", "xms_pl"]) }
            }),
        )
        .await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(
            &client.app_id,
            &dave,
            "openid profile api://orders/Orders.Read",
        )
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    // "Claims are present only if a value exists to fill it."
    for claim in ["email", "given_name", "xms_pl"] {
        assert!(access.get(claim).is_none(), "{claim}: {access}");
    }
}

#[tokio::test]
async fn v1_optional_claims_preferred_username_and_aud_as_guid() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let carol = carol(&graph, "Member").await;
    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({
                "optionalClaims": { "accessToken": [
                    { "name": "preferred_username" },
                    { "name": "aud", "additionalProperties": ["use_guid"] }
                ] }
            }),
        )
        .await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;

    let body = sim
        .sign_in_ok(&client.app_id, &carol, "openid api://orders/Orders.Read")
        .await;
    let access = decode_claims(body["access_token"].as_str().unwrap());
    assert_eq!(access["ver"], "1.0");
    assert_eq!(access["preferred_username"], "carol@sim.test");
    // use_guid: "Emits the client ID of the resource (API) in GUID format as the aud claim".
    assert_eq!(access["aud"], orders.app_id.as_str());
}
