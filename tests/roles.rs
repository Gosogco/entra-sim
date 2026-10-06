//! Tests for app role assignments, delegated permission grants and directory roles.

mod common;

use common::{Graph, Sim};
use serde_json::json;

const GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";
/// Application.ReadWrite.All, as published by Microsoft.
const APPLICATION_READWRITE_ALL: &str = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9";
/// Global Administrator, as published by Microsoft.
const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";

/// Register an application and its service principal, returning the principal's object ID.
async fn create_principal(graph: &Graph, display_name: &str) -> String {
    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({ "displayName": display_name }),
        )
        .await;
    let app_id = application["appId"].as_str().unwrap().to_string();
    let principal = graph
        .post_created("/v1.0/servicePrincipals", &json!({ "appId": app_id }))
        .await;
    principal["id"].as_str().unwrap().to_string()
}

async fn graph_principal_id(graph: &Graph) -> String {
    let found = graph
        .get_ok(&format!(
            "/v1.0/servicePrincipals?$filter=appId%20eq%20'{GRAPH_APP_ID}'"
        ))
        .await;
    found["value"][0]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn an_assignment_grants_a_role_that_appears_in_the_next_token() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // A new application, its principal, and a secret to authenticate with.
    let application = graph
        .post_created(
            "/v1.0/applications",
            &json!({ "displayName": "Granted App" }),
        )
        .await;
    let app_object_id = application["id"].as_str().unwrap();
    let app_id = application["appId"].as_str().unwrap().to_string();
    let principal = graph
        .post_created(
            "/v1.0/servicePrincipals",
            &json!({ "appId": app_id.clone() }),
        )
        .await;
    let principal_id = principal["id"].as_str().unwrap().to_string();

    let secret = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{app_object_id}/addPassword"),
            &json!({}),
        )
        .await;
    let secret_text = secret["secretText"].as_str().unwrap().to_string();

    let scope = format!("{}/.default", sim.public_base_url);
    let roles_in_token = || async {
        let response = sim
            .token_request(&[
                ("grant_type", "client_credentials"),
                ("client_id", &app_id),
                ("client_secret", &secret_text),
                ("scope", &scope),
            ])
            .await;
        let body: serde_json::Value = response.json().await.unwrap();
        let token = body["access_token"].as_str().expect("an access token");
        let claims = common::decode_claims(token);
        claims["roles"]
            .as_array()
            .map(|roles| {
                roles
                    .iter()
                    .map(|role| role.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    // With no assignment the token carries no roles at all.
    assert!(roles_in_token().await.is_empty());

    let resource_id = graph_principal_id(&graph).await;
    let assignment = graph
        .post_created(
            &format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo"),
            &json!({
                "principalId": principal_id,
                "resourceId": resource_id,
                "appRoleId": APPLICATION_READWRITE_ALL
            }),
        )
        .await;
    assert_eq!(assignment["principalType"], "ServicePrincipal");

    // Granting the role changes what the token endpoint issues next.
    assert_eq!(
        roles_in_token().await,
        vec!["Application.ReadWrite.All".to_string()]
    );

    // And revoking it takes the role away again, so revocation is not cosmetic.
    let assignment_id = assignment["id"].as_str().unwrap();
    assert_eq!(
        graph
            .delete(&format!(
                "/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo/{assignment_id}"
            ))
            .await
            .status(),
        204
    );
    assert!(roles_in_token().await.is_empty());
}

#[tokio::test]
async fn assignments_are_visible_from_both_ends() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let principal_id = create_principal(&graph, "Both Ends").await;
    let resource_id = graph_principal_id(&graph).await;

    graph
        .post_created(
            &format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo"),
            &json!({
                "principalId": principal_id,
                "resourceId": resource_id,
                "appRoleId": APPLICATION_READWRITE_ALL
            }),
        )
        .await;

    // "Who has access to this API?" is asked of the resource.
    let assigned_to = graph
        .get_ok(&format!(
            "/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo"
        ))
        .await;
    assert!(
        assigned_to["value"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assignment| assignment["principalId"] == principal_id.as_str())
    );

    // "What can this identity do?" is asked of the recipient.
    let assignments = graph
        .get_ok(&format!(
            "/v1.0/servicePrincipals/{principal_id}/appRoleAssignments"
        ))
        .await;
    let found = assignments["value"].as_array().unwrap();
    assert_eq!(found.len(), 1, "got {assignments}");
    assert_eq!(found[0]["appRoleId"], APPLICATION_READWRITE_ALL);
}

#[tokio::test]
async fn an_assignment_naming_an_undefined_role_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let principal_id = create_principal(&graph, "Bad Role").await;
    let resource_id = graph_principal_id(&graph).await;

    // Storing this would grant nothing, so it is better refused than silently inert.
    let response = graph
        .post(
            &format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo"),
            &json!({
                "principalId": principal_id,
                "resourceId": resource_id,
                "appRoleId": "99999999-9999-9999-9999-999999999999"
            }),
        )
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not defined"),
        "got {body}"
    );
}

#[tokio::test]
async fn a_duplicate_assignment_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let principal_id = create_principal(&graph, "Duplicate").await;
    let resource_id = graph_principal_id(&graph).await;
    let body = json!({
        "principalId": principal_id,
        "resourceId": resource_id,
        "appRoleId": APPLICATION_READWRITE_ALL
    });
    let path = format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo");

    graph.post_created(&path, &body).await;
    let repeat = graph.post(&path, &body).await;
    assert_eq!(repeat.status(), 400);
}

#[tokio::test]
async fn a_user_can_be_assigned_an_app_role() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let resource_id = create_principal(&graph, "Resource").await;

    // Define a role a user is allowed to hold.
    let applications = graph.get_ok("/v1.0/servicePrincipals").await;
    let resource = applications["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|principal| principal["id"] == resource_id.as_str())
        .unwrap();
    let app_id = resource["appId"].as_str().unwrap();
    let application = graph.get_ok(&format!("/v1.0/applications/{app_id}")).await;
    let app_object_id = application["id"].as_str().unwrap();
    graph
        .patch(
            &format!("/v1.0/applications/{app_object_id}"),
            &json!({
                "appRoles": [{
                    "id": "55555555-5555-5555-5555-555555555555",
                    "value": "Widgets.Read",
                    "displayName": "Read widgets",
                    "description": "Read widgets",
                    "isEnabled": true,
                    "allowedMemberTypes": ["User", "Application"]
                }]
            }),
        )
        .await;

    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Assignee",
                "userPrincipalName": "assignee@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    let assignment = graph
        .post_created(
            &format!("/v1.0/users/{user_id}/appRoleAssignments"),
            &json!({
                "principalId": user_id,
                "resourceId": resource_id,
                "appRoleId": "55555555-5555-5555-5555-555555555555"
            }),
        )
        .await;
    assert_eq!(assignment["principalType"], "User");
    assert_eq!(assignment["principalDisplayName"], "Assignee");
}

#[tokio::test]
async fn a_delegated_permission_grant_can_be_managed() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client_id = create_principal(&graph, "Delegating Client").await;
    let resource_id = graph_principal_id(&graph).await;

    let created = graph
        .post_created(
            "/v1.0/oauth2PermissionGrants",
            &json!({
                "clientId": client_id,
                "consentType": "AllPrincipals",
                "resourceId": resource_id,
                "scope": "User.Read Group.Read.All"
            }),
        )
        .await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["consentType"], "AllPrincipals");
    assert!(created["principalId"].is_null());

    // Only the scope is mutable on an existing grant.
    assert_eq!(
        graph
            .patch(
                &format!("/v1.0/oauth2PermissionGrants/{id}"),
                &json!({ "scope": "User.Read" })
            )
            .await
            .status(),
        204
    );
    let fetched = graph
        .get_ok(&format!("/v1.0/oauth2PermissionGrants/{id}"))
        .await;
    assert_eq!(fetched["scope"], "User.Read");

    let by_principal = graph
        .get_ok(&format!(
            "/v1.0/servicePrincipals/{client_id}/oauth2PermissionGrants"
        ))
        .await;
    assert_eq!(by_principal["value"].as_array().unwrap().len(), 1);

    assert_eq!(
        graph
            .delete(&format!("/v1.0/oauth2PermissionGrants/{id}"))
            .await
            .status(),
        204
    );
}

#[tokio::test]
async fn consent_type_and_principal_must_agree() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client_id = create_principal(&graph, "Client").await;
    let resource_id = graph_principal_id(&graph).await;

    // Tenant-wide consent names no principal.
    let with_principal = graph
        .post(
            "/v1.0/oauth2PermissionGrants",
            &json!({
                "clientId": client_id,
                "consentType": "AllPrincipals",
                "principalId": client_id,
                "resourceId": resource_id,
                "scope": "User.Read"
            }),
        )
        .await;
    assert_eq!(with_principal.status(), 400);

    // Per-user consent requires one.
    let without_principal = graph
        .post(
            "/v1.0/oauth2PermissionGrants",
            &json!({
                "clientId": client_id,
                "consentType": "Principal",
                "resourceId": resource_id,
                "scope": "User.Read"
            }),
        )
        .await;
    assert_eq!(without_principal.status(), 400);
}

#[tokio::test]
async fn role_templates_carry_microsofts_real_identifiers() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let templates = graph.get_ok("/v1.0/directoryRoleTemplates?$top=999").await;
    let found = templates["value"].as_array().unwrap();
    assert!(found.len() > 50, "only {} templates", found.len());

    // azuread_directory_role activates by template ID, so these must be the published values.
    let global_admin = found
        .iter()
        .find(|template| template["id"] == GLOBAL_ADMINISTRATOR)
        .expect("Global Administrator should be published");
    assert_eq!(global_admin["displayName"], "Global Administrator");
    assert!(!global_admin["description"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn a_role_is_inert_until_activated() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // A template that has never been activated is not a directory role.
    let before = graph.get_ok("/v1.0/directoryRoles").await;
    assert!(before["value"].as_array().unwrap().is_empty());

    let activated = graph
        .post_created(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": GLOBAL_ADMINISTRATOR }),
        )
        .await;
    assert_eq!(activated["displayName"], "Global Administrator");
    assert_eq!(activated["roleTemplateId"], GLOBAL_ADMINISTRATOR);
    // Activation mints a new object ID distinct from the template's.
    assert_ne!(activated["id"], GLOBAL_ADMINISTRATOR);

    let after = graph.get_ok("/v1.0/directoryRoles").await;
    assert_eq!(after["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn activating_a_role_twice_is_a_conflict() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let body = json!({ "roleTemplateId": GLOBAL_ADMINISTRATOR });

    graph.post_created("/v1.0/directoryRoles", &body).await;
    // Clients rely on the distinction to tell whether they activated it.
    let repeat = graph.post("/v1.0/directoryRoles", &body).await;
    assert_eq!(repeat.status(), 400);
}

#[tokio::test]
async fn activating_an_unknown_template_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph
        .post(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": "99999999-9999-9999-9999-999999999999" }),
        )
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn a_principal_can_be_made_a_member_of_a_directory_role() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let activated = graph
        .post_created(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": GLOBAL_ADMINISTRATOR }),
        )
        .await;
    let role_id = activated["id"].as_str().unwrap();

    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Admin",
                "userPrincipalName": "admin@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    assert_eq!(
        graph
            .post(
                &format!("/v1.0/directoryRoles/{role_id}/members/$ref"),
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

    let members = graph
        .get_ok(&format!("/v1.0/directoryRoles/{role_id}/members"))
        .await;
    assert_eq!(members["value"][0]["id"], user_id);

    // Graph also addresses an activated role by its template ID.
    let by_template = graph
        .get_ok(&format!("/v1.0/directoryRoles/{GLOBAL_ADMINISTRATOR}"))
        .await;
    assert_eq!(by_template["id"], role_id);

    assert_eq!(
        graph
            .delete(&format!(
                "/v1.0/directoryRoles/{role_id}/members/{user_id}/$ref"
            ))
            .await
            .status(),
        204
    );
}

#[tokio::test]
async fn role_management_reports_membership_as_assignments() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Admin",
                "userPrincipalName": "admin@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let user_id = user["id"].as_str().unwrap().to_string();

    // Assigning through roleManagement activates the role if needed, as Entra does.
    let assignment = graph
        .post_created(
            "/v1.0/roleManagement/directory/roleAssignments",
            &json!({
                "roleDefinitionId": GLOBAL_ADMINISTRATOR,
                "principalId": user_id,
                "directoryScopeId": "/"
            }),
        )
        .await;
    let assignment_id = assignment["id"].as_str().unwrap().to_string();

    let roles = graph.get_ok("/v1.0/directoryRoles").await;
    assert_eq!(roles["value"].as_array().unwrap().len(), 1);

    // The same relationship is visible through the directory role's membership.
    let role_id = roles["value"][0]["id"].as_str().unwrap();
    let members = graph
        .get_ok(&format!("/v1.0/directoryRoles/{role_id}/members"))
        .await;
    assert_eq!(members["value"][0]["id"], user_id);

    let listed = graph
        .get_ok("/v1.0/roleManagement/directory/roleAssignments")
        .await;
    assert_eq!(listed["value"].as_array().unwrap().len(), 1);

    assert_eq!(
        graph
            .delete(&format!(
                "/v1.0/roleManagement/directory/roleAssignments/{assignment_id}"
            ))
            .await
            .status(),
        204
    );
    let after = graph
        .get_ok(&format!("/v1.0/directoryRoles/{role_id}/members"))
        .await;
    assert!(after["value"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn role_definitions_list_every_built_in_role() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let definitions = graph
        .get_ok("/v1.0/roleManagement/directory/roleDefinitions?$top=999")
        .await;
    let found = definitions["value"].as_array().unwrap();
    assert!(found.len() > 50);

    let global_admin = found
        .iter()
        .find(|definition| definition["id"] == GLOBAL_ADMINISTRATOR)
        .expect("Global Administrator should be a role definition");
    assert_eq!(global_admin["isBuiltIn"], true);
}

#[tokio::test]
async fn the_tenant_reports_its_initial_domain() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // The provider's own documented example reads this to build a user principal name.
    let domains = graph.get_ok("/v1.0/domains").await;
    let first = &domains["value"][0];
    assert_eq!(first["isInitial"], true);
    assert_eq!(first["isDefault"], true);
    let name = first["id"].as_str().expect("a domain name");

    let organization = graph.get_ok("/v1.0/organization").await;
    assert_eq!(organization["value"][0]["id"], sim.tenant_id);
    assert_eq!(organization["value"][0]["verifiedDomains"][0]["name"], name);

    // A domain's object ID is the domain name itself.
    let fetched = graph.get_ok(&format!("/v1.0/domains/{name}")).await;
    assert_eq!(fetched["id"], name);
}

#[tokio::test]
async fn a_second_grant_for_the_same_triple_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client_id = create_principal(&graph, "Delegating Client").await;
    let resource_id = graph_principal_id(&graph).await;

    let body = json!({
        "clientId": client_id,
        "consentType": "AllPrincipals",
        "resourceId": resource_id,
        "scope": "User.Read"
    });

    let first = graph
        .post_created("/v1.0/oauth2PermissionGrants", &body)
        .await;
    assert!(first["id"].is_string());

    // Entra holds at most one grant per client, resource and principal. Two would make the
    // effective permissions depend on which grant a reader found first, and a revocation could
    // appear to do nothing because the other grant still stood.
    let second = graph.post("/v1.0/oauth2PermissionGrants", &body).await;
    assert_eq!(second.status(), 400);
    let error: serde_json::Value = second.json().await.unwrap();
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Only one oauth2PermissionGrant"),
        "got {error}"
    );

    // A grant for a different user is a different triple, so it is allowed.
    let user = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Other",
                "userPrincipalName": "other@sim.test",
                "accountEnabled": true
            }),
        )
        .await;
    let per_user = graph
        .post(
            "/v1.0/oauth2PermissionGrants",
            &json!({
                "clientId": client_id,
                "consentType": "Principal",
                "principalId": user["id"],
                "resourceId": resource_id,
                "scope": "User.Read"
            }),
        )
        .await;
    assert_eq!(per_user.status(), 201);
}
