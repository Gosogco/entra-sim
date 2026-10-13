//! Shared harness: start the simulator in-process on an ephemeral port.
//!
//! Tests exercise the plain HTTP listener. TLS is a transport concern verified separately, and
//! binding it per test would mean minting a certificate for every case.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use clap::Parser;
use entra_sim::auth::keys::SigningKey;
use entra_sim::config::Config;
use entra_sim::log::Log;
use entra_sim::state::AppState;

/// Generating an RSA 2048 key costs real time, so every simulator in a test binary shares one.
static SIGNING_KEY: LazyLock<Arc<SigningKey>> =
    LazyLock::new(|| Arc::new(SigningKey::generate().expect("generating a signing key")));

pub struct Sim {
    pub base_url: String,
    pub public_base_url: String,
    pub tenant_id: String,
    pub bootstrap_client_id: String,
    pub bootstrap_client_secret: String,
    pub client: reqwest::Client,
    pub log: Option<Log>,
    /// Held so the log directory is removed when the test is done with the simulator.
    _log_dir: Option<TempDir>,
}

/// A directory under the system temp directory, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        Self(std::env::temp_dir().join(format!("entra-sim-test-{}", uuid::Uuid::new_v4())))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Sim {
    /// Start a simulator with default configuration.
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a simulator, letting the caller adjust the configuration first.
    pub async fn start_with(adjust: impl FnOnce(&mut Config)) -> Self {
        Self::try_start_with(adjust)
            .await
            .expect("the simulator should start")
    }

    /// Start a simulator that keeps a log in a fresh temporary directory.
    pub async fn start_with_log(adjust: impl FnOnce(&mut Config)) -> Self {
        let dir = TempDir::new();
        let path = dir.0.clone();
        let mut sim = Self::start_with(|config| {
            config.log_dir = Some(path);
            adjust(config);
        })
        .await;
        sim._log_dir = Some(dir);
        sim
    }

    /// Start a simulator, returning the error instead of panicking.
    pub async fn try_start_with(adjust: impl FnOnce(&mut Config)) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("binding an ephemeral port");
        let addr = listener.local_addr().expect("reading the bound address");

        // Parse with no arguments so the clap defaults stay the single source of truth.
        let mut config = Config::parse_from(["entra-sim"]);
        // Advertise the address we actually bound, so emitted URLs are reachable.
        config.public_host = addr.to_string();
        adjust(&mut config);

        let tenant_id = config.tenant_id.clone();
        let public_base_url = config.public_base_url();
        let bootstrap_client_id = config.bootstrap_client_id.clone();
        let bootstrap_client_secret = config.bootstrap_client_secret.clone();
        let log = config.log_dir.as_deref().map(Log::open).transpose()?;
        let state = AppState::with_seed(config, SIGNING_KEY.clone(), log.clone()).await?;
        let app = entra_sim::router(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serving");
        });

        Ok(Self {
            base_url: format!("http://{addr}"),
            public_base_url,
            tenant_id,
            bootstrap_client_id,
            bootstrap_client_secret,
            client: reqwest::Client::new(),
            log,
            _log_dir: None,
        })
    }

    /// A Graph client whose token carries exactly `roles`, for testing enforcement.
    ///
    /// Registers its own application and principal and grants it only the named Graph app
    /// roles, so the token is minted through the same path a real caller's would be.
    pub async fn graph_with_roles(&self, roles: &[&str]) -> Graph {
        let admin = self.graph().await;

        let application = admin
            .post_created(
                "/v1.0/applications",
                &serde_json::json!({ "displayName": "scoped test client" }),
            )
            .await;
        let object_id = application["id"].as_str().unwrap().to_string();
        let client_id = application["appId"].as_str().unwrap().to_string();

        let principal = admin
            .post_created(
                "/v1.0/servicePrincipals",
                &serde_json::json!({ "appId": client_id.clone() }),
            )
            .await;
        let principal_id = principal["id"].as_str().unwrap().to_string();

        let secret = admin
            .post_created_or_ok(
                &format!("/v1.0/applications/{object_id}/addPassword"),
                &serde_json::json!({}),
            )
            .await;
        let client_secret = secret["secretText"].as_str().unwrap().to_string();

        if !roles.is_empty() {
            let graph_principal = admin
                .get_ok(
                    "/v1.0/servicePrincipals?$filter=appId%20eq%20\
                     '00000003-0000-0000-c000-000000000000'",
                )
                .await;
            let resource_id = graph_principal["value"][0]["id"]
                .as_str()
                .unwrap()
                .to_string();
            let published = graph_principal["value"][0]["appRoles"]
                .as_array()
                .unwrap()
                .clone();

            for role in roles {
                let app_role_id = published
                    .iter()
                    .find(|published| published["value"] == *role)
                    .unwrap_or_else(|| panic!("{role} should be a published Graph app role"))["id"]
                    .as_str()
                    .unwrap()
                    .to_string();
                admin
                    .post_created(
                        &format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo"),
                        &serde_json::json!({
                            "principalId": principal_id,
                            "resourceId": resource_id,
                            "appRoleId": app_role_id
                        }),
                    )
                    .await;
            }
        }

        let token = self
            .token_request(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", &format!("{}/.default", self.public_base_url)),
            ])
            .await
            .json::<serde_json::Value>()
            .await
            .expect("decoding the token response")["access_token"]
            .as_str()
            .expect("an access token")
            .to_string();

        Graph {
            base_url: self.base_url.clone(),
            token,
            client: self.client.clone(),
        }
    }

    /// A Graph client presenting `token`, such as a user's.
    pub fn graph_as(&self, token: &str) -> Graph {
        Graph {
            base_url: self.base_url.clone(),
            token: token.to_string(),
            client: self.client.clone(),
        }
    }

    /// An authenticated client holding a bootstrap-client token, for Graph requests.
    pub async fn graph(&self) -> Graph {
        let token = self.client_credentials_token().await["access_token"]
            .as_str()
            .expect("an access token")
            .to_string();
        Graph {
            base_url: self.base_url.clone(),
            token,
            client: self.client.clone(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("sending request")
    }

    /// Request a client-credentials token for the simulator's own Graph resource, the way
    /// go-azure-sdk does.
    pub async fn client_credentials_token(&self) -> serde_json::Value {
        self.token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &self.bootstrap_client_id),
            ("client_secret", &self.bootstrap_client_secret),
            ("scope", &format!("{}/.default", self.public_base_url)),
        ])
        .await
        .json()
        .await
        .expect("decoding the token response")
    }

    /// Post a form to the token endpoint and return the raw response.
    pub async fn token_request(&self, form: &[(&str, &str)]) -> reqwest::Response {
        self.client
            .post(self.url(&format!("/{}/oauth2/v2.0/token", self.tenant_id)))
            .form(form)
            .send()
            .await
            .expect("sending the token request")
    }

    /// POST a body to a control endpoint, asserting success.
    pub async fn post_json(&self, path: &str, body: &serde_json::Value) -> serde_json::Value {
        let response = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .expect("sending request");
        let status = response.status();
        let decoded: serde_json::Value = response.json().await.expect("decoding JSON");
        assert!(
            status.is_success(),
            "POST {path} returned {status}: {decoded}"
        );
        decoded
    }

    pub async fn get_json(&self, path: &str) -> serde_json::Value {
        let response = self.get(path).await;
        assert!(
            response.status().is_success(),
            "GET {path} returned {}",
            response.status()
        );
        response.json().await.expect("decoding JSON")
    }
}

/// A Graph client that presents a bearer token on every request.
pub struct Graph {
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl Graph {
    /// The bearer token this client presents.
    pub fn token(&self) -> &str {
        &self.token
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.request(reqwest::Method::GET, path)
            .send()
            .await
            .expect("sending request")
    }

    /// GET a path, asserting success and returning the decoded body.
    pub async fn get_ok(&self, path: &str) -> serde_json::Value {
        let response = self.get(path).await;
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("decoding JSON");
        assert!(status.is_success(), "GET {path} returned {status}: {body}");
        body
    }

    pub async fn post(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .expect("sending request")
    }

    /// POST a body, asserting a 201 and returning the created object.
    pub async fn post_created(&self, path: &str, body: &serde_json::Value) -> serde_json::Value {
        let response = self.post(path, body).await;
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("decoding JSON");
        assert_eq!(status, 201, "POST {path} returned {status}: {body}");
        body
    }

    /// POST a body, asserting any success status and returning the body. Graph answers some
    /// actions with 200 and some with 201.
    pub async fn post_created_or_ok(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> serde_json::Value {
        let response = self.post(path, body).await;
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("decoding JSON");
        assert!(status.is_success(), "POST {path} returned {status}: {body}");
        body
    }

    pub async fn patch(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.request(reqwest::Method::PATCH, path)
            .json(body)
            .send()
            .await
            .expect("sending request")
    }

    pub async fn delete(&self, path: &str) -> reqwest::Response {
        self.request(reqwest::Method::DELETE, path)
            .send()
            .await
            .expect("sending request")
    }

    /// GET with an `Origin` header, as a browser sends.
    pub async fn get_with_origin(&self, path: &str, origin: &str) -> reqwest::Response {
        self.request(reqwest::Method::GET, path)
            .header("Origin", origin)
            .send()
            .await
            .expect("sending request")
    }

    /// Request without a bearer token, to check that a route is actually protected.
    pub async fn get_anonymous(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("sending request")
    }
}

/// Decode a JWT's claims without verifying it.
///
/// Verification is covered by the token tests; here the claims are the subject of the
/// assertion, so decoding is enough.
pub fn decode_claims(token: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = token
        .split('.')
        .nth(1)
        .expect("a JWT should have three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("the claims should be base64url");
    serde_json::from_slice(&bytes).expect("the claims should be JSON")
}

/// An API registered in the directory, with the IDs of the roles and scopes it defines.
pub struct Api {
    pub object_id: String,
    pub app_id: String,
    pub principal_id: String,
    pub identifier_uri: String,
    /// Role value to role ID.
    pub roles: std::collections::HashMap<String, String>,
    /// Scope value to scope ID.
    pub scopes: std::collections::HashMap<String, String>,
}

/// A client application with a secret and a service principal.
pub struct Client {
    pub object_id: String,
    pub app_id: String,
    pub principal_id: String,
    pub secret: String,
}

impl Graph {
    /// Register an API at `identifier_uri` that defines `roles`, which users and applications
    /// may both hold, and the delegated `scopes`, then create its service principal.
    pub async fn register_api(
        &self,
        display_name: &str,
        identifier_uri: &str,
        roles: &[&str],
        scopes: &[&str],
        extra: serde_json::Value,
    ) -> Api {
        let role_ids: std::collections::HashMap<String, String> = roles
            .iter()
            .map(|role| (role.to_string(), uuid::Uuid::new_v4().to_string()))
            .collect();
        let scope_ids: std::collections::HashMap<String, String> = scopes
            .iter()
            .map(|scope| (scope.to_string(), uuid::Uuid::new_v4().to_string()))
            .collect();

        let mut body = serde_json::json!({
            "displayName": display_name,
            "identifierUris": [identifier_uri],
            "appRoles": role_ids.iter().map(|(value, id)| serde_json::json!({
                "id": id,
                "value": value,
                "displayName": value,
                "description": format!("{value} on {display_name}"),
                "isEnabled": true,
                "allowedMemberTypes": ["User", "Application"]
            })).collect::<Vec<_>>(),
            "api": {
                "oauth2PermissionScopes": scope_ids.iter().map(|(value, id)| serde_json::json!({
                    "id": id,
                    "value": value,
                    "adminConsentDisplayName": value,
                    "adminConsentDescription": format!("{value} on {display_name}"),
                    "isEnabled": true,
                    "type": "User"
                })).collect::<Vec<_>>()
            }
        });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                if key == "api" {
                    let api = body["api"].as_object_mut().unwrap();
                    for (api_key, api_value) in value.as_object().unwrap() {
                        api.insert(api_key.clone(), api_value.clone());
                    }
                } else {
                    body.insert(key.clone(), value.clone());
                }
            }
        }

        let application = self.post_created("/v1.0/applications", &body).await;
        let app_id = application["appId"].as_str().unwrap().to_string();
        let principal = self
            .post_created(
                "/v1.0/servicePrincipals",
                &serde_json::json!({ "appId": app_id }),
            )
            .await;

        Api {
            object_id: application["id"].as_str().unwrap().to_string(),
            app_id,
            principal_id: principal["id"].as_str().unwrap().to_string(),
            identifier_uri: identifier_uri.to_string(),
            roles: role_ids,
            scopes: scope_ids,
        }
    }

    /// Register a confidential client with a secret, `extra` merged into its registration.
    pub async fn register_client(&self, display_name: &str, extra: serde_json::Value) -> Client {
        let mut body = serde_json::json!({ "displayName": display_name });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                body.insert(key.clone(), value.clone());
            }
        }
        let application = self.post_created("/v1.0/applications", &body).await;
        let object_id = application["id"].as_str().unwrap().to_string();
        let app_id = application["appId"].as_str().unwrap().to_string();
        let principal = self
            .post_created(
                "/v1.0/servicePrincipals",
                &serde_json::json!({ "appId": app_id }),
            )
            .await;
        let secret = self
            .post_created_or_ok(
                &format!("/v1.0/applications/{object_id}/addPassword"),
                &serde_json::json!({}),
            )
            .await;

        Client {
            object_id,
            app_id,
            principal_id: principal["id"].as_str().unwrap().to_string(),
            secret: secret["secretText"].as_str().unwrap().to_string(),
        }
    }

    /// Assign `role` on `api` to the user, group or service principal `principal_id`.
    pub async fn assign_role(&self, principal_id: &str, api: &Api, role: &str) {
        self.post_created(
            &format!(
                "/v1.0/servicePrincipals/{}/appRoleAssignedTo",
                api.principal_id
            ),
            &serde_json::json!({
                "principalId": principal_id,
                "resourceId": api.principal_id,
                "appRoleId": api.roles[role]
            }),
        )
        .await;
    }

    /// Create a user, returning its object ID.
    pub async fn create_user(&self, upn: &str, display_name: &str) -> String {
        let user = self
            .post_created(
                "/v1.0/users",
                &serde_json::json!({
                    "displayName": display_name,
                    "userPrincipalName": upn,
                    "mailNickname": upn.split('@').next().unwrap(),
                    "accountEnabled": true,
                    "passwordProfile": { "password": "Sup3rSecret!" }
                }),
            )
            .await;
        user["id"].as_str().unwrap().to_string()
    }

    /// Create a security group with `members`, returning its object ID.
    pub async fn create_group(&self, display_name: &str, members: &[&str]) -> String {
        let group = self
            .post_created(
                "/v1.0/groups",
                &serde_json::json!({
                    "displayName": display_name,
                    "mailEnabled": false,
                    "mailNickname": display_name.replace(' ', "-").to_lowercase(),
                    "securityEnabled": true
                }),
            )
            .await;
        let id = group["id"].as_str().unwrap().to_string();
        for member in members {
            let response = self
                .post(
                    &format!("/v1.0/groups/{id}/members/$ref"),
                    &serde_json::json!({
                        "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{member}")
                    }),
                )
                .await;
            assert_eq!(response.status(), 204, "adding {member} to {display_name}");
        }
        id
    }
}

impl Sim {
    /// Request a client-credentials token for `scope` as `client`, returning the raw response.
    pub async fn app_token(&self, client: &Client, scope: &str) -> reqwest::Response {
        self.token_request(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client.app_id),
            ("client_secret", &client.secret),
            ("scope", scope),
        ])
        .await
    }
}

/// The redirect URI `Sim::sign_in` registers clients with.
pub const SIGN_IN_REDIRECT: &str = "https://app.example.test/signed-in";

impl Sim {
    /// Sign `user_id` in through the public client `client_id` for `scope`, the way a browser
    /// would by choosing the user on the sign-in page, and redeem the code. Returns the raw token
    /// response. The client must have `SIGN_IN_REDIRECT` registered.
    pub async fn sign_in(&self, client_id: &str, user_id: &str, scope: &str) -> reqwest::Response {
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let redirect = browser
            .post(self.url(&format!("/{}/oauth2/v2.0/authorize", self.tenant_id)))
            .form(&[
                ("client_id", client_id),
                ("response_type", "code"),
                ("redirect_uri", SIGN_IN_REDIRECT),
                ("scope", scope),
                ("user_id", user_id),
            ])
            .send()
            .await
            .expect("submitting the sign-in form");
        assert_eq!(redirect.status(), 302, "the sign-in should redirect");
        let location = redirect.headers()["location"].to_str().unwrap().to_string();
        let code = location
            .split_once('?')
            .and_then(|(_, query)| query.split('&').find_map(|pair| pair.strip_prefix("code=")))
            .unwrap_or_else(|| panic!("no code in {location}"))
            .to_string();

        browser
            .post(self.url(&format!("/{}/oauth2/v2.0/token", self.tenant_id)))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code.as_str()),
                ("redirect_uri", SIGN_IN_REDIRECT),
            ])
            .send()
            .await
            .expect("redeeming the code")
    }

    /// `sign_in`, asserting success and returning the decoded token response.
    pub async fn sign_in_ok(
        &self,
        client_id: &str,
        user_id: &str,
        scope: &str,
    ) -> serde_json::Value {
        let response = self.sign_in(client_id, user_id, scope).await;
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(status.is_success(), "the sign-in returned {status}: {body}");
        body
    }
}

impl Graph {
    /// Register a public client that `Sim::sign_in` can sign users in through.
    pub async fn register_public_client(
        &self,
        display_name: &str,
        extra: serde_json::Value,
    ) -> Client {
        let mut body = serde_json::json!({
            "publicClient": { "redirectUris": [SIGN_IN_REDIRECT] }
        });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                body.insert(key.clone(), value.clone());
            }
        }
        self.register_client(display_name, body).await
    }
}

impl Sim {
    /// A Graph client holding a bootstrap token from `tenant`, for working in another tenant.
    pub async fn graph_in(&self, tenant: &str) -> Graph {
        let response = self
            .client
            .post(self.url(&format!("/{tenant}/oauth2/v2.0/token")))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.bootstrap_client_id.as_str()),
                ("client_secret", self.bootstrap_client_secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
            ])
            .send()
            .await
            .expect("requesting a token");
        let body: serde_json::Value = response.json().await.unwrap();
        Graph {
            base_url: self.base_url.clone(),
            token: body["access_token"]
                .as_str()
                .expect("an access token")
                .to_string(),
            client: self.client.clone(),
        }
    }
}
