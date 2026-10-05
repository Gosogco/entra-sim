//! Runtime configuration, from CLI flags or environment variables.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

/// A simulator of the Microsoft Entra ID identity endpoints and the Microsoft Graph API.
#[derive(Debug, Clone, Parser)]
#[command(name = "entra-sim", version, about)]
pub struct Config {
    /// Address to bind both listeners to.
    #[arg(long, env = "ENTRA_SIM_BIND", default_value = "0.0.0.0")]
    pub bind: IpAddr,

    /// Port for the plain HTTP listener.
    #[arg(long, env = "ENTRA_SIM_HTTP_PORT", default_value_t = 8080)]
    pub http_port: u16,

    /// Port for the HTTPS listener. Terraform requires HTTPS for the metadata host.
    #[arg(long, env = "ENTRA_SIM_HTTPS_PORT", default_value_t = 8443)]
    pub https_port: u16,

    /// Disable the HTTPS listener entirely.
    #[arg(long, env = "ENTRA_SIM_NO_TLS")]
    pub no_tls: bool,

    /// Host and port the simulator advertises in the URLs it emits, such as the metadata
    /// document, the OIDC discovery document and token issuer claims. Clients must be able to
    /// reach the simulator at this address.
    #[arg(long, env = "ENTRA_SIM_PUBLIC_HOST", default_value = "localhost:8443")]
    pub public_host: String,

    /// Subject alternative names to put in the generated server certificate. Ports are ignored.
    #[arg(
        long = "tls-san",
        env = "ENTRA_SIM_TLS_SAN",
        value_delimiter = ',',
        default_values_t = [String::from("localhost"), String::from("127.0.0.1")],
    )]
    pub tls_sans: Vec<String>,

    /// Write the generated CA certificate here, so clients can be configured to trust it.
    #[arg(long, env = "ENTRA_SIM_CA_OUT")]
    pub ca_out: Option<PathBuf>,

    /// Use this PEM certificate chain instead of generating one. Requires --tls-key.
    #[arg(long, env = "ENTRA_SIM_TLS_CERT", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// Use this PEM private key instead of generating one. Requires --tls-cert.
    #[arg(long, env = "ENTRA_SIM_TLS_KEY", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// The tenant ID this simulator serves. `common` and `organizations` alias to it.
    #[arg(
        long,
        env = "ENTRA_SIM_TENANT_ID",
        default_value = "00000000-0000-0000-0000-000000000001"
    )]
    pub tenant_id: String,

    /// Sign tokens with this PKCS#8 PEM key instead of generating one, so that the published
    /// key identifier survives a restart.
    #[arg(long, env = "ENTRA_SIM_SIGNING_KEY")]
    pub signing_key: Option<PathBuf>,

    /// Client ID of the application the simulator registers at startup. Without a client that
    /// already exists, nothing could authenticate in order to create one.
    #[arg(
        long,
        env = "ENTRA_SIM_BOOTSTRAP_CLIENT_ID",
        default_value = "11111111-1111-1111-1111-111111111111"
    )]
    pub bootstrap_client_id: String,

    /// Client secret for the bootstrap application.
    #[arg(
        long,
        env = "ENTRA_SIM_BOOTSTRAP_CLIENT_SECRET",
        default_value = "entra-sim-bootstrap-secret"
    )]
    pub bootstrap_client_secret: String,

    /// App roles granted to the bootstrap client, which become the `roles` claim in its tokens.
    /// Defaults to the set the Terraform azuread provider needs to manage a directory.
    #[arg(
        long = "bootstrap-app-role",
        env = "ENTRA_SIM_BOOTSTRAP_APP_ROLES",
        value_delimiter = ',',
        default_values_t = [
            String::from("Application.ReadWrite.All"),
            String::from("AppRoleAssignment.ReadWrite.All"),
            String::from("Directory.ReadWrite.All"),
            String::from("Group.ReadWrite.All"),
            String::from("RoleManagement.ReadWrite.Directory"),
            String::from("User.ReadWrite.All"),
        ],
    )]
    pub bootstrap_app_roles: Vec<String>,

    /// Lifetime of issued access tokens, in seconds.
    #[arg(long, env = "ENTRA_SIM_TOKEN_TTL", default_value_t = 3600)]
    pub token_ttl_seconds: u64,
}

impl Config {
    /// Base URL the simulator advertises, with no trailing slash.
    ///
    /// The absence of a trailing slash matters. `go-azure-sdk` builds the token URL as
    /// `{loginEndpoint}/{tenant}/oauth2/v2.0/token` without normalising it, so a trailing slash
    /// here would put a double slash in every token request the provider makes.
    pub fn public_base_url(&self) -> String {
        format!("https://{}", self.public_host)
    }

    /// Map a tenant segment from a request path onto the single tenant this simulator serves.
    ///
    /// Entra accepts `common`, `organizations` and `consumers` as aliases that resolve to a
    /// concrete tenant at sign-in time, and the issuer it then stamps into tokens always names
    /// the concrete tenant. Anything else is passed through, so that a request for the wrong
    /// tenant is still visible as such to the handler.
    pub fn resolve_tenant(&self, tenant: &str) -> String {
        match tenant {
            "common" | "organizations" | "consumers" => self.tenant_id.clone(),
            other => other.to_string(),
        }
    }
}
