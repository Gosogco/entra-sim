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
}
