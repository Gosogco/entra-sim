//! TLS material for the HTTPS listener.
//!
//! The Terraform `azuread` provider hardcodes the `https` scheme when it fetches the cloud
//! metadata document, so the simulator has to terminate TLS itself. By default it mints its own
//! CA and a server certificate for the configured names, and writes the CA out so clients can be
//! pointed at it with `SSL_CERT_FILE`.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tracing::info;

/// A PEM certificate chain and its private key, plus the CA that signed it when we generated one.
pub struct TlsMaterial {
    /// Leaf certificate followed by the issuing CA, in PEM form.
    pub chain_pem: String,
    /// Private key for the leaf certificate, in PEM form.
    pub key_pem: String,
    /// The generated CA certificate, absent when the caller supplied their own chain.
    pub ca_pem: Option<String>,
}

/// Load the configured certificate, or generate a CA and leaf for `sans`.
pub async fn load_or_generate(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    sans: &[String],
) -> Result<TlsMaterial> {
    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        let chain_pem = tokio::fs::read_to_string(cert)
            .await
            .with_context(|| format!("reading TLS certificate {}", cert.display()))?;
        let key_pem = tokio::fs::read_to_string(key)
            .await
            .with_context(|| format!("reading TLS key {}", key.display()))?;
        info!(certificate = %cert.display(), "using supplied TLS certificate");
        return Ok(TlsMaterial {
            chain_pem,
            key_pem,
            ca_pem: None,
        });
    }

    generate(sans)
}

/// Mint a CA and a server certificate covering `sans`.
fn generate(sans: &[String]) -> Result<TlsMaterial> {
    let ca_key = KeyPair::generate().context("generating CA key")?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.distinguished_name = distinguished_name("entra-sim local CA");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("self-signing CA certificate")?;

    let leaf_key = KeyPair::generate().context("generating server key")?;
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = san_types(sans)?;
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.distinguished_name = distinguished_name("entra-sim");

    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .context("signing server certificate")?;

    info!(names = ?sans, "generated self-signed TLS certificate");

    Ok(TlsMaterial {
        chain_pem: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
        key_pem: leaf_key.serialize_pem(),
        ca_pem: Some(ca_cert.pem()),
    })
}

/// Turn configured names into SANs, dropping any `:port` suffix and recognising bare IPs.
///
/// Names arrive from the same kind of value as `metadata_host`, which carries a port, but a port
/// is not valid in a subject alternative name.
fn san_types(sans: &[String]) -> Result<Vec<SanType>> {
    if sans.is_empty() {
        anyhow::bail!("at least one TLS subject alternative name is required");
    }

    sans.iter()
        .map(|san| {
            let host = san.rsplit_once(':').map_or(san.as_str(), |(host, _)| host);
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(SanType::IpAddress(ip));
            }
            let dns = host
                .to_string()
                .try_into()
                .with_context(|| format!("{host:?} is not a usable DNS name"))?;
            Ok(SanType::DnsName(dns))
        })
        .collect()
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "entra-sim");
    dn
}
