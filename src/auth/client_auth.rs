//! How a confidential client proves its identity at the token endpoint: a secret, or a signed
//! assertion.
//!
//! The assertion rules follow Microsoft's certificate credentials documentation: the JWT is
//! signed with the private key of a certificate registered in the application's
//! `keyCredentials`, names that certificate in its `x5t#S256` (or the older `x5t`) header, and
//! carries `aud` set to the token endpoint, `iss` and `sub` set to the client ID, `jti`, `nbf` and
//! `exp`.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::auth::oauth_error::{self, OAuthFailure};
use crate::store::Directory;
use crate::store::model::KeyCredential;

/// The only `client_assertion_type` Entra accepts.
pub const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// What a client presented to prove its identity.
#[derive(Debug, Clone)]
pub enum Presented {
    Secret(String),
    Assertion(String),
}

/// Verify an assertion signed with one of the client's registered certificates.
///
/// `audiences` are the token endpoint URLs the request may have been sent to.
pub fn verify_certificate_assertion(
    directory: &Directory,
    client_id: &str,
    assertion: &str,
    audiences: &[String],
    now: OffsetDateTime,
) -> Result<(), OAuthFailure> {
    let header = decode_header(assertion).map_err(|error| {
        oauth_error::invalid_client_assertion(&format!("It is not a well-formed JWT: {error}."))
    })?;
    // Microsoft names PS256; RS256 is what most libraries, MSAL among them, have long sent.
    if !matches!(header.alg, Algorithm::PS256 | Algorithm::RS256) {
        return Err(oauth_error::invalid_client_assertion(&format!(
            "The algorithm {:?} is not supported; use PS256 or RS256.",
            header.alg
        )));
    }

    let application = directory
        .application_by_app_id(client_id)
        .ok_or_else(|| oauth_error::unknown_client(client_id))?;
    let certificate = application
        .key_credentials
        .iter()
        .filter(|credential| credential.usage.eq_ignore_ascii_case("Verify"))
        .filter(|credential| credential.start_date_time <= now && now < credential.end_date_time)
        .filter_map(|credential| Some((credential, certificate_der(credential)?)))
        .find(|(_, der)| {
            header.x5t_s256.as_deref() == Some(thumbprint::<Sha256>(der).as_str())
                || header.x5t.as_deref() == Some(thumbprint::<Sha1>(der).as_str())
        })
        .map(|(_, der)| der)
        .ok_or_else(|| {
            oauth_error::invalid_client_assertion(
                "The certificate named by the assertion's x5t#S256 or x5t header is not a \
                 valid certificate registered on the application.",
            )
        })?;

    let key = rsa_key(&certificate).ok_or_else(|| {
        oauth_error::invalid_client_assertion(
            "The registered certificate does not hold an RSA key.",
        )
    })?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(audiences);
    validation.set_issuer(&[client_id]);
    validation.sub = Some(client_id.to_string());
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub", "nbf"]);
    validation.validate_nbf = true;
    let claims = decode::<Value>(assertion, &key, &validation)
        .map_err(|error| assertion_failure(&error))?
        .claims;
    if claims.get("jti").and_then(Value::as_str).is_none() {
        return Err(oauth_error::invalid_jwt("The assertion has no jti claim."));
    }
    Ok(())
}

/// Sort a validation failure into Microsoft's two codes: a bad signature is AADSTS700027, "Client
/// assertion failed signature validation", and the rest is AADSTS50027, "InvalidJwtToken",
/// whose listed reasons include "unexpected audience" and "not within its valid time range".
fn assertion_failure(error: &jsonwebtoken::errors::Error) -> OAuthFailure {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::InvalidSignature => {
            oauth_error::invalid_client_assertion("Its signature does not match the certificate.")
        }
        _ => oauth_error::invalid_jwt(&format!("The assertion is not valid: {error}.")),
    }
}

/// The DER bytes of a stored certificate. Graph stores the key as base64 DER; a client may also
/// have sent a base64-encoded PEM.
fn certificate_der(credential: &KeyCredential) -> Option<Vec<u8>> {
    let raw = STANDARD.decode(credential.key.as_deref()?.trim()).ok()?;
    let der = match std::str::from_utf8(&raw) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            let body: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            STANDARD.decode(body.trim()).ok()?
        }
        _ => raw,
    };
    Certificate::from_der(&der).ok()?;
    Some(der)
}

fn thumbprint<D: Digest>(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(D::digest(der))
}

fn rsa_key(der: &[u8]) -> Option<DecodingKey> {
    let certificate = Certificate::from_der(der).ok()?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    let key = RsaPublicKey::from_public_key_der(&spki).ok()?;
    DecodingKey::from_rsa_components(
        &URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        &URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    )
    .ok()
}

/// The unverified claims of a JWT, for deciding how to verify it.
pub fn peek_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// A federated identity credential matching an assertion, and what checking it needs.
pub struct FederatedMatch {
    /// The audiences the credential accepts.
    pub audiences: Vec<String>,
}

/// Find the client's federated identity credential for an assertion's `iss`, `sub` and `aud`.
///
/// Microsoft: "The Federated Identity Credential issuer, subject, and audience values must
/// case-sensitively match the corresponding issuer, subject and audience values contained in the
/// token". A mismatch gives AADSTS70021, "No matching federated identity record found for
/// presented assertion."
pub fn matching_federated_credential(
    directory: &Directory,
    client_id: &str,
    claims: &Value,
) -> Result<FederatedMatch, OAuthFailure> {
    let application = directory
        .application_by_app_id(client_id)
        .ok_or_else(|| oauth_error::unknown_client(client_id))?;
    let issuer = claims["iss"].as_str().unwrap_or_default();
    let subject = claims["sub"].as_str().unwrap_or_default();
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(single) => vec![single.as_str()],
        Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    application
        .federated_identity_credentials
        .iter()
        .find(|credential| {
            credential.issuer == issuer
                && credential.subject == subject
                && credential
                    .audiences
                    .iter()
                    .any(|accepted| audiences.contains(&accepted.as_str()))
        })
        .map(|credential| FederatedMatch {
            audiences: credential.audiences.clone(),
        })
        .ok_or_else(oauth_error::no_matching_federated_credential)
}

/// Check an external issuer's signature on a federated assertion, fetching the issuer's keys
/// from its OpenID Connect discovery document the way Entra does.
///
/// Microsoft: "Only issuers that provide tokens signed using the RS256 algorithm are supported".
pub async fn verify_external_signature(
    http: &reqwest::Client,
    assertion: &str,
    issuer: &str,
    audiences: &[String],
) -> Result<(), OAuthFailure> {
    let header = decode_header(assertion).map_err(|error| {
        oauth_error::invalid_jwt(&format!("It is not a well-formed JWT: {error}."))
    })?;
    if header.alg != Algorithm::RS256 {
        return Err(oauth_error::invalid_jwt(
            "Federated identity credentials accept tokens signed with RS256 only.",
        ));
    }

    // Microsoft's reference lists "External ID token from issuer failed signature verification"
    // under AADSTS50027; it names no code for an issuer whose keys cannot be fetched, so that
    // uses the same one.
    let unreachable = |what: &str| {
        oauth_error::invalid_jwt(&format!(
            "The signing keys of the issuer {issuer} could not be read: {what}."
        ))
    };
    let discovery: Value = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| unreachable(&error.to_string()))?
        .json()
        .await
        .map_err(|error| unreachable(&error.to_string()))?;
    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .ok_or_else(|| unreachable("the discovery document has no jwks_uri"))?;
    let jwks: jsonwebtoken::jwk::JwkSet = http
        .get(jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| unreachable(&error.to_string()))?
        .json()
        .await
        .map_err(|error| unreachable(&error.to_string()))?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None => jwks.keys.first(),
    }
    .ok_or_else(|| unreachable("no published key matches the token's kid"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|error| unreachable(&error.to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(audiences);
    validation.set_issuer(&[issuer]);
    validation.validate_nbf = true;
    decode::<Value>(assertion, &key, &validation)
        .map(|_| ())
        .map_err(|error| {
            oauth_error::invalid_jwt(&format!(
                "External ID token from issuer failed verification: {error}."
            ))
        })
}

/// The HTTP client used to fetch external issuers' keys, shared so connections are reused.
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("building the HTTP client")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprints_are_base64url_without_padding() {
        let print = thumbprint::<Sha256>(b"certificate");
        assert_eq!(print.len(), 43);
        assert!(!print.contains('=') && !print.contains('+') && !print.contains('/'));
    }
}
