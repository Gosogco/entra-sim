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
