//! The RSA key the simulator signs tokens with, and the JWKS document that publishes it.
//!
//! Tokens have to be real signed JWTs rather than opaque strings: `go-azure-sdk` parses the
//! access token to read its `iat` claim, and client libraries validate `id_token` signatures
//! against the published JWKS.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;

/// RSA 2048 is what Entra uses, and some client libraries reject anything smaller.
const KEY_BITS: usize = 2048;

/// The signing key, in the several representations the handlers need.
pub struct SigningKey {
    /// Key identifier published in JWKS and set in every token header.
    pub kid: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    /// base64url-encoded modulus, for JWKS.
    modulus: String,
    /// base64url-encoded public exponent, for JWKS.
    exponent: String,
}

impl SigningKey {
    /// Generate a fresh key. The `kid` is derived from the modulus, so it is stable for a given
    /// key but changes whenever a new one is generated.
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, KEY_BITS).context("generating an RSA key")?;
        Self::from_private_key(private)
    }

    /// Load a PKCS#8 PEM key, so that `kid` survives a restart and cached client metadata stays
    /// valid.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let private =
            RsaPrivateKey::from_pkcs8_pem(pem).context("parsing the PKCS#8 signing key")?;
        Self::from_private_key(private)
    }

    fn from_private_key(private: RsaPrivateKey) -> Result<Self> {
        let pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .context("encoding the signing key as PKCS#8")?;
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes())
            .context("loading the signing key for signing")?;

        let public = RsaPublicKey::from(&private);
        let modulus = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let decoding = DecodingKey::from_rsa_components(&modulus, &exponent)
            .context("loading the signing key for verification")?;

        Ok(Self {
            // Entra uses an opaque key identifier; deriving it from the modulus keeps it stable
            // for a given key without publishing anything secret.
            kid: kid_for(&modulus),
            encoding,
            decoding,
            modulus,
            exponent,
        })
    }

    /// The JWKS document served at the `jwks_uri` from OIDC discovery.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: self.kid.clone(),
                n: self.modulus.clone(),
                e: self.exponent.clone(),
            }],
        }
    }
}

fn kid_for(modulus: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(modulus.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}
