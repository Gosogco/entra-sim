//! Proof Key for Code Exchange.
//!
//! The code challenge binds an authorization code to the client instance that requested it, so
//! a code intercepted on the redirect cannot be exchanged by anyone else.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Whether `verifier` satisfies the challenge recorded when the code was issued.
///
/// A missing challenge means the client did not use PKCE. That is refused when a verifier is
/// presented anyway, and permitted otherwise: requiring PKCE of every client would reject
/// confidential clients that legitimately do not use it.
pub fn verify(
    challenge: Option<&str>,
    method: Option<&str>,
    verifier: Option<&str>,
) -> Result<(), &'static str> {
    match (challenge, verifier) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err("a code_verifier was presented but no code_challenge was recorded"),
        (Some(_), None) => Err("the authorization request used PKCE, so code_verifier is required"),
        (Some(challenge), Some(verifier)) => {
            if !is_well_formed(verifier) {
                return Err("the code_verifier must be 43 to 128 unreserved characters");
            }
            // `plain` is the default when the authorization request omits the method.
            let computed = match method.unwrap_or("plain") {
                "S256" => URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                "plain" => verifier.to_string(),
                _ => return Err("the code_challenge_method must be S256 or plain"),
            };
            // Comparing in constant time would be theatre here: the challenge is public, sent
            // in the clear on the authorization request.
            if computed == challenge {
                Ok(())
            } else {
                Err("the code_verifier does not match the code_challenge")
            }
        }
    }
}

/// RFC 7636 fixes the length and alphabet, and a verifier outside them is a client bug worth
/// reporting rather than silently failing the comparison.
fn is_well_formed(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier of the minimum permitted length.
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEF";

    fn s256(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    #[test]
    fn a_matching_s256_verifier_is_accepted() {
        let challenge = s256(VERIFIER);
        assert!(verify(Some(&challenge), Some("S256"), Some(VERIFIER)).is_ok());
    }

    #[test]
    fn a_mismatched_verifier_is_refused() {
        let challenge = s256(VERIFIER);
        let other = "zyxwvutsrqponmlkjihgfedcba9876543210-._~ABCDEF";
        assert!(verify(Some(&challenge), Some("S256"), Some(other)).is_err());
    }

    #[test]
    fn the_plain_method_compares_the_verifier_directly() {
        assert!(verify(Some(VERIFIER), Some("plain"), Some(VERIFIER)).is_ok());
        // Omitting the method means plain, per RFC 7636.
        assert!(verify(Some(VERIFIER), None, Some(VERIFIER)).is_ok());
        // A plain challenge must not be satisfied by the hashed form.
        assert!(verify(Some(VERIFIER), Some("plain"), Some(&s256(VERIFIER))).is_err());
    }

    #[test]
    fn a_verifier_is_required_once_a_challenge_was_recorded() {
        let challenge = s256(VERIFIER);
        assert!(verify(Some(&challenge), Some("S256"), None).is_err());
    }

    #[test]
    fn a_client_that_did_not_use_pkce_is_still_served() {
        // Requiring PKCE of every client would reject confidential clients that do not use it.
        assert!(verify(None, None, None).is_ok());
        // But a verifier with no challenge means the two requests disagree.
        assert!(verify(None, None, Some(VERIFIER)).is_err());
    }

    #[test]
    fn a_malformed_verifier_is_refused() {
        let challenge = s256("short");
        assert!(verify(Some(&challenge), Some("S256"), Some("short")).is_err());

        let long = "a".repeat(129);
        assert!(verify(Some(&s256(&long)), Some("S256"), Some(&long)).is_err());

        let illegal = format!("{VERIFIER}!");
        assert!(verify(Some(&s256(&illegal)), Some("S256"), Some(&illegal)).is_err());
    }

    #[test]
    fn an_unknown_challenge_method_is_refused() {
        assert!(verify(Some("x"), Some("S512"), Some(VERIFIER)).is_err());
    }
}
