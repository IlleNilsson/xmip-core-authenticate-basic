#![forbid(unsafe_code)]

//! Authenticate by HTTP Basic: the credential decoded, and handed to the
//! capability's store.
//!
//! RFC 7617 sends `Authorization: Basic <base64(user-id:password)>`. The
//! first gate reads the user half and calls it a `username` claim, with the
//! base64 text after `Basic ` riding on `Presented::proof` under
//! `basic.credential`, so the password never reaches the record. This gate
//! decodes it, checks that the credential names the user the claim names,
//! and asks the capability's `CredentialStore` — the same store `password`,
//! `digest` and `scram` verify against, which is why this crate depends on
//! the capability and not on `password` (ADR-0050 section 6).
//!
//! The user-id and password are UTF-8, as the `charset` parameter of RFC
//! 7617 section 2.1 lets a server announce; a credential that is not text
//! is refused as such rather than compared byte by byte.

use authenticate::store::CredentialStore;
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use identify::authorization;
use identify::evidence::{self, BASIC_CREDENTIAL};
use xcore::{Mechanism, mechanism};

/// Verifies a `username` claim with a `basic.credential` proof.
pub struct BasicAuthenticator {
    store: CredentialStore,
}

impl BasicAuthenticator {
    #[must_use]
    pub fn new(store: CredentialStore) -> Self {
        Self { store }
    }

    /// The enrolments this verifies against.
    #[must_use]
    pub fn store(&self) -> &CredentialStore {
        &self.store
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `basic`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "basic"
}

impl Authenticator for BasicAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::basic()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the Basic verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let credential = presented.proof(evidence::BASIC_CREDENTIAL).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{BASIC_CREDENTIAL}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        let credential = authorization::under(credential, "basic").unwrap_or(credential);
        let (user, password) = authorization::basic(credential)?;
        if user != presented.value {
            return Err(AuthenticateError::new(format!(
                "the claim names '{}' and the Basic credential names '{user}'",
                presented.value
            )));
        }
        if user.is_empty() {
            return Err(AuthenticateError::new("the user-id presented is empty"));
        }
        if self.store.verify(&user, &password) {
            Ok(Verified::Proven)
        } else {
            Ok(Verified::Refused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> BasicAuthenticator {
        BasicAuthenticator::new(CredentialStore::from_entries(
            4096,
            [("alice", "pencil"), ("Aladdin", "open sesame")],
        ))
    }

    fn claim(username: &str, pair: &str) -> Presented {
        Presented::passed(mechanism::username(), username).with_proof(
            evidence::BASIC_CREDENTIAL,
            codec::base64::encode(pair.as_bytes()),
        )
    }

    #[test]
    fn the_rfc_7617_credential_proves_aladdin() {
        // RFC 7617 section 2: Aladdin, open sesame.
        let presented = Presented::passed(mechanism::username(), "Aladdin")
            .with_proof(evidence::BASIC_CREDENTIAL, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert_eq!(
            verifier().verify(&presented).expect("verified"),
            Verified::Proven
        );
        // With the scheme word still in front, the same.
        let prefixed = Presented::passed(mechanism::basic(), "Aladdin").with_proof(
            evidence::BASIC_CREDENTIAL,
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        );
        assert_eq!(
            verifier().verify(&prefixed).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn a_wrong_password_is_refused_and_a_colon_in_it_is_kept() {
        let verifier = verifier();
        assert_eq!(
            verifier
                .verify(&claim("alice", "alice:pen"))
                .expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn a_credential_that_is_not_base64_or_has_no_colon_is_refused_by_reason() {
        let verifier = verifier();
        let garbage = Presented::passed(mechanism::username(), "alice")
            .with_proof(evidence::BASIC_CREDENTIAL, "!!");
        assert!(
            verifier
                .verify(&garbage)
                .expect_err("refused")
                .message
                .contains("not base64")
        );
        let bare = Presented::passed(mechanism::username(), "alice").with_proof(
            evidence::BASIC_CREDENTIAL,
            codec::base64::encode("alice".as_bytes()),
        );
        assert!(
            verifier
                .verify(&bare)
                .expect_err("refused")
                .message
                .contains("no colon")
        );
    }

    #[test]
    fn a_credential_naming_another_user_than_the_claim_is_refused() {
        let failure = verifier()
            .verify(&claim("bob", "alice:pencil"))
            .expect_err("refused");
        assert!(failure.message.contains("'bob'") && failure.message.contains("'alice'"));
    }

    #[test]
    fn a_username_without_a_credential_proof_is_refused_by_name() {
        let failure = verifier()
            .verify(&Presented::passed(mechanism::username(), "alice"))
            .expect_err("refused");
        assert!(
            failure.message.contains("'basic.credential'"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn another_mechanisms_claim_is_not_this_verifiers() {
        let token = Presented::passed(mechanism::bearer(), "t").with_proof("bearer.token", "x");
        let failure = verifier().verify(&token).expect_err("refused");
        assert!(failure.message.contains("'bearer'"), "{}", failure.message);
    }
}
