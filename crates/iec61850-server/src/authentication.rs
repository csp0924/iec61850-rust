//! Authentication of association requests.
//!
//! An [`AssociationAuthenticator`] installed on an [`IedServer`](crate::IedServer)
//! sees the called and calling AP-title and AE-qualifier and the credentials of
//! every AARQ, and decides whether the association goes ahead. A refused
//! association is answered with a Session REFUSE carrying a Presentation CPR
//! whose user data is an AARE with result rejected-permanent, the
//! acse-service-user diagnostic the authenticator names, and, as its user
//! information, an Initiate-ErrorPDU with access / object-access-denied.
//! Without an authenticator every association is accepted.
//!
//! The authenticator runs on the connection task while the association is
//! being set up, inside `association_setup_timeout_ms`, so it must not block.
//! Neither the server nor this module logs a password or an authentication
//! value: only the mechanism label and the decision are traced.

use std::net::SocketAddr;

pub use iec61850_mms::{AarqAddressing, AcseAuth, AcseServiceUserDiagnostic, ApTitle};

/// What an AARQ presents for authentication.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct AssociationRequest<'a> {
    /// Address of the peer.
    pub peer: SocketAddr,
    /// Called and calling AP-title and AE-qualifier; a field the AARQ left out,
    /// or whose value does not decode, is `None`.
    pub addressing: &'a AarqAddressing,
    /// The mechanism-name and calling-authentication-value of the AARQ.
    pub authentication: &'a AcseAuth,
}

impl<'a> AssociationRequest<'a> {
    /// Builds a request, for instance to exercise an authenticator in a test.
    pub fn new(
        peer: SocketAddr,
        addressing: &'a AarqAddressing,
        authentication: &'a AcseAuth,
    ) -> Self {
        Self {
            peer,
            addressing,
            authentication,
        }
    }

    /// The calling-AP-title, when the AARQ carries one that decodes.
    pub fn calling_ap_title(&self) -> Option<&'a ApTitle> {
        self.addressing.calling_ap_title.as_ref()
    }

    /// The calling-AE-qualifier, when the AARQ carries one that decodes.
    pub fn calling_ae_qualifier(&self) -> Option<i32> {
        self.addressing.calling_ae_qualifier
    }

    /// The password of the password mechanism, when the AARQ uses it.
    pub fn password(&self) -> Option<&'a [u8]> {
        match self.authentication {
            AcseAuth::Password(password) => Some(password),
            _ => None,
        }
    }
}

/// Whether an association request is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssociationDecision {
    /// The association goes ahead to the MMS Initiate negotiation.
    Accept,
    /// The association is refused with this acse-service-user diagnostic, for
    /// instance `AuthenticationFailure` for a wrong password or
    /// `CallingApTitleNotRecognized` for an AP-title outside an allow list.
    Reject(AcseServiceUserDiagnostic),
}

/// Decides whether an association request is accepted.
///
/// Implemented for every `Fn(&AssociationRequest<'_>) -> AssociationDecision`
/// that is `Send + Sync`, so a closure can be installed directly.
pub trait AssociationAuthenticator: Send + Sync {
    /// Returns the decision for `request`.
    fn authenticate(&self, request: &AssociationRequest<'_>) -> AssociationDecision;
}

impl<F> AssociationAuthenticator for F
where
    F: Fn(&AssociationRequest<'_>) -> AssociationDecision + Send + Sync,
{
    fn authenticate(&self, request: &AssociationRequest<'_>) -> AssociationDecision {
        self(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 102))
    }

    #[test]
    fn a_closure_decides_from_the_password() {
        let authenticator = |request: &AssociationRequest<'_>| match request.password() {
            Some(b"secret") => AssociationDecision::Accept,
            _ => AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationFailure),
        };
        let addressing = AarqAddressing::default();
        let right = AcseAuth::Password(b"secret".to_vec());
        let wrong = AcseAuth::Password(b"guess".to_vec());
        assert_eq!(
            authenticator.authenticate(&AssociationRequest::new(peer(), &addressing, &right)),
            AssociationDecision::Accept
        );
        assert_eq!(
            authenticator.authenticate(&AssociationRequest::new(peer(), &addressing, &wrong)),
            AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationFailure)
        );
        assert_eq!(
            authenticator.authenticate(&AssociationRequest::new(
                peer(),
                &addressing,
                &AcseAuth::None
            )),
            AssociationDecision::Reject(AcseServiceUserDiagnostic::AuthenticationFailure)
        );
    }

    #[test]
    fn the_request_debug_output_hides_the_password() {
        let addressing = AarqAddressing::default();
        let auth = AcseAuth::Password(b"secret".to_vec());
        let text = format!("{:?}", AssociationRequest::new(peer(), &addressing, &auth));
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("6 bytes redacted"), "{text}");
    }
}
