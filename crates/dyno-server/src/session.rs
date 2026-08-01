//! Per-connection state, and the rules about what may be done in it.
//!
//! The state machine is small but it is load-bearing: it is what stops an
//! operation that should require authentication from being answered because
//! the check was forgotten in one branch of the dispatch. Every operation asks
//! [`Session::authorise`] before it runs.

use std::net::SocketAddr;

use dyno_core::Dn;
use ldap3_proto::proto::LdapResultCode;

/// Who the client currently is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthState {
    /// No successful bind, or an explicit anonymous bind.
    #[default]
    Anonymous,
    /// A successful simple bind.
    Authenticated(Dn),
}

/// What kind of operation is being attempted, for authorisation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
    /// Bind, unbind, abandon and the root DSE: always permitted.
    Always,
    /// Search and compare.
    Read,
    /// Add, delete, modify, modifyDN.
    Write,
}

/// Why an operation was refused before it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The result code to return.
    pub code: LdapResultCode,
    /// The diagnostic message.
    pub message: String,
}

/// State for one client connection.
#[derive(Debug, Clone)]
pub struct Session {
    peer: SocketAddr,
    tls: bool,
    auth: AuthState,
    /// Whether reads require a successful bind.
    require_bind: bool,
    /// Whether writes are permitted at all on this server.
    allow_writes: bool,
}

impl Session {
    /// A new anonymous session.
    #[must_use]
    pub const fn new(peer: SocketAddr, tls: bool, require_bind: bool, allow_writes: bool) -> Self {
        Self {
            peer,
            tls,
            auth: AuthState::Anonymous,
            require_bind,
            allow_writes,
        }
    }

    /// The client's address.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Whether the connection is encrypted. Always false until Phase 4.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls
    }

    /// The current identity.
    #[must_use]
    pub const fn auth(&self) -> &AuthState {
        &self.auth
    }

    /// The bound DN, if any.
    #[must_use]
    pub const fn bound_dn(&self) -> Option<&Dn> {
        match &self.auth {
            AuthState::Authenticated(dn) => Some(dn),
            AuthState::Anonymous => None,
        }
    }

    /// Whether a bind has succeeded on this connection.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self.auth, AuthState::Authenticated(_))
    }

    /// Record a successful bind.
    pub fn authenticate(&mut self, dn: Dn) {
        self.auth = AuthState::Authenticated(dn);
    }

    /// Return to the anonymous state.
    ///
    /// RFC 4513 §5.1 requires this after a *failed* bind as well as after an
    /// anonymous one: a failed bind must not leave an earlier successful
    /// identity in place, or an attacker could downgrade a session to a
    /// different identity and keep the old one's rights.
    pub fn deauthenticate(&mut self) {
        self.auth = AuthState::Anonymous;
    }

    /// Decide whether an operation of this class may proceed.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] carrying the result code and message to send back.
    pub fn authorise(&self, class: OpClass) -> Result<(), Refusal> {
        match class {
            OpClass::Always => Ok(()),
            OpClass::Read => {
                if self.require_bind && !self.is_authenticated() {
                    return Err(Refusal {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: "this server requires authentication before searching".into(),
                    });
                }
                Ok(())
            }
            OpClass::Write => {
                if !self.allow_writes {
                    return Err(Refusal {
                        code: LdapResultCode::UnwillingToPerform,
                        message: "this server is configured read-only".into(),
                    });
                }
                if !self.is_authenticated() {
                    // Anonymous writes are never permitted, independently of
                    // `require_bind`. A directory that anyone can modify
                    // without identifying themselves has no useful audit trail.
                    return Err(Refusal {
                        code: LdapResultCode::InsufficentAccessRights,
                        message: "anonymous clients may not modify the directory".into(),
                    });
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        match "127.0.0.1:1234".parse() {
            Ok(a) => a,
            Err(e) => panic!("{e}"),
        }
    }

    fn dn(s: &str) -> Dn {
        match Dn::parse(s) {
            Ok(d) => d,
            Err(e) => panic!("{e}"),
        }
    }

    /// Passing case: with anonymous access allowed, an unauthenticated client
    /// may read.
    #[test]
    fn anonymous_reads_are_allowed_when_configured() {
        let s = Session::new(peer(), false, false, true);
        assert!(s.authorise(OpClass::Read).is_ok());
        assert!(s.authorise(OpClass::Always).is_ok());
    }

    /// Failing case: with `require_bind`, the same read is refused.
    #[test]
    fn anonymous_reads_are_refused_when_bind_is_required() {
        let s = Session::new(peer(), false, true, true);
        let err = s.authorise(OpClass::Read).unwrap_err();
        assert_eq!(err.code, LdapResultCode::InsufficentAccessRights);
        // ...and a bind fixes it.
        let mut s = s;
        s.authenticate(dn("cn=admin,dc=example,dc=com"));
        assert!(s.authorise(OpClass::Read).is_ok());
    }

    /// Failing case: anonymous writes are refused even when anonymous reads
    /// are allowed. This is independent of `require_bind` on purpose.
    #[test]
    fn anonymous_writes_are_always_refused() {
        let s = Session::new(peer(), false, false, true);
        assert!(s.authorise(OpClass::Read).is_ok());
        let err = s.authorise(OpClass::Write).unwrap_err();
        assert_eq!(err.code, LdapResultCode::InsufficentAccessRights);
    }

    /// Failing case: a read-only server refuses writes from anyone, including
    /// an authenticated client.
    #[test]
    fn a_read_only_server_refuses_authenticated_writes() {
        let mut s = Session::new(peer(), false, false, false);
        s.authenticate(dn("cn=admin,dc=example,dc=com"));
        let err = s.authorise(OpClass::Write).unwrap_err();
        assert_eq!(err.code, LdapResultCode::UnwillingToPerform);
    }

    /// Validation: a failed bind drops an identity already established on the
    /// connection, per RFC 4513 §5.1.
    #[test]
    fn deauthenticating_drops_a_previous_identity() {
        let mut s = Session::new(peer(), false, true, true);
        s.authenticate(dn("cn=admin,dc=example,dc=com"));
        assert!(s.is_authenticated());
        s.deauthenticate();
        assert!(!s.is_authenticated());
        assert_eq!(s.bound_dn(), None);
        assert!(s.authorise(OpClass::Read).is_err());
    }
}
