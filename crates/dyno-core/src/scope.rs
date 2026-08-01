//! Search scope.

use crate::dn::Dn;

/// How far below the base object a search reaches (RFC 4511 §4.5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Scope {
    /// The base object only.
    #[default]
    Base,
    /// The immediate children of the base, but not the base itself.
    OneLevel,
    /// The base and everything below it.
    Subtree,
    /// Everything below the base, excluding the base itself. A non-standard
    /// but widely implemented scope (`draft-sermersheim-ldap-subordinate-scope`).
    Children,
}

impl Scope {
    /// Whether an entry at `candidate` is in scope for a search based at `base`.
    ///
    /// This is a structural comparison on RDNs. A string suffix test would let
    /// `dc=notexample,dc=com` in under a base of `dc=example,dc=com`.
    #[must_use]
    pub fn contains(self, base: &Dn, candidate: &Dn) -> bool {
        match self {
            Self::Base => candidate == base,
            Self::OneLevel => candidate.is_child_of(base),
            Self::Subtree => candidate.is_within(base),
            Self::Children => candidate.is_strictly_within(base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dn(s: &str) -> Dn {
        match Dn::parse(s) {
            Ok(d) => d,
            Err(e) => panic!("{s:?}: {e}"),
        }
    }

    /// Passing case: each scope admits exactly the entries it should.
    #[test]
    fn each_scope_admits_the_right_entries() {
        let base = dn("dc=example,dc=com");
        let people = dn("ou=People,dc=example,dc=com");
        let bob = dn("cn=Bob,ou=People,dc=example,dc=com");

        assert!(Scope::Base.contains(&base, &base));
        assert!(Scope::OneLevel.contains(&base, &people));
        assert!(Scope::Subtree.contains(&base, &base));
        assert!(Scope::Subtree.contains(&base, &bob));
        assert!(Scope::Children.contains(&base, &bob));
    }

    /// Failing case: each scope excludes exactly what it should. These are the
    /// boundaries that leak entries when they are wrong.
    #[test]
    fn each_scope_excludes_the_right_entries() {
        let base = dn("dc=example,dc=com");
        let people = dn("ou=People,dc=example,dc=com");
        let bob = dn("cn=Bob,ou=People,dc=example,dc=com");
        let elsewhere = dn("cn=Eve,dc=notexample,dc=com");

        // base scope is one entry only
        assert!(!Scope::Base.contains(&base, &people));
        // one-level does not include the base or grandchildren
        assert!(!Scope::OneLevel.contains(&base, &base));
        assert!(!Scope::OneLevel.contains(&base, &bob));
        // children excludes the base itself
        assert!(!Scope::Children.contains(&base, &base));
        // and nothing admits a different naming context that merely shares a
        // string suffix
        for scope in [
            Scope::Base,
            Scope::OneLevel,
            Scope::Subtree,
            Scope::Children,
        ] {
            assert!(
                !scope.contains(&base, &elsewhere),
                "{scope:?} leaked an out-of-tree entry"
            );
        }
    }
}
