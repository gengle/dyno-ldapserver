//! Property tests for the DN invariants.
//!
//! Example-based tests catch the cases we thought of. These catch the ones we
//! did not — which, for DN escaping, is where the bugs actually live.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use dyno_core::{Dn, Rdn, Scope};
use proptest::prelude::*;

/// Values that exercise the escaping rules: reserved characters, leading and
/// trailing spaces, `#`, control characters, and non-ASCII text.
fn ava_value() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r#"[a-zA-Z0-9 ,+"\\<>;#=\x01\x1f\u{00e9}\u{4e2d}]{0,12}"#)
        .unwrap()
}

fn attr_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("cn".to_string()),
        Just("ou".to_string()),
        Just("dc".to_string()),
        Just("sn".to_string()),
        Just("2.5.4.3".to_string()),
    ]
}

fn rdn() -> impl Strategy<Value = Rdn> {
    (attr_type(), ava_value()).prop_map(|(a, v)| Rdn::single(a, v).unwrap())
}

fn dn() -> impl Strategy<Value = Dn> {
    proptest::collection::vec(rdn(), 0..5).prop_map(|rdns| {
        // A DN's RDNs must not repeat an attribute type *within* one RDN;
        // across RDNs repetition is fine, so this is always constructible.
        Dn::from_rdns(rdns)
    })
}

proptest! {
    /// Rendering a DN and parsing it back yields the same DN. This is the
    /// invariant that escaping exists to preserve.
    #[test]
    fn render_parse_round_trips(d in dn()) {
        let rendered = d.to_string();
        let reparsed = Dn::parse(&rendered)
            .unwrap_or_else(|e| panic!("{rendered:?} failed to re-parse: {e}"));
        prop_assert_eq!(&d, &reparsed);
        // ...and rendering is stable, so a value cannot drift over repeated
        // store/load cycles.
        prop_assert_eq!(rendered, reparsed.to_string());
    }

    /// Normalisation is idempotent and agrees with equality: two DNs are equal
    /// exactly when their normalised forms are.
    #[test]
    fn normalisation_agrees_with_equality(a in dn(), b in dn()) {
        prop_assert_eq!(a == b, a.normalised() == b.normalised());
        let renormalised = Dn::parse(&a.normalised()).unwrap();
        prop_assert_eq!(renormalised.normalised(), a.normalised());
    }

    /// A DN built by appending an RDN to a base is a child of that base, and
    /// its parent is that base. These three operations must not disagree.
    #[test]
    fn child_parent_and_containment_agree(base in dn(), leaf in rdn()) {
        let child = base.child(leaf);
        let parent = child.parent();
        prop_assert_eq!(parent.as_ref(), Some(&base));
        prop_assert!(child.is_child_of(&base));
        prop_assert!(child.is_within(&base));
        prop_assert!(child.is_strictly_within(&base));
        prop_assert!(!base.is_strictly_within(&child));
    }

    /// Scope containment is consistent: anything one-level or children-scoped
    /// is also subtree-scoped, and base scope means equality.
    #[test]
    fn scopes_are_consistent(base in dn(), candidate in dn()) {
        let one = Scope::OneLevel.contains(&base, &candidate);
        let sub = Scope::Subtree.contains(&base, &candidate);
        let children = Scope::Children.contains(&base, &candidate);
        let at_base = Scope::Base.contains(&base, &candidate);

        prop_assert!(!one || sub, "one-level entries must be in the subtree");
        prop_assert!(!children || sub, "children must be in the subtree");
        prop_assert!(!at_base || sub, "the base is in its own subtree");
        prop_assert_eq!(at_base, base == candidate);
        prop_assert_eq!(sub, at_base || children);
    }

    /// Containment is transitive: if c is under b and b is under a, c is
    /// under a. A string-suffix implementation satisfies this too, which is
    /// why the negative example test in `dn.rs` exists alongside it.
    #[test]
    fn containment_is_transitive(a in dn(), r1 in rdn(), r2 in rdn()) {
        let b = a.child(r1);
        let c = b.child(r2);
        prop_assert!(c.is_within(&b));
        prop_assert!(b.is_within(&a));
        prop_assert!(c.is_within(&a));
    }

    /// Parsing never panics, whatever bytes arrive. The DN in a bind or search
    /// request is attacker-controlled, so the only acceptable outcomes are a
    /// parsed DN or a typed error.
    #[test]
    fn parsing_arbitrary_input_never_panics(s in ".{0,64}") {
        let _ = Dn::parse(&s);
    }
}
