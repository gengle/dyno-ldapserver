//! The root DSE.
//!
//! The root DSE describes the server, so it is synthesised here rather than
//! stored in a backend — no backend can be the authority on what the server it
//! is plugged into supports. It is reachable only by a base-scoped search of
//! the empty DN (RFC 4512 §5.1), and its attributes are all operational, so a
//! client that does not ask for them by name or with `+` gets an entry with a
//! DN and nothing else. That is correct, and it surprises people.

use dyno_backend::Backend;
use dyno_core::{AttrValue, Dn, Entry};
use ldap3_proto::proto::OID_WHOAMI;

/// The subschema subentry DN advertised in the root DSE.
pub const SUBSCHEMA_DN: &str = "cn=Subschema";

/// Build the root DSE for a backend.
#[must_use]
pub fn build(backend: &dyn Backend) -> Entry {
    let mut entry = Entry::new(Dn::empty());
    entry.set(
        "objectClass",
        vec![AttrValue::from("top"), AttrValue::from("OpenLDAProotDSE")],
    );
    entry.set(
        "namingContexts",
        backend
            .naming_contexts()
            .iter()
            .map(|dn| AttrValue::from(dn.to_string()))
            .collect(),
    );
    entry.set("supportedLDAPVersion", vec![AttrValue::from("3")]);
    entry.set("supportedExtension", vec![AttrValue::from(OID_WHOAMI)]);
    entry.set("subschemaSubentry", vec![AttrValue::from(SUBSCHEMA_DN)]);
    entry.set("vendorName", vec![AttrValue::from("dyno-ldapserver")]);
    entry.set(
        "vendorVersion",
        vec![AttrValue::from(env!("CARGO_PKG_VERSION"))],
    );
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use dyno_backend::MemoryBackend;
    use dyno_core::{AttrSelection, Schema};
    use std::sync::Arc;

    fn backend() -> MemoryBackend {
        MemoryBackend::new(
            "memory",
            vec![
                Dn::parse("dc=example,dc=com").unwrap_or_default(),
                Dn::parse("dc=other,dc=com").unwrap_or_default(),
            ],
            Arc::new(Schema::builtin()),
        )
    }

    /// Passing case: the root DSE advertises every naming context the backend
    /// serves, plus the version and extension information a client uses to
    /// decide what it can do.
    #[test]
    fn advertises_naming_contexts_and_capabilities() {
        let entry = build(&backend());
        assert!(entry.dn().is_empty());
        let contexts: Vec<_> = entry
            .values("namingContexts")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(contexts, vec!["dc=example,dc=com", "dc=other,dc=com"]);
        assert_eq!(entry.first_str("supportedLDAPVersion"), Some("3"));
        assert_eq!(entry.first_str("subschemaSubentry"), Some(SUBSCHEMA_DN));
        assert_eq!(entry.first_str("vendorName"), Some("dyno-ldapserver"));
    }

    /// Failing case: every root DSE attribute is operational, so a client
    /// that asks for user attributes gets none of them. This trips people up
    /// often enough to be worth pinning down.
    #[test]
    fn root_dse_attributes_are_all_operational() {
        let schema = Schema::builtin();
        let entry = build(&backend());

        let default = AttrSelection::from_request::<String>(&[]).project(&entry, &schema);
        assert!(
            !default.has("namingContexts") && !default.has("vendorName"),
            "a default search of the root DSE returns none of the informative \
             attributes, because they are all operational"
        );
        assert!(
            default.has("objectClass"),
            "objectClass is a user attribute even here, and clients expect it"
        );

        let asked = AttrSelection::from_request(&["namingContexts"]).project(&entry, &schema);
        assert!(asked.has("namingContexts"));

        let plus = AttrSelection::from_request(&["+"]).project(&entry, &schema);
        assert!(plus.has("namingContexts"));
        assert!(plus.has("vendorName"));
    }
}
