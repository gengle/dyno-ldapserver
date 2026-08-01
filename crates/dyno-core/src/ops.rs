//! Operation request types.
//!
//! These sit between the wire protocol and the backends. The server decodes
//! `LdapMsg` into these — DNs parsed, filters converted — so that backends and
//! rules never see a raw protocol type, and so the whole pipeline is testable
//! without a socket.

use crate::dn::Dn;
use crate::entry::Entry;
use crate::filter::Filter;
use crate::schema::Schema;
use crate::scope::Scope;
use crate::value::AttrValue;

/// Which attributes a search should return.
///
/// LDAP encodes this as a list of strings with three magic values, and getting
/// the defaults wrong is how a server leaks operational attributes:
///
/// - an empty list, or `*`, means all user attributes;
/// - `+` means all operational attributes (RFC 3673);
/// - `1.1` means no attributes at all, and is only meaningful alone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttrSelection {
    named: Vec<String>,
    all_user: bool,
    all_operational: bool,
    none: bool,
}

impl AttrSelection {
    /// Interpret the attribute list from a search request.
    #[must_use]
    pub fn from_request<S: AsRef<str>>(attrs: &[S]) -> Self {
        let mut sel = Self::default();
        for a in attrs {
            match a.as_ref() {
                "*" => sel.all_user = true,
                "+" => sel.all_operational = true,
                "1.1" => sel.none = true,
                other => sel.named.push(other.to_string()),
            }
        }
        // An empty list means "all user attributes".
        if attrs.is_empty() {
            sel.all_user = true;
        }
        // "1.1" is only meaningful on its own; if anything else was asked for,
        // RFC 4511 §4.5.1.8 says to ignore it.
        if sel.none && (sel.all_user || sel.all_operational || !sel.named.is_empty()) {
            sel.none = false;
        }
        sel
    }

    /// All user attributes and nothing else — the default selection.
    #[must_use]
    pub fn user_attributes() -> Self {
        Self {
            all_user: true,
            ..Self::default()
        }
    }

    /// Whether an attribute should be included in the response.
    #[must_use]
    pub fn includes(&self, attr: &str, schema: &Schema) -> bool {
        if self.none {
            return false;
        }
        if self
            .named
            .iter()
            .any(|n| Schema::base_type(n).eq_ignore_ascii_case(Schema::base_type(attr)))
        {
            return true;
        }
        if schema.is_operational(attr) {
            self.all_operational
        } else {
            self.all_user
        }
    }

    /// Whether the client asked for no attributes at all (`1.1`).
    #[must_use]
    pub fn is_none_requested(&self) -> bool {
        self.none
    }

    /// The explicitly named attributes.
    #[must_use]
    pub fn named(&self) -> &[String] {
        &self.named
    }

    /// Produce a copy of `entry` holding only the selected attributes.
    #[must_use]
    pub fn project(&self, entry: &Entry, schema: &Schema) -> Entry {
        let mut out = Entry::new(entry.dn().clone());
        if self.none {
            return out;
        }
        for attr in entry.attributes() {
            if self.includes(attr.name(), schema) {
                out.set(attr.name(), attr.values().to_vec());
            }
        }
        out
    }
}

/// A decoded search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// Base object.
    pub base: Dn,
    /// Scope.
    pub scope: Scope,
    /// Filter.
    pub filter: Filter,
    /// Which attributes to return.
    pub attrs: AttrSelection,
    /// Maximum entries to return; `None` means no client-imposed limit.
    pub size_limit: Option<usize>,
    /// Maximum seconds to spend; `None` means no client-imposed limit.
    pub time_limit: Option<u64>,
    /// Return attribute names without values.
    pub types_only: bool,
}

impl SearchRequest {
    /// A subtree search with the given base and filter, returning user
    /// attributes and no limits. Convenient for tests and internal lookups.
    #[must_use]
    pub fn subtree(base: Dn, filter: Filter) -> Self {
        Self {
            base,
            scope: Scope::Subtree,
            filter,
            attrs: AttrSelection::user_attributes(),
            size_limit: None,
            time_limit: None,
            types_only: false,
        }
    }

    /// A base-scoped search for exactly one entry.
    #[must_use]
    pub fn base_object(base: Dn) -> Self {
        Self {
            base,
            scope: Scope::Base,
            filter: Filter::Present("objectClass".to_string()),
            attrs: AttrSelection::user_attributes(),
            size_limit: None,
            time_limit: None,
            types_only: false,
        }
    }
}

/// One change within a modify operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modification {
    /// What to do.
    pub op: ModifyOp,
    /// The attribute type.
    pub attr: String,
    /// The values involved. Empty means "all values", for delete and replace.
    pub values: Vec<AttrValue>,
}

/// The kind of change a [`Modification`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifyOp {
    /// Add values, keeping existing ones.
    Add,
    /// Remove the given values, or the whole attribute if none are given.
    Delete,
    /// Replace all values; an empty value list removes the attribute.
    Replace,
}

/// A decoded modify request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    /// The entry to change.
    pub dn: Dn,
    /// The changes, applied in order.
    pub changes: Vec<Modification>,
}

/// A decoded add request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    /// The entry to create, DN included.
    pub entry: Entry,
}

/// A decoded modifyDN request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyDnRequest {
    /// The entry to move or rename.
    pub dn: Dn,
    /// The new RDN.
    pub new_rdn: crate::dn::Rdn,
    /// Whether to delete the old RDN's attribute value from the entry.
    pub delete_old_rdn: bool,
    /// New parent, if the entry is being moved as well as renamed.
    pub new_superior: Option<Dn>,
}

/// A decoded compare request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    /// The entry to test.
    pub dn: Dn,
    /// The attribute type.
    pub attr: String,
    /// The asserted value.
    pub value: AttrValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry::new(Dn::empty())
            .with("cn", &["Bob"])
            .with("userPassword", &["secret"])
            .with("createTimestamp", &["20240101000000Z"])
    }

    /// Passing case: the default selection returns user attributes.
    #[test]
    fn empty_attribute_list_means_all_user_attributes() {
        let sel = AttrSelection::from_request::<String>(&[]);
        let schema = Schema::builtin();
        let out = sel.project(&entry(), &schema);
        assert!(out.has("cn"));
        assert!(out.has("userPassword"));
    }

    /// Failing case: operational attributes are withheld unless asked for.
    /// A client that gets `createTimestamp` it never requested is a bug.
    #[test]
    fn operational_attributes_are_withheld_by_default() {
        let schema = Schema::builtin();
        let default = AttrSelection::from_request::<String>(&[]).project(&entry(), &schema);
        assert!(!default.has("createTimestamp"));

        let plus = AttrSelection::from_request(&["+"]).project(&entry(), &schema);
        assert!(plus.has("createTimestamp"));
        assert!(
            !plus.has("cn"),
            "'+' alone means operational attributes only"
        );

        let by_name = AttrSelection::from_request(&["createTimestamp"]).project(&entry(), &schema);
        assert!(by_name.has("createTimestamp"));
    }

    /// Validation: `1.1` returns the DN and nothing else...
    #[test]
    fn no_attributes_selector_returns_only_the_dn() {
        let schema = Schema::builtin();
        let out = AttrSelection::from_request(&["1.1"]).project(&entry(), &schema);
        assert!(out.is_empty());
    }

    /// Failing case: ...but `1.1` alongside a real attribute is ignored,
    /// per RFC 4511 §4.5.1.8, rather than suppressing the requested attribute.
    #[test]
    fn no_attributes_selector_is_ignored_when_combined() {
        let schema = Schema::builtin();
        let out = AttrSelection::from_request(&["1.1", "cn"]).project(&entry(), &schema);
        assert!(out.has("cn"));
    }

    /// Validation: named attributes are matched ignoring case and options.
    #[test]
    fn named_attributes_match_case_insensitively() {
        let schema = Schema::builtin();
        let out = AttrSelection::from_request(&["CN;lang-en"]).project(&entry(), &schema);
        assert!(out.has("cn"));
    }
}
