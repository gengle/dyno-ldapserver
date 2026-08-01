//! Directory entries.

use std::collections::BTreeMap;

use crate::dn::Dn;
use crate::schema::Schema;
use crate::value::AttrValue;

/// One attribute of an entry: a name and an unordered set of values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    values: Vec<AttrValue>,
}

impl Attribute {
    /// A new attribute with the given values.
    #[must_use]
    pub fn new(name: impl Into<String>, values: Vec<AttrValue>) -> Self {
        Self {
            name: name.into(),
            values,
        }
    }

    /// The attribute name, in the spelling that will be sent to clients.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The values.
    #[must_use]
    pub fn values(&self) -> &[AttrValue] {
        &self.values
    }

    /// The values, mutably.
    pub fn values_mut(&mut self) -> &mut Vec<AttrValue> {
        &mut self.values
    }

    /// Consume into values.
    #[must_use]
    pub fn into_values(self) -> Vec<AttrValue> {
        self.values
    }

    /// The first value as text, if any and if it is UTF-8. Convenient for the
    /// many attributes that are single-valued in practice.
    #[must_use]
    pub fn first_str(&self) -> Option<&str> {
        self.values.first().and_then(AttrValue::as_str)
    }

    /// Number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the attribute has no values. An attribute in this state is not
    /// legal in a stored entry; it must be removed instead.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// A directory entry: a DN and its attributes.
///
/// Attributes are keyed case-insensitively, because `objectClass` and
/// `objectclass` are the same attribute, while the original spelling is kept
/// for what goes back on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    dn: Dn,
    attrs: BTreeMap<String, Attribute>,
}

impl Entry {
    /// An entry with no attributes.
    #[must_use]
    pub fn new(dn: Dn) -> Self {
        Self {
            dn,
            attrs: BTreeMap::new(),
        }
    }

    /// The entry's DN.
    #[must_use]
    pub fn dn(&self) -> &Dn {
        &self.dn
    }

    /// Replace the entry's DN. Used by modifyDN and by proxy rewriting.
    pub fn set_dn(&mut self, dn: Dn) {
        self.dn = dn;
    }

    /// Builder-style attribute setter.
    #[must_use]
    pub fn with(mut self, name: &str, values: &[&str]) -> Self {
        self.set(name, values.iter().map(|v| AttrValue::from(*v)).collect());
        self
    }

    /// Set an attribute, replacing any existing values. Setting an empty value
    /// list removes the attribute, since a valued-less attribute cannot exist.
    pub fn set(&mut self, name: &str, values: Vec<AttrValue>) {
        let key = name.to_ascii_lowercase();
        if values.is_empty() {
            self.attrs.remove(&key);
        } else {
            self.attrs.insert(key, Attribute::new(name, values));
        }
    }

    /// Append values to an attribute, creating it if absent. Values already
    /// present under the attribute's matching rule are skipped, because LDAP
    /// attributes are sets.
    ///
    /// Returns the number of values actually added.
    pub fn add_values(&mut self, name: &str, values: Vec<AttrValue>, schema: &Schema) -> usize {
        let key = name.to_ascii_lowercase();
        let entry = self
            .attrs
            .entry(key)
            .or_insert_with(|| Attribute::new(name, Vec::new()));
        let mut added: usize = 0;
        for v in values {
            let duplicate = entry
                .values
                .iter()
                .any(|existing| schema.values_equal(name, existing, &v) == Some(true));
            if !duplicate {
                entry.values.push(v);
                added = added.saturating_add(1);
            }
        }
        added
    }

    /// Remove specific values from an attribute; removing the last value
    /// removes the attribute. An empty `values` list removes the whole
    /// attribute, matching LDAP delete-modification semantics.
    ///
    /// Returns the number of values removed, or `None` if the attribute is
    /// absent entirely.
    pub fn remove_values(
        &mut self,
        name: &str,
        values: &[AttrValue],
        schema: &Schema,
    ) -> Option<usize> {
        let key = name.to_ascii_lowercase();
        let attr = self.attrs.get_mut(&key)?;
        let removed = if values.is_empty() {
            let n = attr.values.len();
            attr.values.clear();
            n
        } else {
            let before = attr.values.len();
            attr.values.retain(|existing| {
                !values
                    .iter()
                    .any(|v| schema.values_equal(name, existing, v) == Some(true))
            });
            before.saturating_sub(attr.values.len())
        };
        if attr.values.is_empty() {
            self.attrs.remove(&key);
        }
        Some(removed)
    }

    /// Remove an attribute entirely.
    pub fn remove(&mut self, name: &str) -> Option<Attribute> {
        self.attrs.remove(&name.to_ascii_lowercase())
    }

    /// Look an attribute up, ignoring case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.attrs.get(&name.to_ascii_lowercase())
    }

    /// The values of an attribute, or an empty slice if it is absent.
    #[must_use]
    pub fn values(&self, name: &str) -> &[AttrValue] {
        self.get(name).map_or(&[], Attribute::values)
    }

    /// The first value of an attribute as text.
    #[must_use]
    pub fn first_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Attribute::first_str)
    }

    /// Whether an attribute is present with at least one value.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some_and(|a| !a.is_empty())
    }

    /// Whether an attribute holds a value, compared under its matching rule.
    #[must_use]
    pub fn has_value(&self, name: &str, value: &AttrValue, schema: &Schema) -> bool {
        self.values(name)
            .iter()
            .any(|v| schema.values_equal(name, v, value) == Some(true))
    }

    /// Whether the entry has an `objectClass` value, compared case-insensitively.
    #[must_use]
    pub fn has_object_class(&self, class: &str) -> bool {
        self.values("objectClass")
            .iter()
            .filter_map(AttrValue::as_str)
            .any(|v| v.eq_ignore_ascii_case(class))
    }

    /// Iterate attributes in a stable (lower-cased name) order.
    pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.values()
    }

    /// Number of attributes.
    #[must_use]
    pub fn attribute_count(&self) -> usize {
        self.attrs.len()
    }

    /// Whether the entry has no attributes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob() -> Entry {
        Entry::new(match Dn::parse("cn=Bob,ou=People,dc=example,dc=com") {
            Ok(d) => d,
            Err(e) => panic!("{e}"),
        })
        .with("objectClass", &["top", "person"])
        .with("cn", &["Bob"])
        .with("sn", &["Smith"])
    }

    /// Passing case: attributes are addressable regardless of the case used to
    /// write or read them.
    #[test]
    fn attribute_lookup_ignores_case() {
        let e = bob();
        assert_eq!(e.first_str("CN"), Some("Bob"));
        assert!(e.has("objectclass"));
        assert!(e.has_object_class("PERSON"));
    }

    /// Failing case: an absent attribute yields nothing rather than an empty
    /// string, so "present but empty" and "absent" stay distinguishable.
    #[test]
    fn absent_attribute_is_not_an_empty_value() {
        let e = bob();
        assert!(!e.has("mail"));
        assert_eq!(e.first_str("mail"), None);
        assert!(e.values("mail").is_empty());
    }

    /// Passing case: adding a value that is already present under the
    /// attribute's matching rule is a no-op — LDAP attributes are sets.
    #[test]
    fn adding_a_duplicate_value_is_a_no_op() {
        let schema = Schema::builtin();
        let mut e = bob();
        // "person" differs only in case, and objectClass is case-insensitive.
        let added = e.add_values("objectClass", vec!["PERSON".into()], &schema);
        assert_eq!(added, 0);
        assert_eq!(e.values("objectClass").len(), 2);

        let added = e.add_values("objectClass", vec!["inetOrgPerson".into()], &schema);
        assert_eq!(added, 1);
        assert_eq!(e.values("objectClass").len(), 3);
    }

    /// Failing case: case-sensitivity is per attribute, so the same trick with
    /// an octet-string attribute *does* add a second value.
    #[test]
    fn duplicate_detection_respects_the_matching_rule() {
        let schema = Schema::builtin();
        let mut e = bob();
        e.set("userPassword", vec!["Secret".into()]);
        let added = e.add_values("userPassword", vec!["secret".into()], &schema);
        assert_eq!(
            added, 1,
            "octet-string values differing in case are distinct"
        );
    }

    /// Validation: removing the last value removes the attribute, because an
    /// attribute with no values cannot exist in a stored entry.
    #[test]
    fn removing_the_last_value_removes_the_attribute() {
        let schema = Schema::builtin();
        let mut e = bob();
        assert_eq!(e.remove_values("sn", &["Smith".into()], &schema), Some(1));
        assert!(!e.has("sn"));
        assert!(e.get("sn").is_none());
        // Removing from an absent attribute is distinguishable from removing
        // zero values from a present one.
        assert_eq!(e.remove_values("sn", &["Smith".into()], &schema), None);
    }

    /// Validation: setting an empty value list removes rather than storing an
    /// attribute with no values.
    #[test]
    fn setting_no_values_removes_the_attribute() {
        let mut e = bob();
        e.set("sn", Vec::new());
        assert!(!e.has("sn"));
    }
}
