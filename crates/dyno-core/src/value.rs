//! Attribute values.
//!
//! LDAP attribute values are octet strings, not text. `userPassword`,
//! `jpegPhoto` and `userCertificate;binary` are all legitimately non-UTF-8, so
//! the storage type is `Vec<u8>` and text is a view onto it rather than the
//! other way round.

use std::borrow::Cow;
use std::fmt;

/// A single LDAP attribute value: an opaque octet string.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct AttrValue(Vec<u8>);

impl AttrValue {
    /// Wrap raw octets.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The raw octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into raw octets.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The value as text, or `None` if it is not valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The value as text, replacing invalid sequences. For display only —
    /// never use this for comparison.
    #[must_use]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    /// Number of octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is the empty octet string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for AttrValue {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for AttrValue {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl From<&String> for AttrValue {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for AttrValue {
    fn from(b: Vec<u8>) -> Self {
        Self(b)
    }
}

impl From<&[u8]> for AttrValue {
    fn from(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
}

impl fmt::Display for AttrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl fmt::Debug for AttrValue {
    /// Binary values print as a length rather than as bytes. Attribute values
    /// can be credentials, and `Debug` output has a way of reaching logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s:?}"),
            None => write!(f, "<{} binary octets>", self.0.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passing case: UTF-8 values round-trip through text accessors.
    #[test]
    fn text_value_round_trips() {
        let v = AttrValue::from("Bob Smith");
        assert_eq!(v.as_str(), Some("Bob Smith"));
        assert_eq!(v.as_bytes(), b"Bob Smith");
        assert_eq!(v.len(), 9);
    }

    /// Failing case: a non-UTF-8 value has no text view, and must not be
    /// silently lossy-converted by `as_str`.
    #[test]
    fn binary_value_has_no_text_view() {
        let v = AttrValue::new(vec![0xff, 0xfe, 0x00]);
        assert_eq!(v.as_str(), None);
        assert_eq!(v.as_bytes(), &[0xff, 0xfe, 0x00]);
    }

    /// Validation: `Debug` never renders binary octets, so a credential that
    /// reaches a log line does not leak.
    #[test]
    fn debug_redacts_binary_octets() {
        let v = AttrValue::new(vec![0xff, 0xfe]);
        assert_eq!(format!("{v:?}"), "<2 binary octets>");
    }
}
