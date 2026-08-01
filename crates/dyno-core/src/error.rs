//! Error types for the pure domain layer.

use thiserror::Error;

/// Why a distinguished name could not be parsed.
///
/// Every variant is reachable from client-supplied input, so each one is a
/// documented rejection rather than a panic. The server maps these onto LDAP
/// result code 34 (`invalidDNSyntax`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DnError {
    /// An RDN was present but contained no `type=value` pair, e.g. `"cn=a,,dc=x"`.
    #[error("empty relative distinguished name")]
    EmptyRdn,

    /// An RDN component had no `=`, e.g. `"cn"`.
    #[error("relative distinguished name has no '=': {0:?}")]
    MissingEquals(String),

    /// The attribute type was empty, e.g. `"=value"`.
    #[error("empty attribute type")]
    EmptyAttributeType,

    /// The attribute type was not a valid `descr` or `numericoid` (RFC 4512).
    #[error("invalid attribute type {0:?}")]
    InvalidAttributeType(String),

    /// A character that RFC 4514 requires to be escaped appeared bare in a value.
    #[error("unescaped {0:?} in attribute value; RFC 4514 requires it to be escaped")]
    UnescapedSpecial(char),

    /// A `\` appeared as the last character of the DN.
    #[error("distinguished name ends with a trailing '\\' escape")]
    TrailingEscape,

    /// `\` was followed by one hex digit rather than a pair, e.g. `"cn=\\4"`.
    #[error("invalid escape sequence '\\{0}'; expected a character or two hex digits")]
    InvalidEscape(String),

    /// A `#`-prefixed value was not a run of hex pairs, e.g. `"cn=#0"`.
    #[error("invalid hex-encoded attribute value {0:?}")]
    InvalidHexValue(String),

    /// The same attribute type appeared twice in one multi-valued RDN.
    #[error("attribute type {0:?} appears more than once in a single RDN")]
    DuplicateAvaType(String),
}

/// An assertion value did not conform to the syntax its matching rule requires.
///
/// In LDAP this does not make the search fail — it makes that one filter
/// component evaluate to `Undefined` (RFC 4511 §4.5.1). See [`crate::Match`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("value is not valid for the {rule} matching rule")]
pub struct SyntaxError {
    /// The matching rule that rejected the value.
    pub rule: &'static str,
}

impl SyntaxError {
    /// Construct a syntax error naming the rule that rejected the value.
    #[must_use]
    pub const fn new(rule: &'static str) -> Self {
        Self { rule }
    }
}
