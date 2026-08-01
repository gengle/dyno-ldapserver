//! Matching rules and the (deliberately small) schema they are looked up in.
//!
//! Two values are never compared as raw bytes just because they look alike:
//! LDAP compares them under the *matching rule* of their attribute type.
//! `cn=Bob` and `cn=BOB` are the same entry; two `userPassword` values that
//! differ in case are not the same password.
//!
//! The schema here is **open**: an attribute nobody has heard of is not an
//! error, it just gets the default rule ([`MatchingRule::CaseIgnore`]). That
//! keeps the server usable as a test fixture for directories whose schema we
//! do not have. Strict schema enforcement is an open question in `DESIGN.md`
//! and belongs to the write phase, not here.

use std::collections::HashMap;

use crate::dn::Dn;
use crate::error::SyntaxError;
use crate::value::AttrValue;

/// How values of an attribute are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatchingRule {
    /// `caseIgnoreMatch` — the default. Case-insensitive, with leading and
    /// trailing whitespace removed and internal runs of whitespace collapsed
    /// to a single space (RFC 4518 prepare).
    CaseIgnore,
    /// `caseExactMatch` — as above but case is significant.
    CaseExact,
    /// `octetStringMatch` — byte-for-byte. Used for credentials and binary data.
    Octet,
    /// `distinguishedNameMatch` — parse both sides as DNs and compare
    /// structurally. Not orderable.
    DistinguishedName,
    /// `integerMatch` — parse both sides as integers.
    Integer,
    /// `booleanMatch` — `TRUE` or `FALSE`. Not orderable.
    Boolean,
}

impl MatchingRule {
    /// The RFC name, used in error messages and in extensible-match filters.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CaseIgnore => "caseIgnoreMatch",
            Self::CaseExact => "caseExactMatch",
            Self::Octet => "octetStringMatch",
            Self::DistinguishedName => "distinguishedNameMatch",
            Self::Integer => "integerMatch",
            Self::Boolean => "booleanMatch",
        }
    }

    /// Look a matching rule up by RFC name or by OID, for `(attr:rule:=value)`
    /// extensible-match filters. Unknown rules return `None`, which the filter
    /// evaluator turns into `Undefined` rather than an error.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "caseignorematch"
            | "caseignoreia5match"
            | "objectidentifiermatch"
            | "2.5.13.2"
            | "2.5.13.11" => Some(Self::CaseIgnore),
            "caseexactmatch" | "caseexactia5match" | "2.5.13.5" => Some(Self::CaseExact),
            "octetstringmatch" | "2.5.13.17" => Some(Self::Octet),
            "distinguishednamematch" | "2.5.13.1" => Some(Self::DistinguishedName),
            "integermatch" | "2.5.13.14" => Some(Self::Integer),
            "booleanmatch" | "2.5.13.13" => Some(Self::Boolean),
            _ => None,
        }
    }

    /// Whether `<=` and `>=` assertions mean anything for this rule.
    ///
    /// DN and boolean syntaxes have no ordering rule in RFC 4517, so a
    /// `(member>=x)` filter is `Undefined` rather than `false`.
    #[must_use]
    pub const fn supports_ordering(self) -> bool {
        match self {
            Self::CaseIgnore | Self::CaseExact | Self::Octet | Self::Integer => true,
            Self::DistinguishedName | Self::Boolean => false,
        }
    }

    /// Whether substring assertions mean anything for this rule.
    #[must_use]
    pub const fn supports_substring(self) -> bool {
        match self {
            Self::CaseIgnore | Self::CaseExact | Self::Octet => true,
            Self::DistinguishedName | Self::Integer | Self::Boolean => false,
        }
    }

    /// Reduce a value to its comparison key.
    ///
    /// Equality is `normalise(a) == normalise(b)` and ordering is the `Ord` of
    /// the keys, so all the rule-specific subtlety lives here and nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`SyntaxError`] when the value cannot be interpreted under the
    /// rule — an unparseable DN for `distinguishedNameMatch`, a non-integer for
    /// `integerMatch`. Callers evaluating a filter must map that to
    /// [`crate::Match::Undefined`], not to `false`.
    pub fn normalise(self, value: &AttrValue) -> Result<Key, SyntaxError> {
        match self {
            Self::Octet => Ok(Key::Bytes(value.as_bytes().to_vec())),
            Self::CaseIgnore => Ok(match value.as_str() {
                Some(s) => Key::Text(fold_whitespace(s).to_lowercase()),
                // Not text, so case folding is meaningless; fall back to bytes.
                None => Key::Bytes(value.as_bytes().to_vec()),
            }),
            Self::CaseExact => Ok(match value.as_str() {
                Some(s) => Key::Text(fold_whitespace(s)),
                None => Key::Bytes(value.as_bytes().to_vec()),
            }),
            Self::DistinguishedName => {
                let text = value
                    .as_str()
                    .ok_or_else(|| SyntaxError::new(self.name()))?;
                let dn = Dn::parse(text).map_err(|_| SyntaxError::new(self.name()))?;
                Ok(Key::Text(dn.normalised()))
            }
            Self::Integer => {
                let text = value
                    .as_str()
                    .ok_or_else(|| SyntaxError::new(self.name()))?;
                let n: i128 = text
                    .trim()
                    .parse()
                    .map_err(|_| SyntaxError::new(self.name()))?;
                Ok(Key::Int(n))
            }
            Self::Boolean => {
                let text = value
                    .as_str()
                    .ok_or_else(|| SyntaxError::new(self.name()))?;
                match text.trim() {
                    "TRUE" => Ok(Key::Text("TRUE".to_string())),
                    "FALSE" => Ok(Key::Text("FALSE".to_string())),
                    _ => Err(SyntaxError::new(self.name())),
                }
            }
        }
    }
}

/// The comparison key a value reduces to under a [`MatchingRule`].
///
/// Two keys are only ever compared when they came from the same rule, so the
/// cross-variant ordering below is arbitrary but deterministic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// A normalised text key.
    Text(String),
    /// Raw octets, for binary syntaxes and for text rules given non-UTF-8 input.
    Bytes(Vec<u8>),
    /// A numeric key.
    Int(i128),
}

impl Key {
    /// The key as text, if it is textual. Substring matching needs this.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The key as bytes, for substring matching over binary syntaxes.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(s) => Some(s.as_bytes()),
            Self::Bytes(b) => Some(b),
            Self::Int(_) => None,
        }
    }
}

/// Trim the ends and collapse internal whitespace runs to one space.
///
/// This is the "insignificant space handling" step of RFC 4518, and it is why
/// `cn=Bob  Smith` and `cn= Bob Smith ` are the same value.
#[must_use]
pub fn fold_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            pending_space = true;
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

/// What the schema knows about one attribute type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDef {
    /// Canonical spelling, e.g. `objectClass` for input `OBJECTCLASS`.
    pub name: String,
    /// The equality matching rule.
    pub equality: MatchingRule,
    /// Operational attributes are returned only when asked for by name or `+`.
    pub operational: bool,
    /// Whether more than one value is permitted (enforced in the write phase).
    pub single_value: bool,
}

impl AttributeDef {
    fn user(name: &str, equality: MatchingRule) -> Self {
        Self {
            name: name.to_string(),
            equality,
            operational: false,
            single_value: false,
        }
    }

    fn operational(name: &str, equality: MatchingRule) -> Self {
        Self {
            name: name.to_string(),
            equality,
            operational: true,
            single_value: false,
        }
    }

    /// Mark this definition single-valued.
    #[must_use]
    pub fn single(mut self) -> Self {
        self.single_value = true;
        self
    }
}

/// A lookup from attribute type to how it behaves.
///
/// Open by default: [`Schema::lookup`] returns `None` for attributes it does
/// not know, and every caller has a defined fallback.
#[derive(Debug, Clone)]
pub struct Schema {
    defs: HashMap<String, AttributeDef>,
    default_rule: MatchingRule,
}

impl Default for Schema {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Schema {
    /// An empty schema: every attribute gets the default rule.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            defs: HashMap::new(),
            default_rule: MatchingRule::CaseIgnore,
        }
    }

    /// The built-in table of attributes common enough that guessing wrong
    /// about them would be visible: credentials, DN-valued attributes, and the
    /// operational attributes a client expects not to receive by default.
    #[must_use]
    pub fn builtin() -> Self {
        use MatchingRule::{Boolean, CaseExact, CaseIgnore, DistinguishedName, Integer, Octet};
        let defs = [
            // Naming and descriptive attributes.
            AttributeDef::user("objectClass", CaseIgnore),
            AttributeDef::user("cn", CaseIgnore),
            AttributeDef::user("sn", CaseIgnore),
            AttributeDef::user("givenName", CaseIgnore),
            AttributeDef::user("displayName", CaseIgnore),
            AttributeDef::user("uid", CaseIgnore),
            AttributeDef::user("ou", CaseIgnore),
            AttributeDef::user("o", CaseIgnore),
            AttributeDef::user("dc", CaseIgnore),
            AttributeDef::user("l", CaseIgnore),
            AttributeDef::user("st", CaseIgnore),
            AttributeDef::user("street", CaseIgnore),
            AttributeDef::user("title", CaseIgnore),
            AttributeDef::user("description", CaseIgnore),
            AttributeDef::user("mail", CaseIgnore),
            AttributeDef::user("telephoneNumber", CaseIgnore),
            AttributeDef::user("sAMAccountName", CaseIgnore),
            AttributeDef::user("userPrincipalName", CaseIgnore),
            // Credentials and binary data: never case-folded.
            AttributeDef::user("userPassword", Octet),
            AttributeDef::user("userCertificate", Octet),
            AttributeDef::user("jpegPhoto", Octet),
            AttributeDef::user("labeledURI", CaseExact),
            // DN-valued. The proxy phase needs exactly this set to know which
            // values must be rewritten when crossing a namespace boundary.
            AttributeDef::user("member", DistinguishedName),
            AttributeDef::user("uniqueMember", DistinguishedName),
            AttributeDef::user("owner", DistinguishedName),
            AttributeDef::user("seeAlso", DistinguishedName),
            AttributeDef::user("manager", DistinguishedName),
            AttributeDef::user("secretary", DistinguishedName),
            AttributeDef::user("roleOccupant", DistinguishedName),
            AttributeDef::user("distinguishedName", DistinguishedName),
            AttributeDef::operational("memberOf", DistinguishedName),
            // Numeric and boolean.
            AttributeDef::user("uidNumber", Integer).single(),
            AttributeDef::user("gidNumber", Integer).single(),
            AttributeDef::user("employeeNumber", Integer).single(),
            // Operational attributes: present, but only returned on request.
            AttributeDef::operational("createTimestamp", CaseIgnore).single(),
            AttributeDef::operational("modifyTimestamp", CaseIgnore).single(),
            AttributeDef::operational("creatorsName", DistinguishedName).single(),
            AttributeDef::operational("modifiersName", DistinguishedName).single(),
            AttributeDef::operational("entryUUID", CaseIgnore).single(),
            AttributeDef::operational("entryDN", DistinguishedName).single(),
            AttributeDef::operational("subschemaSubentry", DistinguishedName).single(),
            AttributeDef::operational("hasSubordinates", Boolean).single(),
            AttributeDef::operational("numSubordinates", Integer).single(),
            AttributeDef::operational("structuralObjectClass", CaseIgnore).single(),
            // Root DSE attributes, all operational per RFC 4512 §5.1.
            AttributeDef::operational("namingContexts", DistinguishedName),
            AttributeDef::operational("supportedLDAPVersion", Integer),
            AttributeDef::operational("supportedControl", CaseIgnore),
            AttributeDef::operational("supportedExtension", CaseIgnore),
            AttributeDef::operational("supportedSASLMechanisms", CaseExact),
            AttributeDef::operational("supportedFeatures", CaseIgnore),
            AttributeDef::operational("vendorName", CaseExact).single(),
            AttributeDef::operational("vendorVersion", CaseExact).single(),
            AttributeDef::operational("altServer", CaseExact),
        ];

        let mut schema = Self::empty();
        for def in defs {
            schema.insert(def);
        }
        schema
    }

    /// Add or replace an attribute definition. Config may extend the schema.
    pub fn insert(&mut self, def: AttributeDef) {
        self.defs.insert(def.name.to_ascii_lowercase(), def);
    }

    /// Strip attribute options: `userCertificate;binary` is looked up as
    /// `userCertificate`, per RFC 4512 §2.5.
    #[must_use]
    pub fn base_type(attr: &str) -> &str {
        attr.split(';').next().unwrap_or(attr)
    }

    /// The definition for an attribute, ignoring case and options.
    #[must_use]
    pub fn lookup(&self, attr: &str) -> Option<&AttributeDef> {
        self.defs.get(&Self::base_type(attr).to_ascii_lowercase())
    }

    /// The equality rule for an attribute, or the default for unknown ones.
    #[must_use]
    pub fn equality_rule(&self, attr: &str) -> MatchingRule {
        self.lookup(attr).map_or(self.default_rule, |d| d.equality)
    }

    /// The canonical spelling of an attribute name, or the caller's spelling
    /// if the schema has never heard of it.
    #[must_use]
    pub fn canonical_name<'a>(&'a self, attr: &'a str) -> &'a str {
        self.lookup(attr).map_or(attr, |d| d.name.as_str())
    }

    /// Whether an attribute is operational, and so withheld unless requested.
    /// Unknown attributes are treated as user attributes.
    #[must_use]
    pub fn is_operational(&self, attr: &str) -> bool {
        self.lookup(attr).is_some_and(|d| d.operational)
    }

    /// Whether an attribute's values are DNs. The rewriting proxy consults
    /// this to decide what needs translating; a regex over attribute names
    /// would get `memberUid` wrong.
    #[must_use]
    pub fn is_dn_syntax(&self, attr: &str) -> bool {
        self.equality_rule(attr) == MatchingRule::DistinguishedName
    }

    /// Whether an attribute may hold at most one value.
    #[must_use]
    pub fn is_single_valued(&self, attr: &str) -> bool {
        self.lookup(attr).is_some_and(|d| d.single_value)
    }

    /// Compare two values under an attribute's equality rule.
    ///
    /// Returns `None` when either side is invalid for the rule, which the
    /// filter evaluator reads as `Undefined`.
    #[must_use]
    pub fn values_equal(&self, attr: &str, a: &AttrValue, b: &AttrValue) -> Option<bool> {
        let rule = self.equality_rule(attr);
        let (ka, kb) = (rule.normalise(a).ok()?, rule.normalise(b).ok()?);
        Some(ka == kb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passing case: case-insensitive attributes ignore case and insignificant
    /// whitespace, so `cn` values that differ only in presentation are equal.
    #[test]
    fn case_ignore_folds_case_and_whitespace() {
        let schema = Schema::builtin();
        assert_eq!(
            schema.values_equal("cn", &"Bob  Smith".into(), &"  bob smith ".into()),
            Some(true)
        );
        // Attribute name case and options do not change the rule.
        assert_eq!(schema.equality_rule("CN;lang-en"), MatchingRule::CaseIgnore);
    }

    /// Failing case: `userPassword` is octet-string matched, so the same two
    /// values that were equal as `cn` must not be equal as a credential.
    #[test]
    fn octet_string_attributes_do_not_fold_case() {
        let schema = Schema::builtin();
        assert_eq!(
            schema.values_equal("userPassword", &"Secret".into(), &"secret".into()),
            Some(false)
        );
    }

    /// Passing case: DN-valued attributes compare structurally, not textually.
    #[test]
    fn dn_syntax_attributes_compare_structurally() {
        let schema = Schema::builtin();
        assert!(schema.is_dn_syntax("member"));
        assert_eq!(
            schema.values_equal(
                "member",
                &"CN=Bob, OU=People,DC=example,DC=com".into(),
                &"cn=bob,ou=people,dc=example,dc=com".into()
            ),
            Some(true)
        );
    }

    /// Failing case: a value that is not a DN at all is a syntax error rather
    /// than an unequal comparison — the distinction becomes `Undefined` in a
    /// filter, which is what RFC 4511 §4.5.1 requires.
    #[test]
    fn dn_syntax_rejects_a_non_dn_value() {
        let schema = Schema::builtin();
        assert_eq!(
            schema.values_equal("member", &"not a dn".into(), &"cn=bob".into()),
            None
        );
        assert_eq!(
            MatchingRule::Integer.normalise(&"twelve".into()),
            Err(SyntaxError::new("integerMatch"))
        );
    }

    /// Validation: integers compare numerically, not lexically. `9 < 10` is
    /// the whole point of having an integer rule.
    #[test]
    fn integers_order_numerically() {
        let key = |rule: MatchingRule, v: &str| match rule.normalise(&v.into()) {
            Ok(k) => k,
            Err(e) => panic!("{v} should normalise under {}: {e}", rule.name()),
        };
        assert!(key(MatchingRule::Integer, "9") < key(MatchingRule::Integer, "10"));
        // The same values under the default text rule sort the other way,
        // which is exactly the bug the integer rule exists to prevent.
        assert!(key(MatchingRule::CaseIgnore, "9") > key(MatchingRule::CaseIgnore, "10"));
    }

    /// Validation: syntaxes with no RFC ordering rule say so, so the filter
    /// evaluator can return `Undefined` instead of inventing an answer.
    #[test]
    fn unorderable_syntaxes_are_declared() {
        assert!(!MatchingRule::DistinguishedName.supports_ordering());
        assert!(!MatchingRule::Boolean.supports_ordering());
        assert!(MatchingRule::Integer.supports_ordering());
    }

    /// Validation: unknown attributes are accepted with the default rule
    /// rather than rejected, because the server must be usable against
    /// directories whose schema we do not have.
    #[test]
    fn unknown_attributes_get_the_default_rule() {
        let schema = Schema::builtin();
        assert!(schema.lookup("wildlyCustomAttr").is_none());
        assert_eq!(
            schema.equality_rule("wildlyCustomAttr"),
            MatchingRule::CaseIgnore
        );
        assert_eq!(
            schema.canonical_name("wildlyCustomAttr"),
            "wildlyCustomAttr"
        );
        assert!(!schema.is_operational("wildlyCustomAttr"));
    }

    /// Validation: operational attributes are flagged, since search must
    /// withhold them unless a client asks by name or with `+`.
    #[test]
    fn operational_attributes_are_flagged() {
        let schema = Schema::builtin();
        assert!(schema.is_operational("createTimestamp"));
        assert!(schema.is_operational("namingContexts"));
        assert!(!schema.is_operational("cn"));
    }
}
