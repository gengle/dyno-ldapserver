//! Distinguished names: parsing, normalisation, comparison, and rendering.
//!
//! A [`Dn`] is parsed once at the edge of the system and passed around as a
//! structure. Nothing downstream should be doing string surgery on DNs — that
//! is how `ou=People` fails to match `OU=people`, and how a proxy that
//! string-replaces a base DN corrupts `member` values.
//!
//! # What "equal" means here
//!
//! Two DNs are equal when they have the same number of RDNs, in the same
//! order, and each RDN holds the same *set* of `type=value` pairs (an RDN is a
//! set, so `cn=a+sn=b` equals `sn=b+cn=a`). Attribute types are compared
//! case-insensitively. Values are compared after
//! [`fold_whitespace`](crate::schema::fold_whitespace) and case folding.
//!
//! That last point is a deliberate simplification: strictly, the comparison
//! should use each attribute's own matching rule, so a DN whose naming
//! attribute is case-*exact* would compare differently. Directory servers in
//! practice fold case for DN comparison, and doing so keeps [`Dn`] free of a
//! schema reference so it can implement `Eq` and `Hash`.
//!
//! # Rendering
//!
//! [`Display`](std::fmt::Display) produces RFC 4514 with the original spelling
//! and case preserved, escaping whatever needs escaping. [`Dn::normalised`]
//! produces the canonical lower-cased form used as a map key.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::error::DnError;
use crate::schema::fold_whitespace;
use crate::value::AttrValue;

/// One `type=value` pair inside an RDN.
#[derive(Debug, Clone, Eq)]
pub struct Ava {
    /// Attribute type as written by the client, e.g. `OU`.
    attr: String,
    /// Lower-cased attribute type, used for comparison.
    attr_norm: String,
    /// Value as written, un-escaped into raw octets.
    value: AttrValue,
    /// Normalised value bytes, used for comparison.
    value_norm: Vec<u8>,
}

impl Ava {
    /// Build an AVA from an attribute type and value.
    ///
    /// # Errors
    ///
    /// Returns [`DnError::EmptyAttributeType`] or
    /// [`DnError::InvalidAttributeType`] if the type is not a valid RFC 4512
    /// `descr` or `numericoid`.
    pub fn new(attr: impl Into<String>, value: impl Into<AttrValue>) -> Result<Self, DnError> {
        let attr = attr.into();
        validate_attribute_type(&attr)?;
        let value = value.into();
        Ok(Self {
            attr_norm: attr.to_ascii_lowercase(),
            value_norm: normalise_value(&value),
            attr,
            value,
        })
    }

    /// Attribute type as written.
    #[must_use]
    pub fn attr(&self) -> &str {
        &self.attr
    }

    /// Lower-cased attribute type.
    #[must_use]
    pub fn attr_normalised(&self) -> &str {
        &self.attr_norm
    }

    /// Value as written.
    #[must_use]
    pub fn value(&self) -> &AttrValue {
        &self.value
    }
}

impl PartialEq for Ava {
    fn eq(&self, other: &Self) -> bool {
        self.attr_norm == other.attr_norm && self.value_norm == other.value_norm
    }
}

impl std::hash::Hash for Ava {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.attr_norm.hash(state);
        self.value_norm.hash(state);
    }
}

impl Ord for Ava {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.attr_norm, &self.value_norm).cmp(&(&other.attr_norm, &other.value_norm))
    }
}

impl PartialOrd for Ava {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Ava {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.attr, escape_value(&self.value))
    }
}

/// A relative distinguished name: one or more AVAs joined by `+`.
///
/// The AVAs are held in a canonical order so that `cn=a+sn=b` and `sn=b+cn=a`
/// are the same value, but [`Display`](std::fmt::Display) prints them in the
/// order the client wrote them.
#[derive(Debug, Clone, Eq)]
pub struct Rdn {
    /// In the order supplied, for rendering.
    avas: Vec<Ava>,
    /// Sorted, for comparison and hashing.
    sorted: Vec<Ava>,
}

impl Rdn {
    /// Build an RDN from its AVAs.
    ///
    /// # Errors
    ///
    /// Returns [`DnError::EmptyRdn`] if `avas` is empty, or
    /// [`DnError::DuplicateAvaType`] if one attribute type appears twice —
    /// `cn=a+cn=b` is not a legal RDN.
    pub fn new(avas: Vec<Ava>) -> Result<Self, DnError> {
        if avas.is_empty() {
            return Err(DnError::EmptyRdn);
        }
        let mut sorted = avas.clone();
        sorted.sort();
        for pair in sorted.windows(2) {
            if let [a, b] = pair {
                if a.attr_norm == b.attr_norm {
                    return Err(DnError::DuplicateAvaType(a.attr.clone()));
                }
            }
        }
        Ok(Self { avas, sorted })
    }

    /// Convenience for the common single-valued RDN.
    ///
    /// # Errors
    ///
    /// As [`Ava::new`].
    pub fn single(attr: impl Into<String>, value: impl Into<AttrValue>) -> Result<Self, DnError> {
        Self::new(vec![Ava::new(attr, value)?])
    }

    /// The AVAs, in the order supplied.
    #[must_use]
    pub fn avas(&self) -> &[Ava] {
        &self.avas
    }

    /// The value of a given attribute type within this RDN, if present.
    #[must_use]
    pub fn get(&self, attr: &str) -> Option<&AttrValue> {
        let needle = attr.to_ascii_lowercase();
        self.avas
            .iter()
            .find(|a| a.attr_norm == needle)
            .map(Ava::value)
    }

    /// Whether this RDN has more than one AVA.
    #[must_use]
    pub fn is_multi_valued(&self) -> bool {
        self.avas.len() > 1
    }

    fn normalised(&self) -> String {
        let mut parts = self
            .sorted
            .iter()
            .map(|a| {
                format!(
                    "{}={}",
                    a.attr_norm,
                    escape_value(&AttrValue::new(a.value_norm.clone()))
                )
            })
            .collect::<Vec<_>>();
        parts.sort();
        parts.join("+")
    }
}

impl PartialEq for Rdn {
    fn eq(&self, other: &Self) -> bool {
        self.sorted == other.sorted
    }
}

impl std::hash::Hash for Rdn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sorted.hash(state);
    }
}

impl Ord for Rdn {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sorted.cmp(&other.sorted)
    }
}

impl PartialOrd for Rdn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Rdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, ava) in self.avas.iter().enumerate() {
            if i > 0 {
                f.write_str("+")?;
            }
            write!(f, "{ava}")?;
        }
        Ok(())
    }
}

/// A distinguished name: a sequence of RDNs, most specific first.
///
/// The empty DN is the root DSE and is a legal value, not an error.
#[derive(Debug, Clone, Eq)]
pub struct Dn {
    rdns: Vec<Rdn>,
    normalised: String,
}

impl Dn {
    /// The empty DN, which names the root DSE.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rdns: Vec::new(),
            normalised: String::new(),
        }
    }

    /// Build a DN from RDNs, most specific first.
    #[must_use]
    pub fn from_rdns(rdns: Vec<Rdn>) -> Self {
        let normalised = rdns
            .iter()
            .map(Rdn::normalised)
            .collect::<Vec<_>>()
            .join(",");
        Self { rdns, normalised }
    }

    /// Parse an RFC 4514 string representation.
    ///
    /// Deviations from a strict reading of the grammar, all in the direction of
    /// accepting what real clients send:
    ///
    /// - Whitespace around `,` and `=` is accepted and discarded.
    /// - Unescaped leading and trailing spaces inside a value are discarded
    ///   rather than rejected; `\ ` still means a significant space.
    ///
    /// Everything else is strict: a bare `"`, `<`, `>`, `;` or `\` inside a
    /// value is a syntax error, because silently accepting them is how two
    /// components end up disagreeing about where a DN ends.
    ///
    /// # Errors
    ///
    /// Returns the [`DnError`] describing the first problem found.
    pub fn parse(input: &str) -> Result<Self, DnError> {
        let mut chars = input.chars().peekable();
        let mut rdns: Vec<Rdn> = Vec::new();
        let mut avas: Vec<Ava> = Vec::new();

        skip_spaces(&mut chars);
        if chars.peek().is_none() {
            return Ok(Self::empty());
        }

        loop {
            let (ava, terminator) = parse_ava(&mut chars)?;
            avas.push(ava);
            match terminator {
                Some('+') => {}
                Some(_) => {
                    rdns.push(Rdn::new(std::mem::take(&mut avas))?);
                }
                None => {
                    rdns.push(Rdn::new(std::mem::take(&mut avas))?);
                    break;
                }
            }
        }

        Ok(Self::from_rdns(rdns))
    }

    /// Whether this is the empty (root DSE) DN.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// Number of RDNs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rdns.len()
    }

    /// The RDNs, most specific first.
    #[must_use]
    pub fn rdns(&self) -> &[Rdn] {
        &self.rdns
    }

    /// The most specific RDN, or `None` for the root DSE.
    #[must_use]
    pub fn rdn(&self) -> Option<&Rdn> {
        self.rdns.first()
    }

    /// The immediate parent, or `None` for the root DSE.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.rdns.is_empty() {
            return None;
        }
        Some(Self::from_rdns(self.rdns.iter().skip(1).cloned().collect()))
    }

    /// A new DN with `rdn` prepended as the most specific component.
    #[must_use]
    pub fn child(&self, rdn: Rdn) -> Self {
        let mut rdns = Vec::with_capacity(self.rdns.len().saturating_add(1));
        rdns.push(rdn);
        rdns.extend(self.rdns.iter().cloned());
        Self::from_rdns(rdns)
    }

    /// Whether `self` is the immediate child of `base` (one level below).
    #[must_use]
    pub fn is_child_of(&self, base: &Self) -> bool {
        self.parent().is_some_and(|p| &p == base)
    }

    /// Whether `self` is at or below `base` in the tree. The root DSE's empty
    /// DN is above everything, so every DN is within it.
    #[must_use]
    pub fn is_within(&self, base: &Self) -> bool {
        if base.rdns.len() > self.rdns.len() {
            return false;
        }
        let offset = self.rdns.len().saturating_sub(base.rdns.len());
        self.rdns.iter().skip(offset).eq(base.rdns.iter())
    }

    /// Whether `self` is strictly below `base`.
    #[must_use]
    pub fn is_strictly_within(&self, base: &Self) -> bool {
        self.rdns.len() > base.rdns.len() && self.is_within(base)
    }

    /// The canonical, lower-cased form. Use this as a map key; it is the
    /// string form of the same thing `==` compares.
    #[must_use]
    pub fn normalised(&self) -> String {
        self.normalised.clone()
    }

    /// The canonical form without cloning.
    #[must_use]
    pub fn normalised_ref(&self) -> &str {
        &self.normalised
    }

    /// The canonical form with the RDNs reversed, most general first.
    ///
    /// Sorting by this puts every entry of a subtree in one contiguous run,
    /// which is what lets an ordered store answer a subtree search with a
    /// range scan instead of a full table scan.
    #[must_use]
    pub fn sort_key(&self) -> String {
        self.rdns
            .iter()
            .rev()
            .map(Rdn::normalised)
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Default for Dn {
    /// The root DSE.
    fn default() -> Self {
        Self::empty()
    }
}

impl FromStr for Dn {
    type Err = DnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl PartialEq for Dn {
    fn eq(&self, other: &Self) -> bool {
        self.normalised == other.normalised
    }
}

impl std::hash::Hash for Dn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.normalised.hash(state);
    }
}

impl Ord for Dn {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalised.cmp(&other.normalised)
    }
}

impl PartialOrd for Dn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Dn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, rdn) in self.rdns.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{rdn}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsing internals
// ---------------------------------------------------------------------------

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn skip_spaces(chars: &mut Chars<'_>) {
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        let _ = chars.next();
    }
}

/// Parse one `type=value`, stopping at an unescaped `,`, `;` or `+`.
/// Returns the AVA and the terminator that ended it (`None` at end of input).
fn parse_ava(chars: &mut Chars<'_>) -> Result<(Ava, Option<char>), DnError> {
    skip_spaces(chars);

    // Attribute type, up to '='.
    let mut attr = String::new();
    let mut saw_equals = false;
    while let Some(c) = chars.next() {
        match c {
            '=' => {
                saw_equals = true;
                break;
            }
            ',' | ';' | '+' => {
                return Err(if attr.is_empty() {
                    // Two separators in a row, e.g. "cn=a,,dc=x".
                    DnError::EmptyRdn
                } else {
                    DnError::MissingEquals(attr)
                });
            }
            ' ' | '\t' => skip_spaces(chars),
            other => attr.push(other),
        }
    }
    if !saw_equals {
        return Err(if attr.is_empty() {
            DnError::EmptyRdn
        } else {
            DnError::MissingEquals(attr)
        });
    }
    validate_attribute_type(&attr)?;

    let value = parse_value(chars)?;
    let terminator = match chars.peek() {
        Some(&c @ (',' | ';' | '+')) => {
            let _ = chars.next();
            Some(c)
        }
        _ => None,
    };

    Ok((Ava::new(attr, value)?, terminator))
}

/// Parse an attribute value, leaving the terminator un-consumed.
fn parse_value(chars: &mut Chars<'_>) -> Result<AttrValue, DnError> {
    skip_spaces(chars);

    if chars.peek() == Some(&'#') {
        let _ = chars.next();
        return parse_hex_value(chars);
    }

    let mut buf: Vec<u8> = Vec::new();
    // Where the current run of unescaped trailing whitespace began, if any.
    let mut space_run: Option<usize> = None;

    while let Some(&c) = chars.peek() {
        match c {
            ',' | ';' | '+' => break,
            '\\' => {
                let _ = chars.next();
                push_escape(chars, &mut buf)?;
                space_run = None;
            }
            '"' | '<' | '>' => return Err(DnError::UnescapedSpecial(c)),
            ' ' | '\t' => {
                if space_run.is_none() {
                    space_run = Some(buf.len());
                }
                buf.push(b' ');
                let _ = chars.next();
            }
            other => {
                space_run = None;
                let mut tmp = [0u8; 4];
                buf.extend_from_slice(other.encode_utf8(&mut tmp).as_bytes());
                let _ = chars.next();
            }
        }
    }

    if let Some(start) = space_run {
        buf.truncate(start);
    }
    Ok(AttrValue::new(buf))
}

/// Decode the character(s) after a `\`.
fn push_escape(chars: &mut Chars<'_>, buf: &mut Vec<u8>) -> Result<(), DnError> {
    let first = chars.next().ok_or(DnError::TrailingEscape)?;
    if let Some(hi) = first.to_digit(16) {
        // RFC 4514 hex pairs must be exactly two digits. A lone hex digit is
        // ambiguous with an escaped literal, so it is rejected rather than
        // guessed at.
        let second = chars.next().ok_or(DnError::TrailingEscape)?;
        let lo = second
            .to_digit(16)
            .ok_or_else(|| DnError::InvalidEscape(format!("{first}{second}")))?;
        let byte = u8::try_from(hi.saturating_mul(16).saturating_add(lo))
            .map_err(|_| DnError::InvalidEscape(format!("{first}{second}")))?;
        buf.push(byte);
    } else {
        let mut tmp = [0u8; 4];
        buf.extend_from_slice(first.encode_utf8(&mut tmp).as_bytes());
    }
    Ok(())
}

/// Parse a `#`-prefixed hex value, the `#` already consumed.
fn parse_hex_value(chars: &mut Chars<'_>) -> Result<AttrValue, DnError> {
    let mut digits = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_hexdigit() {
            digits.push(c);
            let _ = chars.next();
        } else {
            break;
        }
    }
    skip_spaces(chars);

    if digits.is_empty() || digits.len() % 2 != 0 {
        return Err(DnError::InvalidHexValue(format!("#{digits}")));
    }
    // The length is even, checked above, so this is exactly the pair count.
    let mut bytes = Vec::with_capacity(digits.len().div_ceil(2));
    let mut iter = digits.chars();
    while let (Some(hi), Some(lo)) = (iter.next(), iter.next()) {
        let (hi, lo) = (
            hi.to_digit(16)
                .ok_or_else(|| DnError::InvalidHexValue(digits.clone()))?,
            lo.to_digit(16)
                .ok_or_else(|| DnError::InvalidHexValue(digits.clone()))?,
        );
        let byte = u8::try_from(hi.saturating_mul(16).saturating_add(lo))
            .map_err(|_| DnError::InvalidHexValue(digits.clone()))?;
        bytes.push(byte);
    }
    Ok(AttrValue::new(bytes))
}

/// An attribute type must be an RFC 4512 `descr` (letter, then letters,
/// digits and hyphens) or a `numericoid` (dot-separated numbers).
fn validate_attribute_type(attr: &str) -> Result<(), DnError> {
    if attr.is_empty() {
        return Err(DnError::EmptyAttributeType);
    }
    let mut chars = attr.chars();
    let first = chars.next().ok_or(DnError::EmptyAttributeType)?;

    if first.is_ascii_digit() {
        // numericoid: number *( "." number ), no empty arcs, no leading zeros
        // on a multi-digit arc.
        for arc in attr.split('.') {
            if arc.is_empty() || !arc.chars().all(|c| c.is_ascii_digit()) {
                return Err(DnError::InvalidAttributeType(attr.to_string()));
            }
            if arc.len() > 1 && arc.starts_with('0') {
                return Err(DnError::InvalidAttributeType(attr.to_string()));
            }
        }
        return Ok(());
    }

    if !first.is_ascii_alphabetic() {
        return Err(DnError::InvalidAttributeType(attr.to_string()));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(DnError::InvalidAttributeType(attr.to_string()));
    }
    Ok(())
}

/// Normalise an AVA value for comparison: case-fold and collapse whitespace
/// when the value is text, otherwise compare the octets as they stand.
fn normalise_value(value: &AttrValue) -> Vec<u8> {
    match value.as_str() {
        Some(s) => fold_whitespace(s).to_lowercase().into_bytes(),
        None => value.as_bytes().to_vec(),
    }
}

/// Render a value with RFC 4514 escaping.
fn escape_value(value: &AttrValue) -> String {
    let Some(text) = value.as_str() else {
        // Not text: emit the hex-string form, which is what `#`-values are for.
        let mut out = String::with_capacity(value.len().saturating_mul(2).saturating_add(1));
        out.push('#');
        for b in value.as_bytes() {
            out.push_str(&format!("{b:02X}"));
        }
        return out;
    };

    let mut out = String::with_capacity(text.len());
    let char_count = text.chars().count();
    for (i, c) in text.chars().enumerate() {
        let first = i == 0;
        let last = i.saturating_add(1) == char_count;
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '#' if first => out.push_str("\\#"),
            ' ' if first || last => out.push_str("\\ "),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let mut tmp = [0u8; 4];
                for b in c.encode_utf8(&mut tmp).as_bytes() {
                    out.push_str(&format!("\\{b:02X}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dn(s: &str) -> Dn {
        match Dn::parse(s) {
            Ok(d) => d,
            Err(e) => panic!("expected {s:?} to parse: {e}"),
        }
    }

    // -- parsing ------------------------------------------------------------

    /// Passing case: an ordinary DN parses into its RDNs, most specific first.
    #[test]
    fn parses_a_plain_dn() {
        let d = dn("cn=Bob Smith,ou=People,dc=example,dc=com");
        assert_eq!(d.len(), 4);
        assert_eq!(
            d.rdn().and_then(|r| r.get("cn")).map(ToString::to_string),
            Some("Bob Smith".to_string())
        );
        assert_eq!(d.to_string(), "cn=Bob Smith,ou=People,dc=example,dc=com");
    }

    /// Failing case: an RDN with no `=` is rejected rather than guessed at.
    #[test]
    fn rejects_an_rdn_without_a_value() {
        assert_eq!(
            Dn::parse("cn=Bob,People,dc=example"),
            Err(DnError::MissingEquals("People".to_string()))
        );
    }

    /// Failing case: an empty RDN between two commas is rejected.
    #[test]
    fn rejects_an_empty_rdn() {
        assert_eq!(Dn::parse("cn=Bob,,dc=example"), Err(DnError::EmptyRdn));
        assert_eq!(Dn::parse(",dc=example"), Err(DnError::EmptyRdn));
        // A missing *type* is a different, equally rejected mistake.
        assert_eq!(
            Dn::parse("=Bob,dc=example"),
            Err(DnError::EmptyAttributeType)
        );
    }

    /// Failing case: attribute types must be `descr` or `numericoid`.
    #[test]
    fn rejects_a_malformed_attribute_type() {
        assert_eq!(
            Dn::parse("c_n=Bob"),
            Err(DnError::InvalidAttributeType("c_n".to_string()))
        );
        assert_eq!(
            Dn::parse("1..2=Bob"),
            Err(DnError::InvalidAttributeType("1..2".to_string()))
        );
        // ...but a well-formed OID type is accepted.
        assert!(Dn::parse("2.5.4.3=Bob").is_ok());
    }

    /// Failing case: characters RFC 4514 reserves must be escaped. Accepting
    /// them silently is how two components disagree on where a DN ends.
    #[test]
    fn rejects_unescaped_reserved_characters() {
        assert_eq!(
            Dn::parse(r#"cn=Bo"b,dc=example"#),
            Err(DnError::UnescapedSpecial('"'))
        );
        assert_eq!(Dn::parse("cn=a<b"), Err(DnError::UnescapedSpecial('<')));
    }

    /// Failing case: a lone hex digit after `\` is ambiguous, so it is an
    /// error rather than a guess between `\4` and a truncated `\41`.
    #[test]
    fn rejects_a_truncated_hex_escape() {
        assert_eq!(
            Dn::parse("cn=a\\4z"),
            Err(DnError::InvalidEscape("4z".to_string()))
        );
        assert_eq!(Dn::parse("cn=a\\"), Err(DnError::TrailingEscape));
    }

    /// Failing case: `#`-prefixed values must be whole hex pairs.
    #[test]
    fn rejects_a_malformed_hex_value() {
        assert_eq!(
            Dn::parse("cn=#0"),
            Err(DnError::InvalidHexValue("#0".to_string()))
        );
    }

    /// Failing case: one attribute type may not appear twice in an RDN.
    #[test]
    fn rejects_a_duplicate_type_in_one_rdn() {
        assert_eq!(
            Dn::parse("cn=a+cn=b,dc=example"),
            Err(DnError::DuplicateAvaType("cn".to_string()))
        );
    }

    /// Passing case: escapes decode, and re-rendering re-escapes them.
    #[test]
    fn round_trips_escaped_values() {
        let d = dn(r"cn=Smith\, Bob,dc=example");
        assert_eq!(
            d.rdn().and_then(|r| r.get("cn")).map(ToString::to_string),
            Some("Smith, Bob".to_string())
        );
        assert_eq!(d.to_string(), r"cn=Smith\, Bob,dc=example");
        // Hex escapes decode to the same thing as the literal character.
        assert_eq!(dn(r"cn=Smith\2C Bob"), dn(r"cn=Smith\, Bob"));
    }

    /// Passing case: the empty DN is the root DSE, not an error.
    #[test]
    fn empty_dn_is_the_root_dse() {
        let d = dn("");
        assert!(d.is_empty());
        assert_eq!(d.to_string(), "");
        assert_eq!(d.parent(), None);
    }

    // -- normalisation and comparison ---------------------------------------

    /// Passing case: case and insignificant whitespace do not change identity.
    #[test]
    fn comparison_ignores_case_and_insignificant_space() {
        assert_eq!(
            dn("CN=Bob,OU=People,DC=Example,DC=COM"),
            dn("cn=bob,ou=people,dc=example,dc=com")
        );
        assert_eq!(dn("cn=Bob , ou=People"), dn("cn=bob,ou=people"));
        assert_eq!(dn("cn=Bob   Smith"), dn("cn=bob smith"));
    }

    /// Passing case: an escaped trailing space survives parsing and rendering,
    /// where an unescaped one is discarded as syntax.
    ///
    /// It does *not* survive comparison: RFC 4518's insignificant-space rule
    /// trims the ends of a value before `caseIgnoreMatch` looks at it, so
    /// `cn=Bob\ ` and `cn=Bob` name the same entry even though they are
    /// different strings. Both halves of that are asserted here because it is
    /// exactly the kind of asymmetry that gets "fixed" in the wrong direction.
    #[test]
    fn escaped_space_is_preserved_but_not_significant_for_comparison() {
        let escaped = dn(r"cn=Bob\ ");
        assert_eq!(
            escaped
                .rdn()
                .and_then(|r| r.get("cn"))
                .map(ToString::to_string),
            Some("Bob ".to_string()),
            "the space is part of the value"
        );
        assert_eq!(
            escaped.to_string(),
            r"cn=Bob\ ",
            "and is re-escaped on the way out"
        );
        assert_eq!(
            dn("cn=Bob   ").to_string(),
            "cn=Bob",
            "unescaped trailing space is syntax"
        );
        assert_eq!(escaped, dn("cn=Bob"), "but comparison folds it");
    }

    /// Passing case: an RDN is a set, so AVA order within it does not matter.
    #[test]
    fn multi_valued_rdn_is_order_independent() {
        assert_eq!(dn("cn=Bob+sn=Smith,dc=x"), dn("sn=Smith+cn=Bob,dc=x"));
        // ...but rendering preserves what the client wrote.
        assert_eq!(
            dn("sn=Smith+cn=Bob,dc=x").to_string(),
            "sn=Smith+cn=Bob,dc=x"
        );
    }

    /// Failing case: RDN *order* is structural and does matter.
    #[test]
    fn rdn_order_is_significant() {
        assert_ne!(dn("dc=com,dc=example"), dn("dc=example,dc=com"));
    }

    /// Validation: the normalised form is a stable map key that agrees with `==`.
    #[test]
    fn normalised_form_agrees_with_equality() {
        let a = dn("CN=Bob  Smith , OU=People, DC=Example, DC=Com");
        let b = dn("cn=bob smith,ou=people,dc=example,dc=com");
        assert_eq!(a, b);
        assert_eq!(a.normalised(), b.normalised());
        assert_eq!(a.normalised(), "cn=bob smith,ou=people,dc=example,dc=com");
    }

    // -- tree relationships -------------------------------------------------

    /// Passing case: parent, child and containment agree with each other.
    #[test]
    fn tree_relationships_hold() {
        let base = dn("dc=example,dc=com");
        let people = dn("ou=People,dc=example,dc=com");
        let bob = dn("cn=Bob,ou=People,dc=example,dc=com");

        assert_eq!(people.parent(), Some(base.clone()));
        assert!(people.is_child_of(&base));
        assert!(bob.is_within(&base));
        assert!(bob.is_strictly_within(&base));
        assert!(base.is_within(&base));
        assert!(!base.is_strictly_within(&base));
        assert_eq!(
            base.child(match Rdn::single("ou", "People") {
                Ok(r) => r,
                Err(e) => panic!("{e}"),
            }),
            people
        );
    }

    /// Failing case: containment is structural, not textual. A DN that shares
    /// a string suffix but not an RDN boundary is *not* inside the base.
    #[test]
    fn suffix_string_match_is_not_containment() {
        let base = dn("dc=example,dc=com");
        let impostor = dn("cn=evil,dc=notexample,dc=com");
        assert!(!impostor.is_within(&base));
        // The string form really does end with the base, which is why the
        // naive implementation of this check is wrong.
        assert!(impostor.to_string().ends_with("dc=com"));
        // And a grandchild is not an immediate child.
        assert!(!dn("cn=Bob,ou=People,dc=example,dc=com").is_child_of(&base));
    }

    /// Validation: every DN is within the empty DN, since the root DSE sits
    /// above all naming contexts.
    #[test]
    fn everything_is_within_the_root() {
        assert!(dn("cn=Bob,dc=example,dc=com").is_within(&Dn::empty()));
        assert!(!Dn::empty().is_within(&dn("dc=example,dc=com")));
    }

    /// Validation: the sort key orders a subtree contiguously, which is the
    /// property an ordered backend relies on to answer subtree searches with a
    /// range scan.
    #[test]
    fn sort_key_groups_subtrees_together() {
        let mut keys = [
            dn("cn=Bob,ou=People,dc=example,dc=com"),
            dn("dc=example,dc=com"),
            dn("cn=Zoe,ou=Groups,dc=example,dc=com"),
            dn("ou=People,dc=example,dc=com"),
            dn("dc=other,dc=com"),
        ]
        .map(|d| d.sort_key());
        keys.sort();
        assert_eq!(
            keys,
            [
                "dc=com,dc=example",
                "dc=com,dc=example,ou=groups,cn=zoe",
                "dc=com,dc=example,ou=people",
                "dc=com,dc=example,ou=people,cn=bob",
                // A sibling context sorts after the whole example.com subtree
                // rather than in the middle of it.
                "dc=com,dc=other",
            ]
            .map(str::to_string)
        );
        // Every descendant's key starts with the base's key plus a separator.
        let base = dn("dc=example,dc=com").sort_key();
        assert!(
            dn("cn=Bob,ou=People,dc=example,dc=com")
                .sort_key()
                .starts_with(&format!("{base},"))
        );
        // ...and a look-alike sibling context does not.
        assert!(
            !dn("cn=Eve,dc=notexample,dc=com")
                .sort_key()
                .starts_with(&format!("{base},"))
        );
    }

    /// Validation: control characters and reserved characters survive a
    /// render/parse round trip.
    #[test]
    fn escaping_round_trips_through_rendering() {
        for raw in [
            "plain",
            "with, comma",
            "with+plus",
            "with\\backslash",
            "with\"quote",
            " leading",
            "trailing ",
            "#hash",
            "new\nline",
        ] {
            let original = match Rdn::single("cn", raw) {
                Ok(r) => Dn::from_rdns(vec![r]),
                Err(e) => panic!("{e}"),
            };
            let rendered = original.to_string();
            let reparsed = dn(&rendered);
            assert_eq!(
                original, reparsed,
                "round trip failed for {raw:?} -> {rendered:?}"
            );
        }
    }
}
