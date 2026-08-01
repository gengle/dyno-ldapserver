//! Search filters and their evaluation.
//!
//! # Three-valued logic
//!
//! LDAP filters do not evaluate to a boolean. RFC 4511 §4.5.1.7 defines
//! `TRUE`, `FALSE` and `Undefined`, and the difference is observable: an entry
//! is returned only when the filter is `TRUE`, and `Not(Undefined)` is
//! `Undefined` rather than `TRUE`. Collapsing `Undefined` into `FALSE` early
//! means `(!(uidNumber>=abc))` returns every entry in the directory, which is
//! precisely the sort of accidental disclosure this server should not have.
//!
//! `Undefined` arises here when an assertion value does not conform to the
//! syntax its matching rule requires, or when a filter names a matching rule
//! we do not implement.

use crate::entry::Entry;
use crate::schema::{Key, MatchingRule, Schema};
use crate::value::AttrValue;

/// The result of evaluating a filter against an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// The entry matches and may be returned.
    True,
    /// The entry does not match.
    False,
    /// The filter could not be evaluated. Treated as "do not return" at the
    /// top level, but it does *not* negate to `True`.
    Undefined,
}

impl Match {
    /// Whether an entry with this result should be returned to the client.
    #[must_use]
    pub const fn is_true(self) -> bool {
        matches!(self, Self::True)
    }

    fn from_bool(b: bool) -> Self {
        if b { Self::True } else { Self::False }
    }

    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Undefined => Self::Undefined,
        }
    }
}

/// The three components of a substring assertion, e.g. `(cn=Bo*b*th)`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Substring {
    /// Anchored at the start.
    pub initial: Option<AttrValue>,
    /// Must appear in order, anywhere between `initial` and `final_`.
    pub any: Vec<AttrValue>,
    /// Anchored at the end. Named with a trailing underscore because `final`
    /// is a reserved word.
    pub final_: Option<AttrValue>,
}

impl Substring {
    /// Whether the assertion constrains nothing, i.e. `(cn=*)`. Such a filter
    /// is a presence test, and the decoder should have produced `Present`.
    #[must_use]
    pub fn is_unconstrained(&self) -> bool {
        self.initial.is_none() && self.any.is_empty() && self.final_.is_none()
    }
}

/// An extensible match assertion, `(attr:dn:rule:=value)` (RFC 4511 §4.5.1.7.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchingRuleAssertion {
    /// The named matching rule, if the client specified one.
    pub matching_rule: Option<String>,
    /// The attribute type, if the client specified one. When absent, the
    /// assertion is tried against every attribute of the entry.
    pub attr: Option<String>,
    /// The assertion value.
    pub value: AttrValue,
    /// When set, the values that make up the entry's DN are also considered.
    pub dn_attributes: bool,
}

/// A search filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Conjunction. An empty `And` is `TRUE` — it is the LDAP "absolute true"
    /// filter `(&)`.
    And(Vec<Filter>),
    /// Disjunction. An empty `Or` is `FALSE` — the "absolute false" filter `(|)`.
    Or(Vec<Filter>),
    /// Negation.
    Not(Box<Filter>),
    /// `(attr=value)`.
    Equality {
        /// Attribute type.
        attr: String,
        /// Assertion value.
        value: AttrValue,
    },
    /// `(attr=a*b*c)`.
    Substring {
        /// Attribute type.
        attr: String,
        /// The assertion components.
        pattern: Substring,
    },
    /// `(attr>=value)`.
    GreaterOrEqual {
        /// Attribute type.
        attr: String,
        /// Assertion value.
        value: AttrValue,
    },
    /// `(attr<=value)`.
    LessOrEqual {
        /// Attribute type.
        attr: String,
        /// Assertion value.
        value: AttrValue,
    },
    /// `(attr=*)`.
    Present(String),
    /// `(attr~=value)`. Evaluated as equality; see [`Filter::evaluate`].
    Approx {
        /// Attribute type.
        attr: String,
        /// Assertion value.
        value: AttrValue,
    },
    /// `(attr:rule:=value)`.
    Extensible(MatchingRuleAssertion),
}

impl Filter {
    /// Evaluate the filter against an entry.
    ///
    /// Notes on the semantics chosen where the RFC leaves room:
    ///
    /// - **Approximate match** (`~=`) is evaluated as equality. RFC 4511
    ///   leaves the algorithm to the implementation, and "exactly equal" is a
    ///   defensible approximation that never returns an entry a stricter
    ///   reading would exclude.
    /// - **Unknown attribute types** are `FALSE` rather than `Undefined`. The
    ///   schema is open by design (see [`Schema`]), so an unknown attribute is
    ///   simply an attribute this entry does not have.
    /// - **Unorderable syntaxes** make `>=` and `<=` `Undefined`, since
    ///   RFC 4517 defines no ordering rule for DN or boolean syntax.
    #[must_use]
    pub fn evaluate(&self, entry: &Entry, schema: &Schema) -> Match {
        match self {
            Self::And(subs) => {
                let mut result = Match::True;
                for sub in subs {
                    match sub.evaluate(entry, schema) {
                        // A single FALSE settles it, regardless of Undefined
                        // seen so far.
                        Match::False => return Match::False,
                        Match::Undefined => result = Match::Undefined,
                        Match::True => {}
                    }
                }
                result
            }
            Self::Or(subs) => {
                let mut result = Match::False;
                for sub in subs {
                    match sub.evaluate(entry, schema) {
                        Match::True => return Match::True,
                        Match::Undefined => result = Match::Undefined,
                        Match::False => {}
                    }
                }
                result
            }
            Self::Not(inner) => inner.evaluate(entry, schema).not(),
            Self::Present(attr) => Match::from_bool(entry.has(attr)),
            Self::Equality { attr, value } | Self::Approx { attr, value } => {
                equality(entry, attr, value, schema.equality_rule(attr))
            }
            Self::GreaterOrEqual { attr, value } => ordering(entry, schema, attr, value, true),
            Self::LessOrEqual { attr, value } => ordering(entry, schema, attr, value, false),
            Self::Substring { attr, pattern } => substring(entry, schema, attr, pattern),
            Self::Extensible(assertion) => extensible(entry, schema, assertion),
        }
    }

    /// Every attribute type this filter mentions. Used to validate rules and
    /// to decide what a backend must be able to index on.
    #[must_use]
    pub fn attributes(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_attributes(&mut out);
        out
    }

    fn collect_attributes<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::And(subs) | Self::Or(subs) => {
                for s in subs {
                    s.collect_attributes(out);
                }
            }
            Self::Not(inner) => inner.collect_attributes(out),
            Self::Present(attr) => out.push(attr),
            Self::Equality { attr, .. }
            | Self::Approx { attr, .. }
            | Self::GreaterOrEqual { attr, .. }
            | Self::LessOrEqual { attr, .. }
            | Self::Substring { attr, .. } => out.push(attr),
            Self::Extensible(a) => {
                if let Some(attr) = a.attr.as_deref() {
                    out.push(attr);
                }
            }
        }
    }
}

fn equality(entry: &Entry, attr: &str, value: &AttrValue, rule: MatchingRule) -> Match {
    let Ok(assertion) = rule.normalise(value) else {
        // The client's assertion value is not valid for this syntax.
        return Match::Undefined;
    };
    let values = entry.values(attr);
    if values.is_empty() {
        return Match::False;
    }
    for v in values {
        if rule.normalise(v).ok().is_some_and(|k| k == assertion) {
            return Match::True;
        }
    }
    Match::False
}

fn ordering(entry: &Entry, schema: &Schema, attr: &str, value: &AttrValue, greater: bool) -> Match {
    let rule = schema.equality_rule(attr);
    if !rule.supports_ordering() {
        return Match::Undefined;
    }
    let Ok(assertion) = rule.normalise(value) else {
        return Match::Undefined;
    };
    let values = entry.values(attr);
    if values.is_empty() {
        return Match::False;
    }
    for v in values {
        let Ok(k) = rule.normalise(v) else { continue };
        let hit = if greater {
            k >= assertion
        } else {
            k <= assertion
        };
        if hit {
            return Match::True;
        }
    }
    Match::False
}

fn substring(entry: &Entry, schema: &Schema, attr: &str, pattern: &Substring) -> Match {
    let rule = schema.equality_rule(attr);
    if !rule.supports_substring() {
        return Match::Undefined;
    }
    if pattern.is_unconstrained() {
        // `(attr=*)` in substring clothing: a presence test.
        return Match::from_bool(entry.has(attr));
    }

    // Normalise the assertion components with the same rule as the values, so
    // that case folding applies to both sides.
    let normalise = |v: &AttrValue| -> Option<Vec<u8>> {
        rule.normalise(v).ok().and_then(|k| match k {
            Key::Text(s) => Some(s.into_bytes()),
            Key::Bytes(b) => Some(b),
            Key::Int(_) => None,
        })
    };

    let mut initial = None;
    if let Some(v) = pattern.initial.as_ref() {
        match normalise(v) {
            Some(b) => initial = Some(b),
            None => return Match::Undefined,
        }
    }
    let mut final_ = None;
    if let Some(v) = pattern.final_.as_ref() {
        match normalise(v) {
            Some(b) => final_ = Some(b),
            None => return Match::Undefined,
        }
    }
    let mut anys = Vec::with_capacity(pattern.any.len());
    for v in &pattern.any {
        match normalise(v) {
            Some(b) => anys.push(b),
            None => return Match::Undefined,
        }
    }

    let values = entry.values(attr);
    if values.is_empty() {
        return Match::False;
    }
    for v in values {
        let Some(hay) = normalise(v) else { continue };
        if substring_matches(&hay, initial.as_deref(), &anys, final_.as_deref()) {
            return Match::True;
        }
    }
    Match::False
}

/// `initial`, then each `any` in order, then `final_`, with no overlap.
fn substring_matches(
    hay: &[u8],
    initial: Option<&[u8]>,
    anys: &[Vec<u8>],
    final_: Option<&[u8]>,
) -> bool {
    let mut cursor = 0usize;

    if let Some(prefix) = initial {
        if !hay.starts_with(prefix) {
            return false;
        }
        cursor = prefix.len();
    }

    let end = match final_ {
        Some(suffix) => {
            if !hay.ends_with(suffix) {
                return false;
            }
            let end = hay.len().saturating_sub(suffix.len());
            if end < cursor {
                // initial and final overlap: not a match
                return false;
            }
            end
        }
        None => hay.len(),
    };

    // Greedy left-to-right search for the `any` fragments in the region
    // between the anchors. Greedy is correct here because the fragments have
    // no wildcards of their own.
    for fragment in anys {
        if fragment.is_empty() {
            continue;
        }
        let Some(region) = hay.get(cursor..end) else {
            return false;
        };
        match find_subslice(region, fragment) {
            Some(pos) => {
                cursor = cursor.saturating_add(pos).saturating_add(fragment.len());
            }
            None => return false,
        }
    }
    true
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn extensible(entry: &Entry, schema: &Schema, assertion: &MatchingRuleAssertion) -> Match {
    // An unrecognised matching rule is Undefined, not an error and not false.
    let explicit_rule = match assertion.matching_rule.as_deref() {
        Some(name) => match MatchingRule::from_name(name) {
            Some(rule) => Some(rule),
            None => return Match::Undefined,
        },
        None => None,
    };

    let mut result = Match::False;

    let mut consider = |attr: &str| -> Option<Match> {
        let rule = explicit_rule.unwrap_or_else(|| schema.equality_rule(attr));
        match equality(entry, attr, &assertion.value, rule) {
            Match::True => Some(Match::True),
            Match::Undefined => {
                result = Match::Undefined;
                None
            }
            Match::False => None,
        }
    };

    match assertion.attr.as_deref() {
        Some(attr) => {
            if let Some(m) = consider(attr) {
                return m;
            }
        }
        None => {
            // No attribute named: try them all.
            for a in entry.attributes() {
                if let Some(m) = consider(a.name()) {
                    return m;
                }
            }
        }
    }

    if assertion.dn_attributes {
        // `:dn:` — also consider the AVAs that make up the entry's DN.
        for rdn in entry.dn().rdns() {
            for ava in rdn.avas() {
                if assertion
                    .attr
                    .as_deref()
                    .is_some_and(|a| !a.eq_ignore_ascii_case(ava.attr()))
                {
                    continue;
                }
                let rule = explicit_rule.unwrap_or_else(|| schema.equality_rule(ava.attr()));
                let (Ok(a), Ok(b)) = (
                    rule.normalise(ava.value()),
                    rule.normalise(&assertion.value),
                ) else {
                    result = Match::Undefined;
                    continue;
                };
                if a == b {
                    return Match::True;
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dn::Dn;

    fn entry() -> Entry {
        Entry::new(
            match Dn::parse("cn=Bob Smith,ou=People,dc=example,dc=com") {
                Ok(d) => d,
                Err(e) => panic!("{e}"),
            },
        )
        .with("objectClass", &["top", "person", "inetOrgPerson"])
        .with("cn", &["Bob Smith"])
        .with("sn", &["Smith"])
        .with("uid", &["bsmith"])
        .with("uidNumber", &["1010"])
        .with("mail", &["bob@example.com"])
        .with("userPassword", &["Secret"])
        .with("member", &["cn=Alice,ou=People,dc=example,dc=com"])
    }

    fn eq(attr: &str, value: &str) -> Filter {
        Filter::Equality {
            attr: attr.to_string(),
            value: value.into(),
        }
    }

    fn evaluate(f: &Filter) -> Match {
        f.evaluate(&entry(), &Schema::builtin())
    }

    // -- equality -----------------------------------------------------------

    /// Passing case: equality matches under the attribute's matching rule, so
    /// case and insignificant whitespace do not defeat it.
    #[test]
    fn equality_matches_case_insensitively() {
        assert_eq!(evaluate(&eq("cn", "bob   smith")), Match::True);
        assert_eq!(evaluate(&eq("UID", "BSMITH")), Match::True);
    }

    /// Failing case: a value that is genuinely different does not match, and
    /// neither does an attribute the entry does not have.
    #[test]
    fn equality_rejects_non_matching_and_absent() {
        assert_eq!(evaluate(&eq("cn", "Alice")), Match::False);
        assert_eq!(evaluate(&eq("telephoneNumber", "555")), Match::False);
        // userPassword is octet-matched: case matters here even though it did
        // not for cn.
        assert_eq!(evaluate(&eq("userPassword", "secret")), Match::False);
        assert_eq!(evaluate(&eq("userPassword", "Secret")), Match::True);
    }

    /// Passing case: DN-valued attributes match structurally.
    #[test]
    fn dn_valued_equality_is_structural() {
        assert_eq!(
            evaluate(&eq("member", "CN=alice, OU=people, DC=example, DC=com")),
            Match::True
        );
    }

    /// Failing case: an assertion value that is not a DN makes the component
    /// Undefined, and — critically — negating it does not turn it True.
    #[test]
    fn invalid_assertion_syntax_is_undefined_and_stays_undefined() {
        let bad = eq("member", "this is not a dn");
        assert_eq!(evaluate(&bad), Match::Undefined);
        assert_eq!(evaluate(&Filter::Not(Box::new(bad))), Match::Undefined);
    }

    // -- presence -----------------------------------------------------------

    /// Passing and failing pair for presence.
    #[test]
    fn presence_tracks_whether_the_attribute_exists() {
        assert_eq!(evaluate(&Filter::Present("mail".into())), Match::True);
        assert_eq!(
            evaluate(&Filter::Present("telephoneNumber".into())),
            Match::False
        );
        assert_eq!(
            evaluate(&Filter::Not(Box::new(Filter::Present(
                "telephoneNumber".into()
            )))),
            Match::True
        );
    }

    // -- substring ----------------------------------------------------------

    fn substr(attr: &str, initial: Option<&str>, any: &[&str], final_: Option<&str>) -> Filter {
        Filter::Substring {
            attr: attr.to_string(),
            pattern: Substring {
                initial: initial.map(AttrValue::from),
                any: any.iter().map(|s| AttrValue::from(*s)).collect(),
                final_: final_.map(AttrValue::from),
            },
        }
    }

    /// Passing case: anchors and interior fragments all match, case-insensitively.
    #[test]
    fn substring_matches_anchors_and_fragments() {
        assert_eq!(evaluate(&substr("cn", Some("bob"), &[], None)), Match::True);
        assert_eq!(
            evaluate(&substr("cn", None, &[], Some("SMITH"))),
            Match::True
        );
        assert_eq!(evaluate(&substr("cn", None, &["b s"], None)), Match::True);
        assert_eq!(
            evaluate(&substr("mail", Some("bob"), &["@"], Some(".com"))),
            Match::True
        );
    }

    /// Failing case: fragments must appear in order and must not overlap the
    /// anchors — the two mistakes a naive `contains` loop makes.
    #[test]
    fn substring_requires_ordered_non_overlapping_fragments() {
        // "smith" then "bob" is the wrong order.
        assert_eq!(
            evaluate(&substr("cn", None, &["smith", "bob"], None)),
            Match::False
        );
        // initial and final that would have to share characters.
        assert_eq!(
            evaluate(&substr("uid", Some("bsmi"), &[], Some("mith"))),
            Match::False
        );
        // a fragment that simply is not there
        assert_eq!(evaluate(&substr("cn", None, &["zzz"], None)), Match::False);
    }

    /// Failing case: substring assertions are Undefined for syntaxes that have
    /// no substring rule, rather than silently comparing text.
    #[test]
    fn substring_on_a_dn_syntax_is_undefined() {
        assert_eq!(
            evaluate(&substr("member", Some("cn=al"), &[], None)),
            Match::Undefined
        );
    }

    // -- ordering -----------------------------------------------------------

    /// Passing case: integer attributes order numerically.
    #[test]
    fn ordering_on_integers_is_numeric() {
        assert_eq!(
            evaluate(&Filter::GreaterOrEqual {
                attr: "uidNumber".into(),
                value: "999".into()
            }),
            Match::True,
            "1010 >= 999 numerically"
        );
        assert_eq!(
            evaluate(&Filter::LessOrEqual {
                attr: "uidNumber".into(),
                value: "999".into()
            }),
            Match::False
        );
    }

    /// Failing case: an unorderable syntax or an unparseable assertion is
    /// Undefined, so `(!(uidNumber>=abc))` does not return the whole directory.
    #[test]
    fn ordering_is_undefined_where_no_ordering_exists() {
        assert_eq!(
            evaluate(&Filter::GreaterOrEqual {
                attr: "uidNumber".into(),
                value: "abc".into()
            }),
            Match::Undefined
        );
        assert_eq!(
            evaluate(&Filter::GreaterOrEqual {
                attr: "member".into(),
                value: "cn=alice,dc=example,dc=com".into()
            }),
            Match::Undefined
        );
    }

    // -- boolean combination ------------------------------------------------

    /// Passing case: the empty `And` is the absolute-true filter `(&)`, which
    /// is what clients send to mean "everything".
    #[test]
    fn empty_and_is_true_and_empty_or_is_false() {
        assert_eq!(evaluate(&Filter::And(vec![])), Match::True);
        assert_eq!(evaluate(&Filter::Or(vec![])), Match::False);
    }

    /// Validation: RFC 4511 §4.5.1.7 truth tables for Undefined.
    #[test]
    fn undefined_propagates_per_rfc_truth_tables() {
        let undef = eq("member", "not a dn");
        let yes = eq("cn", "Bob Smith");
        let no = eq("cn", "Alice");

        // AND: FALSE beats Undefined; TRUE does not.
        assert_eq!(
            evaluate(&Filter::And(vec![undef.clone(), no.clone()])),
            Match::False
        );
        assert_eq!(
            evaluate(&Filter::And(vec![undef.clone(), yes.clone()])),
            Match::Undefined
        );
        // OR: TRUE beats Undefined; FALSE does not.
        assert_eq!(evaluate(&Filter::Or(vec![undef.clone(), yes])), Match::True);
        assert_eq!(evaluate(&Filter::Or(vec![undef, no])), Match::Undefined);
    }

    // -- extensible match ---------------------------------------------------

    /// Passing case: an extensible match with an explicit rule overrides the
    /// schema's rule for that attribute.
    #[test]
    fn extensible_match_uses_the_named_rule() {
        // cn is normally case-insensitive; ask for case-exact and it still
        // matches the exact spelling...
        assert_eq!(
            evaluate(&Filter::Extensible(MatchingRuleAssertion {
                matching_rule: Some("caseExactMatch".into()),
                attr: Some("cn".into()),
                value: "Bob Smith".into(),
                dn_attributes: false,
            })),
            Match::True
        );
    }

    /// Failing case: ...but not a differently-cased one, and an unknown rule
    /// is Undefined rather than an error.
    #[test]
    fn extensible_match_rejects_wrong_case_and_unknown_rules() {
        assert_eq!(
            evaluate(&Filter::Extensible(MatchingRuleAssertion {
                matching_rule: Some("caseExactMatch".into()),
                attr: Some("cn".into()),
                value: "bob smith".into(),
                dn_attributes: false,
            })),
            Match::False
        );
        assert_eq!(
            evaluate(&Filter::Extensible(MatchingRuleAssertion {
                matching_rule: Some("noSuchMatchingRule".into()),
                attr: Some("cn".into()),
                value: "Bob Smith".into(),
                dn_attributes: false,
            })),
            Match::Undefined
        );
    }

    /// Validation: `:dn:` also considers the AVAs in the entry's own DN.
    #[test]
    fn extensible_match_can_search_dn_components() {
        assert_eq!(
            evaluate(&Filter::Extensible(MatchingRuleAssertion {
                matching_rule: None,
                attr: Some("ou".into()),
                value: "People".into(),
                dn_attributes: true,
            })),
            Match::True,
            "ou=People appears in the DN but not in the entry's attributes"
        );
        assert_eq!(
            evaluate(&Filter::Extensible(MatchingRuleAssertion {
                matching_rule: None,
                attr: Some("ou".into()),
                value: "People".into(),
                dn_attributes: false,
            })),
            Match::False
        );
    }

    /// Validation: the attribute list a filter touches is reported for
    /// load-time validation of rules and for backend indexing.
    #[test]
    fn reports_referenced_attributes() {
        let f = Filter::And(vec![
            eq("cn", "x"),
            Filter::Not(Box::new(Filter::Present("mail".into()))),
        ]);
        assert_eq!(f.attributes(), vec!["cn", "mail"]);
    }
}
