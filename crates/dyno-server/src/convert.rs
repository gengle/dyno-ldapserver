//! Translation between the wire protocol and the domain types.
//!
//! This is the only module that knows both `ldap3_proto` and `dyno_core`.
//! Everything past it works in parsed DNs and typed filters, so a malformed
//! DN is rejected once, here, rather than being re-parsed and re-handled at
//! every layer.

use dyno_core::ops::{
    AddRequest, AttrSelection, CompareRequest, Modification, ModifyDnRequest, ModifyOp,
    ModifyRequest, SearchRequest,
};
use dyno_core::{AttrValue, Dn, DnError, Entry, Filter, MatchingRuleAssertion, Scope, Substring};
use ldap3_proto::proto::{
    LdapAddRequest, LdapCompareRequest, LdapFilter, LdapModifyDNRequest, LdapModifyRequest,
    LdapModifyType, LdapPartialAttribute, LdapResultCode, LdapSearchRequest, LdapSearchResultEntry,
    LdapSearchScope,
};
use thiserror::Error;

/// Why a request could not be turned into domain types.
///
/// Each variant carries the LDAP result code the client should see, so the
/// decision about how to report a malformed request is made once, next to the
/// code that detects it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertError {
    /// A DN in the request is not a valid DN.
    #[error("{field} {value:?} is not a valid DN: {source}")]
    InvalidDn {
        /// Which field of the request.
        field: &'static str,
        /// What the client sent.
        value: String,
        /// The parse failure.
        source: DnError,
    },

    /// A new RDN in a modifyDN request is not a single valid RDN.
    #[error("newrdn {value:?} is not a valid relative distinguished name")]
    InvalidRdn {
        /// What the client sent.
        value: String,
    },

    /// An attribute type in the request is empty or malformed.
    #[error("invalid attribute description {value:?}")]
    InvalidAttributeType {
        /// What the client sent.
        value: String,
    },

    /// The request is structurally well-formed but not something we can act
    /// on, e.g. an add with no attributes.
    #[error("{0}")]
    Malformed(String),
}

impl ConvertError {
    /// The LDAP result code to report.
    #[must_use]
    pub const fn result_code(&self) -> LdapResultCode {
        match self {
            Self::InvalidDn { .. } | Self::InvalidRdn { .. } => LdapResultCode::InvalidDNSyntax,
            Self::InvalidAttributeType { .. } => LdapResultCode::InvalidAttributeSyntax,
            Self::Malformed(_) => LdapResultCode::ProtocolError,
        }
    }
}

/// Parse a DN from a request field.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] naming the field, so the client's error message
/// says which DN was wrong.
pub fn parse_dn(field: &'static str, value: &str) -> Result<Dn, ConvertError> {
    Dn::parse(value).map_err(|source| ConvertError::InvalidDn {
        field,
        value: value.to_string(),
        source,
    })
}

/// Convert a protocol scope.
#[must_use]
pub const fn scope(s: &LdapSearchScope) -> Scope {
    match s {
        LdapSearchScope::Base => Scope::Base,
        LdapSearchScope::OneLevel => Scope::OneLevel,
        LdapSearchScope::Subtree => Scope::Subtree,
        LdapSearchScope::Children => Scope::Children,
    }
}

/// Convert a protocol filter into a domain filter.
///
/// Two normalisations happen here, both of which prevent a wrong answer later:
///
/// - A substring assertion with no components at all is a presence test.
///   Clients do send `(cn=*)` as an empty substring filter.
/// - An `Equality` assertion whose value is `*` is *not* special-cased: a
///   literal asterisk is a legitimate attribute value, and treating it as a
///   wildcard here would be a filter-injection bug.
#[must_use]
pub fn filter(f: &LdapFilter) -> Filter {
    match f {
        LdapFilter::And(subs) => Filter::And(subs.iter().map(filter).collect()),
        LdapFilter::Or(subs) => Filter::Or(subs.iter().map(filter).collect()),
        LdapFilter::Not(inner) => Filter::Not(Box::new(filter(inner))),
        LdapFilter::Equality(attr, value) => Filter::Equality {
            attr: attr.clone(),
            value: AttrValue::from(value.as_str()),
        },
        LdapFilter::Approx(attr, value) => Filter::Approx {
            attr: attr.clone(),
            value: AttrValue::from(value.as_str()),
        },
        LdapFilter::GreaterOrEqual(attr, value) => Filter::GreaterOrEqual {
            attr: attr.clone(),
            value: AttrValue::from(value.as_str()),
        },
        LdapFilter::LessOrEqual(attr, value) => Filter::LessOrEqual {
            attr: attr.clone(),
            value: AttrValue::from(value.as_str()),
        },
        LdapFilter::Present(attr) => Filter::Present(attr.clone()),
        LdapFilter::Substring(attr, sub) => {
            let pattern = Substring {
                initial: sub.initial.as_deref().map(AttrValue::from),
                any: sub
                    .any
                    .iter()
                    .map(|s| AttrValue::from(s.as_str()))
                    .collect(),
                final_: sub.final_.as_deref().map(AttrValue::from),
            };
            if pattern.is_unconstrained() {
                Filter::Present(attr.clone())
            } else {
                Filter::Substring {
                    attr: attr.clone(),
                    pattern,
                }
            }
        }
        LdapFilter::Extensible(a) => Filter::Extensible(MatchingRuleAssertion {
            matching_rule: a.matching_rule.clone(),
            attr: a.type_.clone(),
            value: AttrValue::from(a.match_value.as_str()),
            dn_attributes: a.dn_attributes,
        }),
    }
}

/// Limits the server imposes regardless of what the client asked for.
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits {
    /// Maximum entries per search.
    pub size_limit: usize,
    /// Maximum seconds per search.
    pub time_limit: u64,
}

/// Convert a search request, clamping the client's limits to the server's.
///
/// A client asking for more than the server allows gets the server's limit,
/// not an error: that is what RFC 4511 §4.5.1.4 describes, and it keeps one
/// client from monopolising the server by asking for everything.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] if the base object is not a valid DN.
pub fn search_request(
    req: &LdapSearchRequest,
    limits: ServerLimits,
) -> Result<SearchRequest, ConvertError> {
    let base = parse_dn("base object", &req.base)?;

    // Negative and zero limits both mean "no client limit" on the wire.
    let client_size = usize::try_from(req.sizelimit).ok().filter(|n| *n > 0);
    let size_limit = Some(match client_size {
        Some(n) => n.min(limits.size_limit),
        None => limits.size_limit,
    });

    let client_time = u64::try_from(req.timelimit).ok().filter(|n| *n > 0);
    let time_limit = Some(match client_time {
        Some(n) => n.min(limits.time_limit),
        None => limits.time_limit,
    });

    Ok(SearchRequest {
        base,
        scope: scope(&req.scope),
        filter: filter(&req.filter),
        attrs: AttrSelection::from_request(&req.attrs),
        size_limit,
        time_limit,
        types_only: req.typesonly,
    })
}

/// Convert a domain entry into a protocol search result entry.
///
/// `types_only` returns attribute names with no values, per RFC 4511
/// §4.5.1.6 — it must not return the values and let the client discard them.
#[must_use]
pub fn entry_to_proto(entry: &Entry, types_only: bool) -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn: entry.dn().to_string(),
        attributes: entry
            .attributes()
            .map(|a| LdapPartialAttribute {
                atype: a.name().to_string(),
                vals: if types_only {
                    Vec::new()
                } else {
                    a.values().iter().map(|v| v.as_bytes().to_vec()).collect()
                },
            })
            .collect(),
    }
}

/// Convert an add request.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] for a malformed DN,
/// [`ConvertError::InvalidAttributeType`] for an empty attribute name, and
/// [`ConvertError::Malformed`] for an attribute with no values — which is not
/// representable in a directory and would silently vanish.
pub fn add_request(req: &LdapAddRequest) -> Result<AddRequest, ConvertError> {
    let dn = parse_dn("entry", &req.dn)?;
    let mut entry = Entry::new(dn);
    for attr in &req.attributes {
        if attr.atype.trim().is_empty() {
            return Err(ConvertError::InvalidAttributeType {
                value: attr.atype.clone(),
            });
        }
        if attr.vals.is_empty() {
            return Err(ConvertError::Malformed(format!(
                "attribute {:?} in an add request has no values",
                attr.atype
            )));
        }
        let values: Vec<AttrValue> = attr
            .vals
            .iter()
            .map(|v| AttrValue::new(v.clone()))
            .collect();
        // A repeated attribute type in one add request accumulates rather than
        // overwriting; some clients split values across entries in the list.
        let mut merged = entry.values(&attr.atype).to_vec();
        merged.extend(values);
        entry.set(&attr.atype, merged);
    }
    Ok(AddRequest { entry })
}

/// Convert a modify request.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] or [`ConvertError::InvalidAttributeType`].
pub fn modify_request(req: &LdapModifyRequest) -> Result<ModifyRequest, ConvertError> {
    let dn = parse_dn("entry", &req.dn)?;
    let mut changes = Vec::with_capacity(req.changes.len());
    for change in &req.changes {
        if change.modification.atype.trim().is_empty() {
            return Err(ConvertError::InvalidAttributeType {
                value: change.modification.atype.clone(),
            });
        }
        changes.push(Modification {
            op: match change.operation {
                LdapModifyType::Add => ModifyOp::Add,
                LdapModifyType::Delete => ModifyOp::Delete,
                LdapModifyType::Replace => ModifyOp::Replace,
            },
            attr: change.modification.atype.clone(),
            values: change
                .modification
                .vals
                .iter()
                .map(|v| AttrValue::new(v.clone()))
                .collect(),
        });
    }
    Ok(ModifyRequest { dn, changes })
}

/// Convert a modifyDN request.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] for the entry or new superior, or
/// [`ConvertError::InvalidRdn`] if the new RDN is not exactly one RDN — a
/// `newrdn` of `cn=a,ou=b` is a client bug and must not be silently accepted
/// as a move.
pub fn modify_dn_request(req: &LdapModifyDNRequest) -> Result<ModifyDnRequest, ConvertError> {
    let dn = parse_dn("entry", &req.dn)?;
    let parsed = Dn::parse(&req.newrdn).map_err(|_| ConvertError::InvalidRdn {
        value: req.newrdn.clone(),
    })?;
    let new_rdn = match parsed.rdns() {
        [only] => only.clone(),
        _ => {
            return Err(ConvertError::InvalidRdn {
                value: req.newrdn.clone(),
            });
        }
    };
    let new_superior = match req.new_superior.as_deref() {
        Some(s) => Some(parse_dn("new superior", s)?),
        None => None,
    };
    Ok(ModifyDnRequest {
        dn,
        new_rdn,
        delete_old_rdn: req.deleteoldrdn,
        new_superior,
    })
}

/// Convert a compare request.
///
/// # Errors
///
/// [`ConvertError::InvalidDn`] or [`ConvertError::InvalidAttributeType`].
pub fn compare_request(req: &LdapCompareRequest) -> Result<CompareRequest, ConvertError> {
    if req.atype.trim().is_empty() {
        return Err(ConvertError::InvalidAttributeType {
            value: req.atype.clone(),
        });
    }
    Ok(CompareRequest {
        dn: parse_dn("entry", &req.dn)?,
        attr: req.atype.clone(),
        value: AttrValue::new(req.val.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::proto::{LdapMatchingRuleAssertion, LdapModify, LdapSubstringFilter};

    fn limits() -> ServerLimits {
        ServerLimits {
            size_limit: 100,
            time_limit: 30,
        }
    }

    fn search(base: &str, sizelimit: i32) -> LdapSearchRequest {
        LdapSearchRequest {
            base: base.to_string(),
            scope: LdapSearchScope::Subtree,
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".to_string()),
            attrs: vec![],
        }
    }

    /// Passing case: a well-formed search converts, and an unlimited client
    /// request picks up the server's limit.
    #[test]
    fn converts_a_search_request() {
        let req = search_request(&search("dc=example,dc=com", 0), limits()).unwrap();
        assert_eq!(req.base, Dn::parse("dc=example,dc=com").unwrap());
        assert_eq!(req.scope, Scope::Subtree);
        assert_eq!(req.size_limit, Some(100));
    }

    /// Failing case: a malformed base DN is rejected with `invalidDNSyntax`
    /// rather than being passed to the backend as a string.
    #[test]
    fn rejects_a_malformed_base_dn() {
        let err = search_request(&search("this is not a dn", 0), limits()).unwrap_err();
        assert_eq!(err.result_code(), LdapResultCode::InvalidDNSyntax);
    }

    /// Validation: a client may lower the server's limit but not raise it.
    #[test]
    fn client_size_limit_is_clamped_not_trusted() {
        assert_eq!(
            search_request(&search("dc=x", 5), limits())
                .unwrap()
                .size_limit,
            Some(5)
        );
        assert_eq!(
            search_request(&search("dc=x", 100_000), limits())
                .unwrap()
                .size_limit,
            Some(100),
            "a client must not be able to raise the server's limit"
        );
        assert_eq!(
            search_request(&search("dc=x", -1), limits())
                .unwrap()
                .size_limit,
            Some(100),
            "a negative limit is not a huge unsigned one"
        );
    }

    /// Validation: an empty substring assertion is a presence test, which is
    /// how clients encode `(cn=*)`.
    #[test]
    fn empty_substring_filter_becomes_presence() {
        let f = LdapFilter::Substring("cn".into(), LdapSubstringFilter::default());
        assert_eq!(filter(&f), Filter::Present("cn".into()));
    }

    /// Failing case: an equality assertion of `*` is a literal asterisk, not a
    /// wildcard. Treating it as one would be a filter-injection bug.
    #[test]
    fn literal_asterisk_is_not_a_wildcard() {
        let f = LdapFilter::Equality("cn".into(), "*".into());
        assert_eq!(
            filter(&f),
            Filter::Equality {
                attr: "cn".into(),
                value: "*".into()
            }
        );
    }

    /// Validation: extensible match components survive conversion.
    #[test]
    fn converts_an_extensible_match() {
        let f = LdapFilter::Extensible(LdapMatchingRuleAssertion {
            matching_rule: Some("caseExactMatch".into()),
            type_: Some("cn".into()),
            match_value: "Bob".into(),
            dn_attributes: true,
        });
        assert_eq!(
            filter(&f),
            Filter::Extensible(MatchingRuleAssertion {
                matching_rule: Some("caseExactMatch".into()),
                attr: Some("cn".into()),
                value: "Bob".into(),
                dn_attributes: true,
            })
        );
    }

    /// Passing case: an add request converts into an entry.
    #[test]
    fn converts_an_add_request() {
        let req = LdapAddRequest {
            dn: "cn=Bob,dc=example,dc=com".into(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".into(),
                    vals: vec![b"top".to_vec(), b"person".to_vec()],
                },
                LdapPartialAttribute {
                    atype: "cn".into(),
                    vals: vec![b"Bob".to_vec()],
                },
            ],
        };
        let converted = add_request(&req).unwrap();
        assert_eq!(converted.entry.values("objectClass").len(), 2);
        assert_eq!(converted.entry.first_str("cn"), Some("Bob"));
    }

    /// Failing case: an add carrying an attribute with no values is rejected.
    /// Accepting it would store an attribute that cannot exist.
    #[test]
    fn rejects_an_add_with_a_valueless_attribute() {
        let req = LdapAddRequest {
            dn: "cn=Bob,dc=example,dc=com".into(),
            attributes: vec![LdapPartialAttribute {
                atype: "cn".into(),
                vals: vec![],
            }],
        };
        assert!(matches!(
            add_request(&req).unwrap_err(),
            ConvertError::Malformed(_)
        ));
    }

    /// Failing case: `newrdn` must be one RDN. A full DN there is a client bug
    /// that would otherwise be silently reinterpreted as a move.
    #[test]
    fn rejects_a_multi_rdn_newrdn() {
        let req = LdapModifyDNRequest {
            dn: "cn=Bob,dc=example,dc=com".into(),
            newrdn: "cn=Robert,ou=People".into(),
            deleteoldrdn: true,
            new_superior: None,
        };
        assert_eq!(
            modify_dn_request(&req).unwrap_err(),
            ConvertError::InvalidRdn {
                value: "cn=Robert,ou=People".into()
            }
        );
    }

    /// Validation: `typesOnly` strips values on the way out rather than
    /// leaving the client to ignore them.
    #[test]
    fn types_only_omits_values() {
        let entry = Entry::new(Dn::parse("cn=Bob,dc=example,dc=com").unwrap())
            .with("cn", &["Bob"])
            .with("userPassword", &["secret"]);
        let proto = entry_to_proto(&entry, true);
        assert_eq!(proto.attributes.len(), 2);
        assert!(proto.attributes.iter().all(|a| a.vals.is_empty()));

        let with_values = entry_to_proto(&entry, false);
        assert!(with_values.attributes.iter().any(|a| !a.vals.is_empty()));
    }

    /// Validation: modify operations map to the right domain operation.
    #[test]
    fn converts_each_modify_operation() {
        let req = LdapModifyRequest {
            dn: "cn=Bob,dc=example,dc=com".into(),
            changes: vec![
                LdapModify {
                    operation: LdapModifyType::Add,
                    modification: LdapPartialAttribute {
                        atype: "mail".into(),
                        vals: vec![b"bob@example.com".to_vec()],
                    },
                },
                LdapModify {
                    operation: LdapModifyType::Delete,
                    modification: LdapPartialAttribute {
                        atype: "description".into(),
                        vals: vec![],
                    },
                },
            ],
        };
        let converted = modify_request(&req).unwrap();
        assert_eq!(converted.changes[0].op, ModifyOp::Add);
        assert_eq!(converted.changes[1].op, ModifyOp::Delete);
        assert!(converted.changes[1].values.is_empty());
    }
}
