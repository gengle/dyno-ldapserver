//! LDIF parsing and a read-only backend over an LDIF file.
//!
//! Only *content* records are supported (RFC 2849 §1), which is what a
//! directory fixture is. Change records (`changetype: add`) describe an
//! operation rather than a state, and quietly treating one as an entry would
//! load a directory that does not match the file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use dyno_core::ops::SearchRequest;
use dyno_core::{AttrValue, Dn, Entry, Schema};
use thiserror::Error;

use crate::error::BackendError;
use crate::memory::MemoryBackend;
use crate::{Backend, BindOutcome, Result};

/// Why an LDIF document could not be read.
///
/// Every variant names the line it happened on, because an LDIF fixture is
/// usually hand-written and "parse error" without a location is useless.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LdifError {
    /// A record did not start with a `dn:` line.
    #[error("line {line}: record does not begin with a 'dn:' line")]
    MissingDn {
        /// 1-based line number.
        line: usize,
    },

    /// The DN on a `dn:` line could not be parsed.
    #[error("line {line}: invalid DN: {source}")]
    InvalidDn {
        /// 1-based line number.
        line: usize,
        /// The underlying parse failure.
        source: dyno_core::DnError,
    },

    /// A line was neither a comment, a separator, nor `name: value`.
    #[error("line {line}: expected 'attribute: value', found {content:?}")]
    MalformedLine {
        /// 1-based line number.
        line: usize,
        /// The offending line.
        content: String,
    },

    /// A `::` value was not valid base64.
    #[error("line {line}: invalid base64 value for attribute {attr:?}")]
    InvalidBase64 {
        /// 1-based line number.
        line: usize,
        /// The attribute whose value failed to decode.
        attr: String,
    },

    /// A `:<` URL-valued attribute was found. Fetching a URL while loading a
    /// directory is an I/O operation we deliberately do not perform.
    #[error("line {line}: URL-valued attributes ('{attr}:<') are not supported")]
    UrlValue {
        /// 1-based line number.
        line: usize,
        /// The attribute.
        attr: String,
    },

    /// A change record was found where a content record was expected.
    #[error(
        "line {line}: change records ('changetype:') are not supported; expected a directory snapshot"
    )]
    ChangeRecord {
        /// 1-based line number.
        line: usize,
    },

    /// A continuation line appeared before any attribute line.
    #[error("line {line}: continuation line with nothing to continue")]
    DanglingContinuation {
        /// 1-based line number.
        line: usize,
    },

    /// Two records in the same document share a DN.
    #[error("line {line}: duplicate entry {dn}")]
    DuplicateEntry {
        /// 1-based line number.
        line: usize,
        /// The repeated DN.
        dn: String,
    },

    /// The file could not be read.
    #[error("cannot read {path}: {message}")]
    Io {
        /// The path.
        path: String,
        /// The OS error text.
        message: String,
    },
}

/// One logical line: text with the line number it started on.
struct LogicalLine {
    number: usize,
    text: String,
}

/// Join RFC 2849 continuation lines (a leading single space) and drop
/// comments and the `version:` header.
fn unfold(input: &str) -> std::result::Result<Vec<LogicalLine>, LdifError> {
    let mut out: Vec<LogicalLine> = Vec::new();
    for (idx, raw) in input.lines().enumerate() {
        let number = idx.saturating_add(1);
        // A comment can itself be continued, so it must be dropped before
        // unfolding, not after.
        if raw.starts_with('#') {
            continue;
        }
        if let Some(rest) = raw.strip_prefix(' ') {
            match out.last_mut() {
                Some(last) if !last.text.is_empty() => last.text.push_str(rest),
                _ => return Err(LdifError::DanglingContinuation { line: number }),
            }
        } else {
            out.push(LogicalLine {
                number,
                text: raw.trim_end_matches('\r').to_string(),
            });
        }
    }
    Ok(out)
}

/// Split `attr: value`, `attr:: base64` or `attr:< url`.
fn split_line(line: &LogicalLine) -> std::result::Result<(String, AttrValue), LdifError> {
    let Some(colon) = line.text.find(':') else {
        return Err(LdifError::MalformedLine {
            line: line.number,
            content: line.text.clone(),
        });
    };
    let (attr, rest) = line.text.split_at(colon);
    let attr = attr.trim().to_string();
    if attr.is_empty() {
        return Err(LdifError::MalformedLine {
            line: line.number,
            content: line.text.clone(),
        });
    }
    // `rest` starts with the ':' we found.
    let rest = rest.get(1..).unwrap_or_default();

    if let Some(b64) = rest.strip_prefix(':') {
        let decoded = BASE64
            .decode(b64.trim())
            .map_err(|_| LdifError::InvalidBase64 {
                line: line.number,
                attr: attr.clone(),
            })?;
        return Ok((attr, AttrValue::new(decoded)));
    }
    if rest.starts_with('<') {
        return Err(LdifError::UrlValue {
            line: line.number,
            attr,
        });
    }
    Ok((attr, AttrValue::from(rest.trim_start_matches(' '))))
}

/// Parse an LDIF document into entries.
///
/// # Errors
///
/// Returns the first [`LdifError`] encountered, with its line number.
pub fn parse_ldif(input: &str) -> std::result::Result<Vec<Entry>, LdifError> {
    let lines = unfold(input)?;
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut current: Option<Entry> = None;
    let mut record_start = 1usize;

    for line in &lines {
        if line.text.trim().is_empty() {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            continue;
        }

        let (attr, value) = split_line(line)?;

        if attr.eq_ignore_ascii_case("version") && current.is_none() {
            continue;
        }
        if attr.eq_ignore_ascii_case("changetype") {
            return Err(LdifError::ChangeRecord { line: line.number });
        }

        match current.as_mut() {
            None => {
                if !attr.eq_ignore_ascii_case("dn") {
                    return Err(LdifError::MissingDn { line: line.number });
                }
                let text = value.to_string_lossy().to_string();
                let dn = Dn::parse(&text).map_err(|source| LdifError::InvalidDn {
                    line: line.number,
                    source,
                })?;
                let key = dn.normalised();
                if seen.contains(&key) {
                    return Err(LdifError::DuplicateEntry {
                        line: line.number,
                        dn: text,
                    });
                }
                seen.push(key);
                record_start = line.number;
                current = Some(Entry::new(dn));
            }
            Some(entry) => {
                if attr.eq_ignore_ascii_case("dn") {
                    // A second dn: line means the previous record was never
                    // terminated by a blank line. Treat it as a new record.
                    entries.push(std::mem::replace(entry, Entry::new(Dn::empty())));
                    let text = value.to_string_lossy().to_string();
                    let dn = Dn::parse(&text).map_err(|source| LdifError::InvalidDn {
                        line: line.number,
                        source,
                    })?;
                    let key = dn.normalised();
                    if seen.contains(&key) {
                        return Err(LdifError::DuplicateEntry {
                            line: line.number,
                            dn: text,
                        });
                    }
                    seen.push(key);
                    record_start = line.number;
                    *entry = Entry::new(dn);
                } else {
                    let mut values = entry.values(&attr).to_vec();
                    values.push(value);
                    entry.set(&attr, values);
                }
            }
        }
    }

    if let Some(entry) = current.take() {
        if entry.is_empty() {
            return Err(LdifError::MissingDn { line: record_start });
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// A read-only directory loaded from an LDIF file.
///
/// Reads are delegated to a [`MemoryBackend`]; writes are not delegated at
/// all, so they take the trait's default refusal.
#[derive(Debug)]
pub struct LdifBackend {
    path: PathBuf,
    inner: MemoryBackend,
}

impl LdifBackend {
    /// Load an LDIF file.
    ///
    /// # Errors
    ///
    /// Returns [`LdifError::Io`] if the file cannot be read, or a parse error
    /// with the offending line number.
    pub fn load(
        path: impl AsRef<Path>,
        schema: Arc<Schema>,
    ) -> std::result::Result<Self, LdifError> {
        let path = path.as_ref().to_path_buf();
        let text = std::fs::read_to_string(&path).map_err(|e| LdifError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Self::from_str_with_path(&text, path, schema)
    }

    /// Load LDIF from a string, e.g. from a config file or a test.
    ///
    /// # Errors
    ///
    /// As [`parse_ldif`], plus [`LdifError::DuplicateEntry`] if two entries
    /// collide once normalised.
    pub fn from_ldif(text: &str, schema: Arc<Schema>) -> std::result::Result<Self, LdifError> {
        Self::from_str_with_path(text, PathBuf::from("<inline>"), schema)
    }

    fn from_str_with_path(
        text: &str,
        path: PathBuf,
        schema: Arc<Schema>,
    ) -> std::result::Result<Self, LdifError> {
        let entries = parse_ldif(text)?;
        let inner = MemoryBackend::from_entries("ldif", entries, schema).map_err(|_| {
            LdifError::DuplicateEntry {
                line: 0,
                dn: "<duplicate after normalisation>".to_string(),
            }
        })?;
        Ok(Self { path, inner })
    }

    /// The file this backend was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl Backend for LdifBackend {
    fn name(&self) -> &str {
        "ldif"
    }

    fn schema(&self) -> &Arc<Schema> {
        self.inner.schema()
    }

    fn naming_contexts(&self) -> Vec<Dn> {
        self.inner.naming_contexts()
    }

    async fn search(&self, req: &SearchRequest) -> Result<Vec<Entry>> {
        self.inner.search(req).await
    }

    async fn closest_ancestor(&self, dn: &Dn) -> Result<Option<Dn>> {
        self.inner.closest_ancestor(dn).await
    }

    async fn bind(&self, dn: &Dn, password: &[u8]) -> Result<BindOutcome> {
        self.inner.bind(dn, password).await
    }

    // Writes deliberately fall through to the trait defaults, which refuse
    // with `unwillingToPerform`. See the module docs.
}

impl From<LdifError> for BackendError {
    fn from(e: LdifError) -> Self {
        Self::Internal(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dyno_core::ops::AddRequest;

    const SAMPLE: &str = "\
version: 1
# a comment, which may itself be folded
#  like this

dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: cn=Bob Smith,dc=example,dc=com
objectClass: top
objectClass: person
cn: Bob Smith
sn: Smith
description: a description that is long enough to need
  folding across two lines
userPassword:: aHVudGVyMg==
";

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::builtin())
    }

    /// Passing case: a well-formed document parses, including multi-valued
    /// attributes, folded lines and base64 values.
    #[test]
    fn parses_a_well_formed_document() {
        let entries = parse_ldif(SAMPLE).unwrap();
        assert_eq!(entries.len(), 2);

        let bob = &entries[1];
        assert_eq!(bob.dn().to_string(), "cn=Bob Smith,dc=example,dc=com");
        assert_eq!(bob.values("objectClass").len(), 2);
        assert_eq!(
            bob.first_str("description"),
            Some("a description that is long enough to need folding across two lines"),
            "continuation lines join without a separator"
        );
        assert_eq!(
            bob.first_str("userPassword"),
            Some("hunter2"),
            "base64 values decode"
        );
    }

    /// Failing case: a record that does not start with `dn:` is rejected with
    /// its line number rather than silently skipped.
    #[test]
    fn rejects_a_record_without_a_dn() {
        let err = parse_ldif("objectClass: top\ncn: Bob\n").unwrap_err();
        assert_eq!(err, LdifError::MissingDn { line: 1 });
    }

    /// Failing case: an unparseable DN is reported with the line and the
    /// underlying DN error.
    #[test]
    fn rejects_an_invalid_dn() {
        let err = parse_ldif("dn: this is not a dn\ncn: x\n").unwrap_err();
        assert!(matches!(err, LdifError::InvalidDn { line: 1, .. }), "{err}");
    }

    /// Failing case: base64 that does not decode is an error, not an empty
    /// value — a truncated password hash must not load as a blank one.
    #[test]
    fn rejects_invalid_base64() {
        let err = parse_ldif("dn: cn=x\nuserPassword:: !!!not base64!!!\n").unwrap_err();
        assert_eq!(
            err,
            LdifError::InvalidBase64 {
                line: 2,
                attr: "userPassword".into()
            }
        );
    }

    /// Failing case: change records describe operations, not state. Loading
    /// one as if it were an entry would produce a directory that does not
    /// match the file.
    #[test]
    fn rejects_change_records() {
        let ldif = "dn: cn=x,dc=example,dc=com\nchangetype: add\nobjectClass: top\n";
        assert_eq!(
            parse_ldif(ldif).unwrap_err(),
            LdifError::ChangeRecord { line: 2 }
        );
    }

    /// Failing case: URL-valued attributes would make loading a fixture
    /// perform network or file I/O.
    #[test]
    fn rejects_url_valued_attributes() {
        let ldif = "dn: cn=x,dc=example,dc=com\njpegPhoto:< file:///etc/passwd\n";
        assert_eq!(
            parse_ldif(ldif).unwrap_err(),
            LdifError::UrlValue {
                line: 2,
                attr: "jpegPhoto".into()
            }
        );
    }

    /// Failing case: two records naming the same entry — even spelled
    /// differently — is a mistake in the fixture, not a silent overwrite.
    #[test]
    fn rejects_duplicate_entries() {
        let ldif = "dn: cn=Bob,dc=example,dc=com\nobjectClass: top\n\n\
                    dn: CN=bob, dc=example, dc=com\nobjectClass: top\n";
        assert!(matches!(
            parse_ldif(ldif).unwrap_err(),
            LdifError::DuplicateEntry { .. }
        ));
    }

    /// Failing case: a continuation line with nothing to continue.
    #[test]
    fn rejects_a_dangling_continuation() {
        let err = parse_ldif(" oops\n").unwrap_err();
        assert_eq!(err, LdifError::DanglingContinuation { line: 1 });
    }

    /// Passing case: the LDIF backend answers searches.
    #[tokio::test]
    async fn ldif_backend_serves_reads() {
        let b = LdifBackend::from_ldif(SAMPLE, schema()).unwrap();
        let found = b
            .search(&SearchRequest::subtree(
                Dn::parse("dc=example,dc=com").unwrap(),
                dyno_core::Filter::Present("objectClass".into()),
            ))
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(
            b.naming_contexts(),
            vec![Dn::parse("dc=example,dc=com").unwrap()]
        );
    }

    /// Failing case: the LDIF backend refuses writes with
    /// `unwillingToPerform`, rather than accepting them into memory where they
    /// would silently disappear on restart.
    #[tokio::test]
    async fn ldif_backend_refuses_writes() {
        let b = LdifBackend::from_ldif(SAMPLE, schema()).unwrap();
        let entry = Entry::new(Dn::parse("cn=New,dc=example,dc=com").unwrap())
            .with("objectClass", &["top"])
            .with("cn", &["New"]);
        assert!(matches!(
            b.add(AddRequest { entry }).await.unwrap_err(),
            BackendError::Unwilling(_)
        ));
        assert!(matches!(
            b.delete(&Dn::parse("cn=Bob Smith,dc=example,dc=com").unwrap())
                .await
                .unwrap_err(),
            BackendError::Unwilling(_)
        ));
    }
}
