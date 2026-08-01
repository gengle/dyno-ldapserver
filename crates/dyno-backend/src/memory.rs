//! An in-memory directory.
//!
//! Entries live in a `BTreeMap` keyed by [`Dn::sort_key`], so a subtree search
//! is a range scan rather than a scan of the whole store.
//!
//! # Concurrency
//!
//! One `RwLock` over the whole map. Reads are concurrent; a write serialises
//! against everything. That is the right trade for a fixture directory —
//! operations are microseconds and the lock is never held across an `await` —
//! and it makes each operation trivially atomic, which matters more here than
//! throughput: a modify that fails half way through must leave the entry as it
//! was, and the simplest way to guarantee that is to apply changes to a clone
//! and swap it in under the lock.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use dyno_core::ops::{
    AddRequest, Modification, ModifyDnRequest, ModifyOp, ModifyRequest, SearchRequest,
};
use dyno_core::{AttrValue, Dn, Entry, Rdn, Schema, Scope};

use crate::error::BackendError;
use crate::{Backend, BindOutcome, Result};

/// An in-memory directory that supports the full set of operations.
#[derive(Debug)]
pub struct MemoryBackend {
    name: String,
    schema: Arc<Schema>,
    suffixes: Vec<Dn>,
    entries: RwLock<BTreeMap<String, Entry>>,
}

impl MemoryBackend {
    /// An empty store serving the given naming contexts.
    #[must_use]
    pub fn new(name: impl Into<String>, suffixes: Vec<Dn>, schema: Arc<Schema>) -> Self {
        Self {
            name: name.into(),
            schema,
            suffixes,
            entries: RwLock::new(BTreeMap::new()),
        }
    }

    /// A store pre-loaded with entries, with naming contexts inferred as the
    /// shallowest DNs present.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::EntryAlreadyExists`] if two entries share a DN.
    pub fn from_entries(
        name: impl Into<String>,
        entries: Vec<Entry>,
        schema: Arc<Schema>,
    ) -> Result<Self> {
        let mut map = BTreeMap::new();
        for entry in entries {
            let key = entry.dn().sort_key();
            if map.insert(key, entry).is_some() {
                return Err(BackendError::EntryAlreadyExists);
            }
        }
        let suffixes = infer_suffixes(&map);
        Ok(Self {
            name: name.into(),
            schema,
            suffixes,
            entries: RwLock::new(map),
        })
    }

    /// Number of entries held.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Internal`] if the lock is poisoned.
    pub fn len(&self) -> Result<usize> {
        Ok(self.read()?.len())
    }

    /// Whether the store is empty.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Internal`] if the lock is poisoned.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.read()?.is_empty())
    }

    /// Fetch one entry by DN.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Internal`] if the lock is poisoned.
    pub fn get(&self, dn: &Dn) -> Result<Option<Entry>> {
        Ok(self.read()?.get(&dn.sort_key()).cloned())
    }

    /// Insert or replace an entry, bypassing the validation [`Backend::add`]
    /// performs. For seeding fixtures.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Internal`] if the lock is poisoned.
    pub fn insert(&self, entry: Entry) -> Result<()> {
        let mut guard = self.write()?;
        guard.insert(entry.dn().sort_key(), entry);
        Ok(())
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<String, Entry>>> {
        self.entries
            .read()
            .map_err(|_| BackendError::Internal("entry store lock is poisoned".into()))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, BTreeMap<String, Entry>>> {
        self.entries
            .write()
            .map_err(|_| BackendError::Internal("entry store lock is poisoned".into()))
    }
}

/// The shallowest DNs in the store: entries with no ancestor also present.
fn infer_suffixes(map: &BTreeMap<String, Entry>) -> Vec<Dn> {
    let mut suffixes: Vec<Dn> = Vec::new();
    for entry in map.values() {
        let dn = entry.dn();
        if !suffixes.iter().any(|s| dn.is_within(s)) {
            suffixes.retain(|s| !s.is_within(dn));
            suffixes.push(dn.clone());
        }
    }
    suffixes
}

/// The half-open range of sort keys covering `base` and everything under it.
///
/// The upper bound uses `char::MAX` after the separator so that the range
/// cannot run past the subtree into a sibling whose name merely starts with
/// the same characters.
fn subtree_bounds(base: &Dn) -> (String, String) {
    let start = base.sort_key();
    let mut end = start.clone();
    end.push(',');
    end.push(char::MAX);
    (start, end)
}

/// Whether a sort key belongs to `base`'s subtree.
fn key_in_subtree(key: &str, base_key: &str) -> bool {
    if base_key.is_empty() {
        return true;
    }
    key == base_key
        || (key.len() > base_key.len() && key.starts_with(base_key) && {
            // The character right after the base must be the RDN separator, or
            // `dc=example` would swallow `dc=example2`.
            key.as_bytes().get(base_key.len()) == Some(&b',')
        })
}

/// Constant-time byte comparison.
///
/// Length is not hidden — an attacker can already learn a password's length
/// from the request they sent — but the content comparison does not short
/// circuit on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compare a presented password against a stored `userPassword` value.
///
/// Only cleartext is understood, with or without an explicit `{CLEARTEXT}`
/// scheme prefix. A value carrying any other scheme (`{SSHA}`, `{CRYPT}`, …)
/// is *not* treated as a literal password to compare against — doing so would
/// let the hash text itself work as a password.
fn password_matches(stored: &AttrValue, presented: &[u8]) -> bool {
    let bytes = stored.as_bytes();
    if let Some(text) = stored.as_str() {
        if let Some(rest) = text.strip_prefix("{CLEARTEXT}") {
            return constant_time_eq(rest.as_bytes(), presented);
        }
        if text.starts_with('{') && text.contains('}') {
            // A scheme we do not implement. Never matches.
            return false;
        }
    }
    constant_time_eq(bytes, presented)
}

impl MemoryBackend {
    /// Validate and apply an add, under the write lock.
    fn add_locked(&self, map: &mut BTreeMap<String, Entry>, entry: Entry) -> Result<()> {
        let dn = entry.dn().clone();
        if dn.is_empty() {
            return Err(BackendError::NamingViolation(
                "cannot add an entry with an empty DN".into(),
            ));
        }
        let key = dn.sort_key();
        if map.contains_key(&key) {
            return Err(BackendError::EntryAlreadyExists);
        }

        // The parent must exist, unless this entry is itself a naming context
        // that the backend was configured to serve.
        let is_suffix = self.suffixes.iter().any(|s| &dn == s);
        if !is_suffix {
            let parent = dn.parent().unwrap_or_default();
            if !parent.is_empty() && !map.contains_key(&parent.sort_key()) {
                return Err(BackendError::NoSuchParent {
                    matched: closest_ancestor(map, &dn),
                });
            }
        }

        // An entry must carry the attribute values that name it. Without this
        // check, `cn=Bob` could hold `cn: Alice` and searches for the entry by
        // its own name would miss it.
        if let Some(rdn) = dn.rdn() {
            for ava in rdn.avas() {
                if !entry.has_value(ava.attr(), ava.value(), &self.schema) {
                    return Err(BackendError::NamingViolation(format!(
                        "entry does not contain its RDN value {}={}",
                        ava.attr(),
                        ava.value()
                    )));
                }
            }
        }

        if !entry.has("objectClass") {
            return Err(BackendError::ObjectClassViolation(
                "entry has no objectClass".into(),
            ));
        }

        self.check_single_valued(&entry)?;
        map.insert(key, entry);
        Ok(())
    }

    fn check_single_valued(&self, entry: &Entry) -> Result<()> {
        for attr in entry.attributes() {
            if attr.len() > 1 && self.schema.is_single_valued(attr.name()) {
                return Err(BackendError::ConstraintViolation(format!(
                    "attribute {} is single-valued but has {} values",
                    attr.name(),
                    attr.len()
                )));
            }
        }
        Ok(())
    }

    /// Apply one modification to a working copy of an entry.
    fn apply_modification(&self, entry: &mut Entry, m: &Modification) -> Result<()> {
        match m.op {
            ModifyOp::Add => {
                if m.values.is_empty() {
                    return Err(BackendError::ConstraintViolation(
                        "add modification has no values".into(),
                    ));
                }
                for v in &m.values {
                    if entry.has_value(&m.attr, v, &self.schema) {
                        return Err(BackendError::AttributeOrValueExists {
                            attr: m.attr.clone(),
                        });
                    }
                }
                entry.add_values(&m.attr, m.values.clone(), &self.schema);
            }
            ModifyOp::Delete => {
                if !entry.has(&m.attr) {
                    return Err(BackendError::NoSuchAttribute {
                        attr: m.attr.clone(),
                    });
                }
                for v in &m.values {
                    if !entry.has_value(&m.attr, v, &self.schema) {
                        return Err(BackendError::NoSuchAttribute {
                            attr: m.attr.clone(),
                        });
                    }
                }
                entry.remove_values(&m.attr, &m.values, &self.schema);
            }
            ModifyOp::Replace => {
                entry.set(&m.attr, m.values.clone());
            }
        }
        Ok(())
    }
}

/// The closest ancestor of `dn` that exists in the map.
fn closest_ancestor(map: &BTreeMap<String, Entry>, dn: &Dn) -> Option<Dn> {
    let mut candidate = dn.parent();
    while let Some(c) = candidate {
        if c.is_empty() {
            return None;
        }
        if map.contains_key(&c.sort_key()) {
            return Some(c);
        }
        candidate = c.parent();
    }
    None
}

#[async_trait]
impl Backend for MemoryBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn schema(&self) -> &Arc<Schema> {
        &self.schema
    }

    fn naming_contexts(&self) -> Vec<Dn> {
        self.suffixes.clone()
    }

    async fn search(&self, req: &SearchRequest) -> Result<Vec<Entry>> {
        let map = self.read()?;

        // RFC 4511 §4.5.3: if the base object does not exist, the search fails
        // with noSuchObject regardless of scope — it does not return nothing.
        let base_key = req.base.sort_key();
        if !req.base.is_empty() && !map.contains_key(&base_key) {
            return Err(BackendError::NoSuchObject {
                matched: closest_ancestor(&map, &req.base),
            });
        }

        // One extra entry past the limit, so the caller can tell "exactly the
        // limit" from "more than the limit" and answer sizeLimitExceeded.
        let ceiling = req.size_limit.map(|n| n.saturating_add(1));

        let mut out = Vec::new();
        let (start, end) = subtree_bounds(&req.base);
        let candidates: Box<dyn Iterator<Item = (&String, &Entry)>> = if req.base.is_empty() {
            Box::new(map.iter())
        } else {
            Box::new(map.range(start..=end))
        };

        for (key, entry) in candidates {
            if !key_in_subtree(key, &base_key) {
                continue;
            }
            if !req.scope.contains(&req.base, entry.dn()) {
                continue;
            }
            if !req.filter.evaluate(entry, &self.schema).is_true() {
                continue;
            }
            out.push(req.attrs.project(entry, &self.schema));
            if ceiling.is_some_and(|c| out.len() >= c) {
                break;
            }
            if req.scope == Scope::Base {
                break;
            }
        }
        Ok(out)
    }

    async fn closest_ancestor(&self, dn: &Dn) -> Result<Option<Dn>> {
        let map = self.read()?;
        if map.contains_key(&dn.sort_key()) {
            return Ok(Some(dn.clone()));
        }
        Ok(closest_ancestor(&map, dn))
    }

    async fn bind(&self, dn: &Dn, password: &[u8]) -> Result<BindOutcome> {
        let map = self.read()?;
        let Some(entry) = map.get(&dn.sort_key()) else {
            // Do not distinguish "no such entry" from "wrong password": that
            // difference is a DN oracle.
            return Ok(BindOutcome::Invalid);
        };
        let stored = entry.values("userPassword");
        if stored.is_empty() || password.is_empty() {
            return Ok(BindOutcome::Invalid);
        }
        let ok = stored.iter().any(|v| password_matches(v, password));
        Ok(if ok {
            BindOutcome::Success
        } else {
            BindOutcome::Invalid
        })
    }

    async fn add(&self, req: AddRequest) -> Result<()> {
        let mut map = self.write()?;
        self.add_locked(&mut map, req.entry)
    }

    async fn delete(&self, dn: &Dn) -> Result<()> {
        let mut map = self.write()?;
        let key = dn.sort_key();
        if !map.contains_key(&key) {
            return Err(BackendError::NoSuchObject {
                matched: closest_ancestor(&map, dn),
            });
        }
        // LDAP delete removes one leaf entry. Removing a subtree silently
        // would make a typo catastrophic.
        let (start, end) = subtree_bounds(dn);
        let has_children = map
            .range(start..=end)
            .any(|(k, _)| k != &key && key_in_subtree(k, &key));
        if has_children {
            return Err(BackendError::NotAllowedOnNonLeaf);
        }
        map.remove(&key);
        Ok(())
    }

    async fn modify(&self, req: ModifyRequest) -> Result<()> {
        let mut map = self.write()?;
        let key = req.dn.sort_key();
        let Some(existing) = map.get(&key) else {
            return Err(BackendError::NoSuchObject {
                matched: closest_ancestor(&map, &req.dn),
            });
        };

        // Apply to a clone so a failure part way through changes nothing.
        let mut working = existing.clone();
        for m in &req.changes {
            self.apply_modification(&mut working, m)?;
        }

        // The entry must still contain the values that name it.
        if let Some(rdn) = req.dn.rdn() {
            for ava in rdn.avas() {
                if !working.has_value(ava.attr(), ava.value(), &self.schema) {
                    return Err(BackendError::NamingViolation(format!(
                        "modification would remove the RDN value {}={}",
                        ava.attr(),
                        ava.value()
                    )));
                }
            }
        }
        if !working.has("objectClass") {
            return Err(BackendError::ObjectClassViolation(
                "modification would remove objectClass".into(),
            ));
        }
        self.check_single_valued(&working)?;

        map.insert(key, working);
        Ok(())
    }

    async fn modify_dn(&self, req: ModifyDnRequest) -> Result<()> {
        let mut map = self.write()?;
        let old_key = req.dn.sort_key();
        if !map.contains_key(&old_key) {
            return Err(BackendError::NoSuchObject {
                matched: closest_ancestor(&map, &req.dn),
            });
        }

        let parent = match req.new_superior.clone() {
            Some(p) => p,
            None => req.dn.parent().unwrap_or_default(),
        };
        if !parent.is_empty() && !map.contains_key(&parent.sort_key()) {
            return Err(BackendError::NoSuchParent {
                matched: closest_ancestor(&map, &parent),
            });
        }
        // Moving an entry beneath itself would detach the subtree from the
        // tree entirely.
        if parent.is_within(&req.dn) {
            return Err(BackendError::NamingViolation(
                "cannot move an entry beneath itself".into(),
            ));
        }

        let new_dn = parent.child(req.new_rdn.clone());
        let new_key = new_dn.sort_key();
        if new_key != old_key && map.contains_key(&new_key) {
            return Err(BackendError::EntryAlreadyExists);
        }

        // Collect the entry and its descendants, then re-key them all.
        let (start, end) = subtree_bounds(&req.dn);
        let affected: Vec<String> = map
            .range(start..=end)
            .filter(|(k, _)| key_in_subtree(k, &old_key))
            .map(|(k, _)| k.clone())
            .collect();

        let mut moved: Vec<Entry> = Vec::with_capacity(affected.len());
        for key in &affected {
            let Some(mut entry) = map.remove(key) else {
                continue;
            };
            let entry_dn = entry.dn().clone();
            let rebased = rebase(&entry_dn, &req.dn, &new_dn);
            if entry_dn == req.dn {
                if req.delete_old_rdn {
                    if let Some(old_rdn) = req.dn.rdn() {
                        for ava in old_rdn.avas() {
                            entry.remove_values(
                                ava.attr(),
                                std::slice::from_ref(ava.value()),
                                &self.schema,
                            );
                        }
                    }
                }
                for ava in req.new_rdn.avas() {
                    entry.add_values(ava.attr(), vec![ava.value().clone()], &self.schema);
                }
            }
            entry.set_dn(rebased);
            moved.push(entry);
        }

        for entry in moved {
            map.insert(entry.dn().sort_key(), entry);
        }
        Ok(())
    }
}

/// Replace the `old_base` suffix of `dn` with `new_base`.
fn rebase(dn: &Dn, old_base: &Dn, new_base: &Dn) -> Dn {
    let depth = dn.len().saturating_sub(old_base.len());
    let mut rdns: Vec<Rdn> = dn.rdns().iter().take(depth).cloned().collect();
    rdns.extend(new_base.rdns().iter().cloned());
    Dn::from_rdns(rdns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dyno_core::ops::{AttrSelection, CompareRequest};
    use dyno_core::{Filter, Scope};

    fn dn(s: &str) -> Dn {
        Dn::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn person(name: &str, parent: &str) -> Entry {
        Entry::new(dn(&format!("cn={name},{parent}")))
            .with("objectClass", &["top", "person"])
            .with("cn", &[name])
            .with("sn", &[name])
    }

    fn fixture() -> MemoryBackend {
        let schema = Arc::new(Schema::builtin());
        let entries = vec![
            Entry::new(dn("dc=example,dc=com"))
                .with("objectClass", &["top", "domain"])
                .with("dc", &["example"]),
            Entry::new(dn("ou=People,dc=example,dc=com"))
                .with("objectClass", &["top", "organizationalUnit"])
                .with("ou", &["People"]),
            person("Alice", "ou=People,dc=example,dc=com"),
            person("Bob", "ou=People,dc=example,dc=com"),
            Entry::new(dn("dc=other,dc=com"))
                .with("objectClass", &["top", "domain"])
                .with("dc", &["other"]),
        ];
        MemoryBackend::from_entries("memory", entries, schema).unwrap()
    }

    fn all(base: &str, scope: Scope) -> SearchRequest {
        SearchRequest {
            base: dn(base),
            scope,
            filter: Filter::Present("objectClass".into()),
            attrs: AttrSelection::user_attributes(),
            size_limit: None,
            time_limit: None,
            types_only: false,
        }
    }

    // -- search -------------------------------------------------------------

    /// Passing case: a subtree search returns the base and everything under it.
    #[tokio::test]
    async fn subtree_search_returns_the_subtree() {
        let b = fixture();
        let found = b
            .search(&all("dc=example,dc=com", Scope::Subtree))
            .await
            .unwrap();
        assert_eq!(found.len(), 4);
    }

    /// Failing case: the range scan must not spill into a sibling naming
    /// context that shares a suffix. `dc=other,dc=com` is not under
    /// `dc=example,dc=com`.
    #[tokio::test]
    async fn subtree_search_does_not_leak_sibling_contexts() {
        let b = fixture();
        let found = b
            .search(&all("dc=example,dc=com", Scope::Subtree))
            .await
            .unwrap();
        assert!(
            found
                .iter()
                .all(|e| e.dn().is_within(&dn("dc=example,dc=com"))),
            "search leaked an entry outside the base"
        );
    }

    /// Failing case: searching a base that does not exist is `noSuchObject`
    /// with the closest real ancestor, not an empty result set.
    #[tokio::test]
    async fn search_with_a_missing_base_reports_the_closest_ancestor() {
        let b = fixture();
        let err = b
            .search(&all("ou=Nowhere,dc=example,dc=com", Scope::Subtree))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            BackendError::NoSuchObject {
                matched: Some(dn("dc=example,dc=com"))
            }
        );
    }

    /// Validation: the size limit returns one entry beyond the limit so the
    /// server can distinguish "exactly n matched" from "more than n matched".
    #[tokio::test]
    async fn size_limit_returns_one_extra_entry_as_an_overflow_signal() {
        let b = fixture();
        let mut req = all("dc=example,dc=com", Scope::Subtree);
        req.size_limit = Some(2);
        assert_eq!(b.search(&req).await.unwrap().len(), 3);

        req.size_limit = Some(10);
        assert_eq!(
            b.search(&req).await.unwrap().len(),
            4,
            "no overflow to signal"
        );
    }

    // -- add ----------------------------------------------------------------

    /// Passing case: an add lands, and is immediately visible to search.
    #[tokio::test]
    async fn add_creates_a_searchable_entry() {
        let b = fixture();
        let entry = person("Carol", "ou=People,dc=example,dc=com");
        b.add(AddRequest { entry }).await.unwrap();

        let found = b
            .search(&SearchRequest::subtree(
                dn("dc=example,dc=com"),
                Filter::Equality {
                    attr: "cn".into(),
                    value: "carol".into(),
                },
            ))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dn(), &dn("cn=Carol,ou=People,dc=example,dc=com"));
    }

    /// Failing case: adding the same DN twice is rejected.
    #[tokio::test]
    async fn add_rejects_a_duplicate_dn() {
        let b = fixture();
        let entry = person("Alice", "ou=People,dc=example,dc=com");
        assert_eq!(
            b.add(AddRequest { entry }).await.unwrap_err(),
            BackendError::EntryAlreadyExists
        );
    }

    /// Failing case: LDAP creates no intermediate nodes, so an add under a
    /// missing parent fails rather than conjuring the parent.
    #[tokio::test]
    async fn add_rejects_a_missing_parent() {
        let b = fixture();
        let entry = person("Dave", "ou=Ghosts,dc=example,dc=com");
        assert_eq!(
            b.add(AddRequest { entry }).await.unwrap_err(),
            BackendError::NoSuchParent {
                matched: Some(dn("dc=example,dc=com"))
            }
        );
    }

    /// Failing case: an entry must contain the value that names it, or
    /// searching for it by its own RDN would not find it.
    #[tokio::test]
    async fn add_rejects_an_entry_that_contradicts_its_own_rdn() {
        let b = fixture();
        let entry = Entry::new(dn("cn=Dave,ou=People,dc=example,dc=com"))
            .with("objectClass", &["top", "person"])
            .with("cn", &["Someone Else"])
            .with("sn", &["Dave"]);
        assert!(matches!(
            b.add(AddRequest { entry }).await.unwrap_err(),
            BackendError::NamingViolation(_)
        ));
    }

    /// Failing case: an entry with no objectClass is rejected.
    #[tokio::test]
    async fn add_rejects_an_entry_without_an_object_class() {
        let b = fixture();
        let entry = Entry::new(dn("cn=Dave,ou=People,dc=example,dc=com")).with("cn", &["Dave"]);
        assert!(matches!(
            b.add(AddRequest { entry }).await.unwrap_err(),
            BackendError::ObjectClassViolation(_)
        ));
    }

    // -- delete -------------------------------------------------------------

    /// Passing case: deleting a leaf removes it from search results.
    #[tokio::test]
    async fn delete_removes_a_leaf() {
        let b = fixture();
        b.delete(&dn("cn=Bob,ou=People,dc=example,dc=com"))
            .await
            .unwrap();
        assert_eq!(
            b.get(&dn("cn=Bob,ou=People,dc=example,dc=com")).unwrap(),
            None
        );
        let found = b
            .search(&all("dc=example,dc=com", Scope::Subtree))
            .await
            .unwrap();
        assert_eq!(found.len(), 3);
    }

    /// Failing case: deleting a non-leaf is refused. A delete that silently
    /// took the subtree with it would make one typo catastrophic.
    #[tokio::test]
    async fn delete_refuses_a_non_leaf() {
        let b = fixture();
        assert_eq!(
            b.delete(&dn("ou=People,dc=example,dc=com"))
                .await
                .unwrap_err(),
            BackendError::NotAllowedOnNonLeaf
        );
        assert!(
            b.get(&dn("cn=Bob,ou=People,dc=example,dc=com"))
                .unwrap()
                .is_some()
        );
    }

    /// Failing case: deleting something that is not there reports the closest
    /// ancestor rather than succeeding quietly.
    #[tokio::test]
    async fn delete_rejects_a_missing_entry() {
        let b = fixture();
        assert_eq!(
            b.delete(&dn("cn=Nobody,ou=People,dc=example,dc=com"))
                .await
                .unwrap_err(),
            BackendError::NoSuchObject {
                matched: Some(dn("ou=People,dc=example,dc=com"))
            }
        );
    }

    // -- modify -------------------------------------------------------------

    /// Passing case: add, replace and delete modifications all apply.
    #[tokio::test]
    async fn modify_applies_each_change_kind() {
        let b = fixture();
        let target = dn("cn=Bob,ou=People,dc=example,dc=com");
        b.modify(ModifyRequest {
            dn: target.clone(),
            changes: vec![
                Modification {
                    op: ModifyOp::Add,
                    attr: "mail".into(),
                    values: vec!["bob@example.com".into()],
                },
                Modification {
                    op: ModifyOp::Replace,
                    attr: "sn".into(),
                    values: vec!["Smith".into()],
                },
            ],
        })
        .await
        .unwrap();

        let e = b.get(&target).unwrap().unwrap();
        assert_eq!(e.first_str("mail"), Some("bob@example.com"));
        assert_eq!(e.first_str("sn"), Some("Smith"));

        b.modify(ModifyRequest {
            dn: target.clone(),
            changes: vec![Modification {
                op: ModifyOp::Delete,
                attr: "mail".into(),
                values: vec![],
            }],
        })
        .await
        .unwrap();
        assert!(!b.get(&target).unwrap().unwrap().has("mail"));
    }

    /// Failing case: a modify list that fails part way through leaves the
    /// entry exactly as it was. Atomicity is the property, and the only way to
    /// see it is to make the second change fail after the first succeeded.
    #[tokio::test]
    async fn a_failed_modification_leaves_the_entry_untouched() {
        let b = fixture();
        let target = dn("cn=Bob,ou=People,dc=example,dc=com");
        let err = b
            .modify(ModifyRequest {
                dn: target.clone(),
                changes: vec![
                    Modification {
                        op: ModifyOp::Add,
                        attr: "mail".into(),
                        values: vec!["bob@example.com".into()],
                    },
                    Modification {
                        op: ModifyOp::Delete,
                        attr: "telephoneNumber".into(),
                        values: vec!["555".into()],
                    },
                ],
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            BackendError::NoSuchAttribute {
                attr: "telephoneNumber".into()
            }
        );
        assert!(
            !b.get(&target).unwrap().unwrap().has("mail"),
            "the first change was rolled back with the second"
        );
    }

    /// Failing case: a modify may not strip the value that names the entry.
    #[tokio::test]
    async fn modify_cannot_remove_the_rdn_value() {
        let b = fixture();
        let target = dn("cn=Bob,ou=People,dc=example,dc=com");
        let err = b
            .modify(ModifyRequest {
                dn: target,
                changes: vec![Modification {
                    op: ModifyOp::Replace,
                    attr: "cn".into(),
                    values: vec!["Robert".into()],
                }],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::NamingViolation(_)));
    }

    // -- modifyDN -----------------------------------------------------------

    /// Passing case: renaming moves the entry and fixes up its RDN attribute.
    #[tokio::test]
    async fn modify_dn_renames_and_updates_the_rdn_attribute() {
        let b = fixture();
        b.modify_dn(ModifyDnRequest {
            dn: dn("cn=Bob,ou=People,dc=example,dc=com"),
            new_rdn: Rdn::single("cn", "Robert").unwrap(),
            delete_old_rdn: true,
            new_superior: None,
        })
        .await
        .unwrap();

        assert!(
            b.get(&dn("cn=Bob,ou=People,dc=example,dc=com"))
                .unwrap()
                .is_none()
        );
        let moved = b
            .get(&dn("cn=Robert,ou=People,dc=example,dc=com"))
            .unwrap()
            .expect("renamed entry should exist");
        assert!(moved.has_value("cn", &"Robert".into(), &Schema::builtin()));
        assert!(
            !moved.has_value("cn", &"Bob".into(), &Schema::builtin()),
            "deleteOldRDN was requested"
        );
    }

    /// Passing case: moving a non-leaf takes its children with it, and their
    /// DNs are rewritten rather than left dangling.
    #[tokio::test]
    async fn modify_dn_moves_descendants() {
        let b = fixture();
        b.add(AddRequest {
            entry: Entry::new(dn("ou=Staff,dc=example,dc=com"))
                .with("objectClass", &["top", "organizationalUnit"])
                .with("ou", &["Staff"]),
        })
        .await
        .unwrap();

        b.modify_dn(ModifyDnRequest {
            dn: dn("ou=People,dc=example,dc=com"),
            new_rdn: Rdn::single("ou", "Humans").unwrap(),
            delete_old_rdn: true,
            new_superior: Some(dn("ou=Staff,dc=example,dc=com")),
        })
        .await
        .unwrap();

        assert!(
            b.get(&dn("cn=Bob,ou=Humans,ou=Staff,dc=example,dc=com"))
                .unwrap()
                .is_some(),
            "child DNs must follow the move"
        );
        assert!(
            b.get(&dn("cn=Bob,ou=People,dc=example,dc=com"))
                .unwrap()
                .is_none()
        );
    }

    /// Failing case: an entry cannot be moved underneath itself, which would
    /// detach the whole subtree from the directory.
    #[tokio::test]
    async fn modify_dn_refuses_to_move_an_entry_beneath_itself() {
        let b = fixture();
        let err = b
            .modify_dn(ModifyDnRequest {
                dn: dn("ou=People,dc=example,dc=com"),
                new_rdn: Rdn::single("ou", "Inner").unwrap(),
                delete_old_rdn: false,
                new_superior: Some(dn("cn=Bob,ou=People,dc=example,dc=com")),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::NamingViolation(_)));
    }

    // -- bind and compare ---------------------------------------------------

    /// Passing case: a correct password authenticates.
    #[tokio::test]
    async fn bind_accepts_the_right_password() {
        let b = fixture();
        let mut e = person("Eve", "ou=People,dc=example,dc=com");
        e.set("userPassword", vec!["hunter2".into()]);
        b.insert(e).unwrap();
        assert_eq!(
            b.bind(&dn("cn=Eve,ou=People,dc=example,dc=com"), b"hunter2")
                .await
                .unwrap(),
            BindOutcome::Success
        );
    }

    /// Failing case: wrong password, empty password, missing entry and a
    /// hashed password we cannot verify all produce the same answer. A
    /// different answer for a missing entry would be a DN oracle.
    #[tokio::test]
    async fn bind_rejects_everything_else_identically() {
        let b = fixture();
        let mut e = person("Eve", "ou=People,dc=example,dc=com");
        e.set("userPassword", vec!["hunter2".into()]);
        b.insert(e).unwrap();
        let eve = dn("cn=Eve,ou=People,dc=example,dc=com");

        assert_eq!(b.bind(&eve, b"wrong").await.unwrap(), BindOutcome::Invalid);
        assert_eq!(b.bind(&eve, b"").await.unwrap(), BindOutcome::Invalid);
        assert_eq!(
            b.bind(&dn("cn=Ghost,ou=People,dc=example,dc=com"), b"hunter2")
                .await
                .unwrap(),
            BindOutcome::Invalid
        );
        // An entry with no password at all cannot be bound as.
        assert_eq!(
            b.bind(&dn("cn=Bob,ou=People,dc=example,dc=com"), b"anything")
                .await
                .unwrap(),
            BindOutcome::Invalid
        );
    }

    /// Failing case: a stored hash is never usable as a literal password. If
    /// `{SSHA}xyz` compared equal to the string `{SSHA}xyz`, anyone who could
    /// read the directory could bind as anyone.
    #[tokio::test]
    async fn a_stored_hash_is_not_a_usable_password() {
        let b = fixture();
        let mut e = person("Frank", "ou=People,dc=example,dc=com");
        e.set("userPassword", vec!["{SSHA}bm90YXJlYWxoYXNo".into()]);
        b.insert(e).unwrap();
        assert_eq!(
            b.bind(
                &dn("cn=Frank,ou=People,dc=example,dc=com"),
                b"{SSHA}bm90YXJlYWxoYXNo"
            )
            .await
            .unwrap(),
            BindOutcome::Invalid
        );
    }

    /// Passing and failing pair for compare.
    #[tokio::test]
    async fn compare_answers_true_and_false() {
        let b = fixture();
        let bob = dn("cn=Bob,ou=People,dc=example,dc=com");
        assert!(
            b.compare(CompareRequest {
                dn: bob.clone(),
                attr: "cn".into(),
                value: "BOB".into(),
            })
            .await
            .unwrap()
        );
        assert!(
            !b.compare(CompareRequest {
                dn: bob,
                attr: "cn".into(),
                value: "Alice".into(),
            })
            .await
            .unwrap()
        );
    }
}
