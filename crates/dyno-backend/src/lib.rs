//! Backends: the things that can answer LDAP operations.
//!
//! The central abstraction of the project is [`Backend`], not "the store".
//! An in-memory fixture, a read-only LDIF file and (later) a connection to an
//! upstream directory are all implementations of the same trait, which is what
//! keeps the rewriting proxy from being a bolt-on.
//!
//! Everything a backend receives has already been decoded and validated by the
//! server: DNs are parsed, filters are typed, attribute selections are
//! resolved. A backend never sees a protocol type.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod error;
pub mod ldif;
pub mod memory;

use std::sync::Arc;

use async_trait::async_trait;
use dyno_core::ops::{AddRequest, CompareRequest, ModifyDnRequest, ModifyRequest, SearchRequest};
use dyno_core::{Dn, Entry, Schema};

pub use error::BackendError;
pub use ldif::{LdifBackend, LdifError, parse_ldif};
pub use memory::MemoryBackend;

/// Result alias for backend operations.
pub type Result<T> = std::result::Result<T, BackendError>;

/// The outcome of authenticating a DN and password against a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// The credentials are correct.
    Success,
    /// The entry exists but the password is wrong, or the entry has no
    /// password at all. Both must produce the same answer to the client:
    /// distinguishing them tells an attacker which DNs exist.
    Invalid,
    /// This backend does not authenticate; the caller should fall back to its
    /// own configured credentials.
    NotSupported,
}

/// Something that can answer LDAP operations.
///
/// Write operations default to refusing, so a read-only backend gets correct
/// behaviour by implementing nothing. The refusal is
/// [`BackendError::Unwilling`], which the server maps to result code 53 —
/// the code a client can act on, rather than a generic error.
#[async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    /// A human-readable name, for logs and errors.
    fn name(&self) -> &str;

    /// The schema this backend's entries conform to.
    fn schema(&self) -> &Arc<Schema>;

    /// The naming contexts this backend serves, advertised in the root DSE.
    fn naming_contexts(&self) -> Vec<Dn>;

    /// Find entries matching a search request.
    ///
    /// The size limit in the request is advisory to the backend: the server
    /// enforces it again on the way out, because rules may drop entries after
    /// the backend has counted them.
    async fn search(&self, req: &SearchRequest) -> Result<Vec<Entry>>;

    /// Whether an entry exists, and if not, the closest existing ancestor.
    /// Used to fill in `matchedDN` on a `noSuchObject` response.
    async fn closest_ancestor(&self, dn: &Dn) -> Result<Option<Dn>>;

    /// Authenticate a DN and password. Defaults to "this backend does not do
    /// authentication".
    async fn bind(&self, _dn: &Dn, _password: &[u8]) -> Result<BindOutcome> {
        Ok(BindOutcome::NotSupported)
    }

    /// Create an entry.
    ///
    /// # Errors
    ///
    /// Defaults to [`BackendError::Unwilling`] for read-only backends.
    async fn add(&self, _req: AddRequest) -> Result<()> {
        Err(BackendError::Unwilling(format!(
            "backend {} is read-only",
            self.name()
        )))
    }

    /// Delete an entry.
    ///
    /// # Errors
    ///
    /// Defaults to [`BackendError::Unwilling`] for read-only backends.
    async fn delete(&self, _dn: &Dn) -> Result<()> {
        Err(BackendError::Unwilling(format!(
            "backend {} is read-only",
            self.name()
        )))
    }

    /// Modify an entry's attributes.
    ///
    /// # Errors
    ///
    /// Defaults to [`BackendError::Unwilling`] for read-only backends.
    async fn modify(&self, _req: ModifyRequest) -> Result<()> {
        Err(BackendError::Unwilling(format!(
            "backend {} is read-only",
            self.name()
        )))
    }

    /// Rename or move an entry.
    ///
    /// # Errors
    ///
    /// Defaults to [`BackendError::Unwilling`] for read-only backends.
    async fn modify_dn(&self, _req: ModifyDnRequest) -> Result<()> {
        Err(BackendError::Unwilling(format!(
            "backend {} is read-only",
            self.name()
        )))
    }

    /// Test whether an entry holds a value. Implemented in terms of
    /// [`Backend::search`] by default.
    ///
    /// # Errors
    ///
    /// Propagates whatever the underlying search returns.
    async fn compare(&self, req: CompareRequest) -> Result<bool> {
        let search = SearchRequest::base_object(req.dn.clone());
        let entries = self.search(&search).await?;
        let entry = entries
            .first()
            .ok_or(BackendError::NoSuchObject { matched: None })?;
        Ok(entry.has_value(&req.attr, &req.value, self.schema()))
    }
}
