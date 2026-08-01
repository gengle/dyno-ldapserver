//! Backend errors, chosen to map cleanly onto LDAP result codes.
//!
//! Every variant here corresponds to a specific code the client can act on.
//! There is deliberately no catch-all "error" that becomes `operationsError`
//! for anything that goes wrong — that turns a diagnosable problem into an
//! opaque one.

use dyno_core::Dn;
use thiserror::Error;

/// Why a backend operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BackendError {
    /// The named entry does not exist. `matched` carries the closest existing
    /// ancestor, which the server returns as `matchedDN` (RFC 4511 §4.1.9) so
    /// a client can tell "wrong subtree" from "wrong entry".
    #[error("no such object")]
    NoSuchObject {
        /// The closest ancestor that does exist, if any.
        matched: Option<Dn>,
    },

    /// An add was attempted for a DN that already exists.
    #[error("entry already exists")]
    EntryAlreadyExists,

    /// An add was attempted whose parent does not exist. LDAP has no implicit
    /// intermediate-node creation.
    #[error("parent entry does not exist")]
    NoSuchParent {
        /// The closest ancestor that does exist, if any.
        matched: Option<Dn>,
    },

    /// A delete was attempted on an entry that still has children.
    #[error("entry has children and cannot be deleted")]
    NotAllowedOnNonLeaf,

    /// A modify tried to add a value that is already present.
    #[error("attribute {attr:?} already holds that value")]
    AttributeOrValueExists {
        /// The attribute in question.
        attr: String,
    },

    /// A modify tried to delete an attribute or value that is not there.
    #[error("attribute {attr:?} has no such value")]
    NoSuchAttribute {
        /// The attribute in question.
        attr: String,
    },

    /// The entry does not satisfy its object class definition — in practice,
    /// it has no `objectClass` at all.
    #[error("object class violation: {0}")]
    ObjectClassViolation(String),

    /// A change would break a schema constraint, such as putting two values in
    /// a single-valued attribute.
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    /// A change would leave the entry inconsistent with its own DN, e.g.
    /// deleting the attribute value that names it.
    #[error("naming violation: {0}")]
    NamingViolation(String),

    /// The operation is understood but this backend will not perform it —
    /// a write to a read-only backend, most often.
    #[error("unwilling to perform: {0}")]
    Unwilling(String),

    /// The backend is temporarily unusable, e.g. an upstream is unreachable.
    #[error("backend unavailable: {0}")]
    Unavailable(String),

    /// Something went wrong inside the backend. Reserved for genuine internal
    /// faults such as a poisoned lock, not for ordinary client mistakes.
    #[error("internal backend error: {0}")]
    Internal(String),
}
