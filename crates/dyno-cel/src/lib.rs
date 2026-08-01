//! The CEL rule engine.
//!
//! **Status: not yet implemented.** This is Phase 2 of the build plan in
//! `DESIGN.md`; the crate exists so the workspace layout and dependency
//! direction are fixed before rules arrive, and so that `dyno-config` can grow
//! a rule table without a later re-shuffle.
//!
//! The shape it will take:
//!
//! - [`cel::Program::compile`] at config load, never on the hot path.
//! - `Program::references()` to validate at load time that a rule only reads
//!   variables the pipeline actually publishes, and to skip building the
//!   expensive parts of the context for rules that do not read them.
//! - A per-request `Context` derived from a shared base scope, populated from
//!   a `serde::Serialize` request struct via `cel::to_value`.
//! - Typed decisions rather than bare booleans: predicates for access control
//!   and `when:` clauses, transforms for DN and attribute rewriting.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

/// The stage of the pipeline a rule runs in.
///
/// Request and response rules see different contexts and may return different
/// things, and that separation is what makes proxy rewriting tractable: the
/// request stage translates the client's view into the backend's, and the
/// response stage translates back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Before the backend: deny the operation, or rewrite its base DN or filter.
    Request,
    /// After the backend: drop an entry, or rewrite its DN or attributes.
    Response,
}

impl Stage {
    /// The name used in config files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}
