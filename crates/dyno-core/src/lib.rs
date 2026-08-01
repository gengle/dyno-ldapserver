//! Pure domain types for an LDAP directory.
//!
//! This crate contains no I/O and no async. Everything here is a value type or
//! a pure function, because DN normalisation and filter matching are the
//! subtlest correctness problems in the project and they should be testable
//! without a server running.
//!
//! The pieces:
//!
//! - [`Dn`] — a parsed, normalised, comparable distinguished name.
//! - [`AttrValue`] — an LDAP attribute value (an octet string, not a `String`).
//! - [`Entry`] / [`Attribute`] — a directory entry.
//! - [`Schema`] / [`MatchingRule`] — how two values are compared, per attribute.
//! - [`Filter`] — a search filter and its three-valued evaluation.
//! - [`Scope`] — base / one-level / subtree / children scope evaluation.
//! - [`ops`] — request types shared by backends and the rule engine.

// Library code denies these (see the workspace lint table); tests are allowed
// to assert loudly, since a panicking test is a failing test and nothing more.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod dn;
pub mod entry;
pub mod error;
pub mod filter;
pub mod ops;
pub mod schema;
pub mod scope;
pub mod value;

pub use dn::{Ava, Dn, Rdn};
pub use entry::{Attribute, Entry};
pub use error::{DnError, SyntaxError};
pub use filter::{Filter, Match, MatchingRuleAssertion, Substring};
pub use ops::{AttrSelection, SearchRequest};
pub use schema::{AttributeDef, MatchingRule, Schema};
pub use scope::Scope;
pub use value::AttrValue;
