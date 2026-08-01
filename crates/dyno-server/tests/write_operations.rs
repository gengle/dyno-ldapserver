//! End-to-end write tests: a real LDAP client adding, modifying, renaming and
//! deleting objects against a running server.
//!
//! Each feature has a pair: the operation succeeding and being visible
//! afterwards, and the operation being correctly refused with the result code
//! a client can act on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::HashSet;

use common::{ADMIN_DN, ADMIN_PW, BOB_DN, BOB_PW, Harness};
use ldap3::{Mod, Scope, SearchEntry};

/// Result codes we assert on, named rather than numeric.
mod rc {
    pub const SUCCESS: u32 = 0;
    pub const NO_SUCH_ATTRIBUTE: u32 = 16;
    pub const NO_SUCH_OBJECT: u32 = 32;
    pub const INVALID_DN_SYNTAX: u32 = 34;
    pub const INSUFFICIENT_ACCESS: u32 = 50;
    pub const UNWILLING_TO_PERFORM: u32 = 53;
    pub const OBJECT_CLASS_VIOLATION: u32 = 65;
    pub const NOT_ALLOWED_ON_NON_LEAF: u32 = 66;
    pub const ENTRY_ALREADY_EXISTS: u32 = 68;
}

fn attrs(pairs: &[(&str, &[&str])]) -> Vec<(String, HashSet<String>)> {
    pairs
        .iter()
        .map(|(k, vs)| {
            (
                (*k).to_string(),
                vs.iter().map(|v| (*v).to_string()).collect(),
            )
        })
        .collect()
}

fn carol() -> Vec<(String, HashSet<String>)> {
    attrs(&[
        ("objectClass", &["top", "person", "inetOrgPerson"]),
        ("cn", &["Carol"]),
        ("sn", &["Danvers"]),
        ("mail", &["carol@example.com"]),
    ])
}

const CAROL_DN: &str = "cn=Carol,ou=People,dc=example,dc=com";

/// How many entries a subtree search of the whole directory returns.
async fn count_all(ldap: &mut ldap3::Ldap) -> usize {
    let (entries, res) = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS);
    entries.len()
}

/// Whether an entry can be found by DN.
async fn exists(ldap: &mut ldap3::Ldap, dn: &str) -> bool {
    let result = ldap
        .search(dn, Scope::Base, "(objectClass=*)", vec!["dn"])
        .await
        .unwrap();
    match result.1.rc {
        rc::SUCCESS => !result.0.is_empty(),
        rc::NO_SUCH_OBJECT => false,
        other => panic!("unexpected result code {other} looking up {dn}"),
    }
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

/// **Passing case.** An authenticated client adds an entry; it is immediately
/// visible to search, with the values it was created with.
#[tokio::test]
async fn add_creates_an_entry_that_search_can_find() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let before = count_all(&mut ldap).await;
    let res = ldap.add(CAROL_DN, carol()).await.unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "add should succeed: {}", res.text);

    assert_eq!(count_all(&mut ldap).await, before + 1);

    let (found, _) = ldap
        .search(
            "ou=People,dc=example,dc=com",
            Scope::Subtree,
            "(cn=carol)",
            vec!["cn", "sn", "mail"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(found.len(), 1, "the new entry should be searchable by cn");
    let entry = SearchEntry::construct(found[0].clone());
    assert_eq!(entry.dn, CAROL_DN);
    assert_eq!(entry.attrs["sn"], vec!["Danvers"]);
    assert_eq!(entry.attrs["mail"], vec!["carol@example.com"]);

    ldap.unbind().await.unwrap();
    h.shutdown().await;
}

/// **Failing case.** The same add from an anonymous client is refused, and the
/// entry is not created. Anonymous writes are never permitted, even though
/// anonymous *reads* are allowed in this configuration.
#[tokio::test]
async fn add_is_refused_for_an_anonymous_client() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let res = ldap.add(CAROL_DN, carol()).await.unwrap();
    assert_eq!(res.rc, rc::INSUFFICIENT_ACCESS, "{}", res.text);
    assert!(
        !exists(&mut ldap, CAROL_DN).await,
        "a refused add must not have created anything"
    );

    h.shutdown().await;
}

/// **Failing case.** Adding an entry that already exists is rejected with
/// `entryAlreadyExists`, and the original entry is untouched.
#[tokio::test]
async fn add_rejects_a_duplicate_entry() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    ldap.add(CAROL_DN, carol())
        .await
        .unwrap()
        .success()
        .unwrap();
    let res = ldap.add(CAROL_DN, carol()).await.unwrap();
    assert_eq!(res.rc, rc::ENTRY_ALREADY_EXISTS, "{}", res.text);

    let (found, _) = ldap
        .search(CAROL_DN, Scope::Base, "(objectClass=*)", vec!["sn"])
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(found.len(), 1, "still exactly one entry");

    h.shutdown().await;
}

/// **Failing case.** An add below a parent that does not exist fails with
/// `noSuchObject` and reports the closest ancestor that does exist, so the
/// client can tell a typo'd branch from a typo'd leaf.
#[tokio::test]
async fn add_rejects_a_missing_parent_and_reports_the_matched_dn() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap
        .add("cn=Ghost,ou=Nowhere,dc=example,dc=com", carol())
        .await
        .unwrap();
    assert_eq!(res.rc, rc::NO_SUCH_OBJECT, "{}", res.text);
    assert_eq!(
        res.matched, "dc=example,dc=com",
        "matchedDN should name the deepest existing ancestor"
    );

    h.shutdown().await;
}

/// **Failing case.** Structurally invalid requests are rejected before they
/// reach the backend: a malformed DN, and an entry with no objectClass.
#[tokio::test]
async fn add_rejects_malformed_requests() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap.add("this is not a dn", carol()).await.unwrap();
    assert_eq!(res.rc, rc::INVALID_DN_SYNTAX, "{}", res.text);

    let res = ldap
        .add(
            "cn=NoClass,ou=People,dc=example,dc=com",
            attrs(&[("cn", &["NoClass"]), ("sn", &["Nobody"])]),
        )
        .await
        .unwrap();
    assert_eq!(res.rc, rc::OBJECT_CLASS_VIOLATION, "{}", res.text);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

/// **Passing case.** Deleting a leaf removes it: the entry is gone and the
/// directory is one entry smaller.
#[tokio::test]
async fn delete_removes_an_entry() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    ldap.add(CAROL_DN, carol())
        .await
        .unwrap()
        .success()
        .unwrap();
    assert!(exists(&mut ldap, CAROL_DN).await);
    let before = count_all(&mut ldap).await;

    let res = ldap.delete(CAROL_DN).await.unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "{}", res.text);

    assert!(!exists(&mut ldap, CAROL_DN).await);
    assert_eq!(count_all(&mut ldap).await, before - 1);

    h.shutdown().await;
}

/// **Failing case.** Deleting an entry that is not there fails with
/// `noSuchObject` rather than succeeding quietly.
#[tokio::test]
async fn delete_rejects_a_missing_entry() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap
        .delete("cn=Nobody,ou=People,dc=example,dc=com")
        .await
        .unwrap();
    assert_eq!(res.rc, rc::NO_SUCH_OBJECT, "{}", res.text);
    assert_eq!(res.matched, "ou=People,dc=example,dc=com");

    h.shutdown().await;
}

/// **Failing case.** Deleting a node that still has children is refused, and
/// the children survive. A delete that took the subtree with it would make one
/// mistyped DN catastrophic.
#[tokio::test]
async fn delete_refuses_a_non_leaf_and_leaves_children_intact() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap.delete("ou=People,dc=example,dc=com").await.unwrap();
    assert_eq!(res.rc, rc::NOT_ALLOWED_ON_NON_LEAF, "{}", res.text);

    assert!(
        exists(&mut ldap, BOB_DN).await,
        "children must be untouched"
    );
    assert!(exists(&mut ldap, "ou=People,dc=example,dc=com").await);

    h.shutdown().await;
}

/// **Failing case.** An anonymous client cannot delete, and the entry survives.
#[tokio::test]
async fn delete_is_refused_for_an_anonymous_client() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let res = ldap.delete(BOB_DN).await.unwrap();
    assert_eq!(res.rc, rc::INSUFFICIENT_ACCESS, "{}", res.text);
    assert!(exists(&mut ldap, BOB_DN).await);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// add and remove, round trip
// ---------------------------------------------------------------------------

/// **Passing case.** The full lifecycle a client cares about: the object is
/// absent, is added, is found, is deleted, and is absent again — with the
/// directory returning to exactly its original size.
#[tokio::test]
async fn objects_can_be_added_and_removed_repeatedly() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let original = count_all(&mut ldap).await;

    for round in 0..3 {
        assert!(
            !exists(&mut ldap, CAROL_DN).await,
            "round {round}: entry should start absent"
        );

        ldap.add(CAROL_DN, carol())
            .await
            .unwrap()
            .success()
            .unwrap_or_else(|e| panic!("round {round}: add failed: {e}"));
        assert!(exists(&mut ldap, CAROL_DN).await, "round {round}: added");
        assert_eq!(count_all(&mut ldap).await, original + 1);

        ldap.delete(CAROL_DN)
            .await
            .unwrap()
            .success()
            .unwrap_or_else(|e| panic!("round {round}: delete failed: {e}"));
        assert!(!exists(&mut ldap, CAROL_DN).await, "round {round}: deleted");
        assert_eq!(
            count_all(&mut ldap).await,
            original,
            "round {round}: the directory returned to its original size"
        );
    }

    h.shutdown().await;
}

/// **Passing case.** Changes made on one connection are visible on another.
/// A store that were somehow per-connection would pass every test above.
#[tokio::test]
async fn writes_are_visible_to_other_connections() {
    let h = Harness::start().await;
    let mut writer = h.connect_as_admin().await;
    let mut reader = h.connect().await;

    assert!(!exists(&mut reader, CAROL_DN).await);
    writer
        .add(CAROL_DN, carol())
        .await
        .unwrap()
        .success()
        .unwrap();
    assert!(
        exists(&mut reader, CAROL_DN).await,
        "a second connection should see the new entry"
    );

    writer.delete(CAROL_DN).await.unwrap().success().unwrap();
    assert!(!exists(&mut reader, CAROL_DN).await);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// modify
// ---------------------------------------------------------------------------

/// **Passing case.** Add, replace and delete modifications all take effect.
#[tokio::test]
async fn modify_applies_each_change_kind() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap
        .modify(
            BOB_DN,
            vec![
                Mod::Add("description".to_string(), ["a person".to_string()].into()),
                Mod::Replace("sn".to_string(), ["Smythe".to_string()].into()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "{}", res.text);

    let (found, _) = ldap
        .search(
            BOB_DN,
            Scope::Base,
            "(objectClass=*)",
            vec!["sn", "description"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    let entry = SearchEntry::construct(found[0].clone());
    assert_eq!(entry.attrs["sn"], vec!["Smythe"]);
    assert_eq!(entry.attrs["description"], vec!["a person"]);

    let res = ldap
        .modify(
            BOB_DN,
            vec![Mod::Delete("description".to_string(), HashSet::new())],
        )
        .await
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "{}", res.text);

    let (found, _) = ldap
        .search(BOB_DN, Scope::Base, "(objectClass=*)", vec!["description"])
        .await
        .unwrap()
        .success()
        .unwrap();
    let entry = SearchEntry::construct(found[0].clone());
    assert!(!entry.attrs.contains_key("description"));

    h.shutdown().await;
}

/// **Failing case.** A modify list that fails part way through applies none of
/// it. The first change here is valid; the second is not.
#[tokio::test]
async fn a_failed_modify_applies_nothing() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap
        .modify(
            BOB_DN,
            vec![
                Mod::Add(
                    "description".to_string(),
                    ["added first".to_string()].into(),
                ),
                Mod::Delete("telephoneNumber".to_string(), ["555".to_string()].into()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(res.rc, rc::NO_SUCH_ATTRIBUTE, "{}", res.text);

    let (found, _) = ldap
        .search(BOB_DN, Scope::Base, "(objectClass=*)", vec!["description"])
        .await
        .unwrap()
        .success()
        .unwrap();
    let entry = SearchEntry::construct(found[0].clone());
    assert!(
        !entry.attrs.contains_key("description"),
        "the successful part of a failed modify must be rolled back"
    );

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// modifyDN
// ---------------------------------------------------------------------------

/// **Passing case.** Renaming an entry moves it and rewrites its naming
/// attribute.
#[tokio::test]
async fn modifydn_renames_an_entry() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap
        .modifydn(BOB_DN, "cn=Robert", true, None)
        .await
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "{}", res.text);

    assert!(!exists(&mut ldap, BOB_DN).await);
    let renamed = "cn=Robert,ou=People,dc=example,dc=com";
    assert!(exists(&mut ldap, renamed).await);

    let (found, _) = ldap
        .search(renamed, Scope::Base, "(objectClass=*)", vec!["cn"])
        .await
        .unwrap()
        .success()
        .unwrap();
    let entry = SearchEntry::construct(found[0].clone());
    assert_eq!(entry.attrs["cn"], vec!["Robert"], "deleteOldRDN was set");

    h.shutdown().await;
}

/// **Failing case.** Renaming onto a DN that already exists is refused, and
/// both entries survive unchanged.
#[tokio::test]
async fn modifydn_refuses_to_overwrite_an_existing_entry() {
    let h = Harness::start().await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap.modifydn(BOB_DN, "cn=Alice", true, None).await.unwrap();
    assert_eq!(res.rc, rc::ENTRY_ALREADY_EXISTS, "{}", res.text);

    assert!(exists(&mut ldap, BOB_DN).await);
    assert!(exists(&mut ldap, "cn=Alice,ou=People,dc=example,dc=com").await);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// read-only server
// ---------------------------------------------------------------------------

/// **Failing case.** With `allow_writes = false`, even a correctly
/// authenticated administrator is refused, with `unwillingToPerform` rather
/// than an access-control error — the server is not saying "not you", it is
/// saying "not here".
#[tokio::test]
async fn a_read_only_server_refuses_all_writes() {
    let h = Harness::with_config(&common::default_config(false, false)).await;
    let mut ldap = h.connect_as_admin().await;

    let res = ldap.add(CAROL_DN, carol()).await.unwrap();
    assert_eq!(res.rc, rc::UNWILLING_TO_PERFORM, "{}", res.text);

    let res = ldap.delete(BOB_DN).await.unwrap();
    assert_eq!(res.rc, rc::UNWILLING_TO_PERFORM, "{}", res.text);

    assert!(exists(&mut ldap, BOB_DN).await);
    assert!(!exists(&mut ldap, CAROL_DN).await);

    h.shutdown().await;
}

/// **Passing case.** A user whose password lives in the directory can bind and
/// then write, which proves the two credential sources are equivalent to
/// everything downstream.
#[tokio::test]
async fn a_directory_user_can_bind_and_write() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    ldap.simple_bind(BOB_DN, BOB_PW)
        .await
        .unwrap()
        .success()
        .expect("Bob's password is stored in the directory");

    let res = ldap.add(CAROL_DN, carol()).await.unwrap();
    assert_eq!(res.rc, rc::SUCCESS, "{}", res.text);
    assert!(exists(&mut ldap, CAROL_DN).await);

    // ...and the administrator configured in the file works too.
    let mut admin = h.connect().await;
    admin
        .simple_bind(ADMIN_DN, ADMIN_PW)
        .await
        .unwrap()
        .success()
        .unwrap();
    admin.delete(CAROL_DN).await.unwrap().success().unwrap();

    h.shutdown().await;
}
