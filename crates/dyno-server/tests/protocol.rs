//! End-to-end protocol tests: bind, search, compare, the root DSE and
//! extended operations, driven by a real LDAP client over a real socket.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{ADMIN_DN, ADMIN_PW, BOB_DN, BOB_PW, Harness};
use ldap3::{Scope, SearchEntry, exop::WhoAmI};

mod rc {
    pub const SUCCESS: u32 = 0;
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const SIZE_LIMIT_EXCEEDED: u32 = 4;
    pub const COMPARE_FALSE: u32 = 5;
    pub const COMPARE_TRUE: u32 = 6;
    pub const AUTH_METHOD_NOT_SUPPORTED: u32 = 7;
    pub const NO_SUCH_OBJECT: u32 = 32;
    pub const INVALID_DN_SYNTAX: u32 = 34;
    pub const INVALID_CREDENTIALS: u32 = 49;
    pub const INSUFFICIENT_ACCESS: u32 = 50;
    pub const UNAVAILABLE: u32 = 52;
}

/// Search and return the DNs found, asserting success.
async fn dns(ldap: &mut ldap3::Ldap, base: &str, scope: Scope, filter: &str) -> Vec<String> {
    let (entries, res) = ldap
        .search(base, scope, filter, vec!["dn"])
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS);
    let mut out: Vec<String> = entries
        .into_iter()
        .map(|e| SearchEntry::construct(e).dn)
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

/// **Passing case.** Anonymous bind, a configured account, and an account
/// whose password lives in the directory all authenticate.
#[tokio::test]
async fn bind_accepts_valid_credentials() {
    let h = Harness::start().await;

    let mut ldap = h.connect().await;
    assert_eq!(ldap.simple_bind("", "").await.unwrap().rc, rc::SUCCESS);
    assert_eq!(
        ldap.simple_bind(ADMIN_DN, ADMIN_PW).await.unwrap().rc,
        rc::SUCCESS
    );
    assert_eq!(
        ldap.simple_bind(BOB_DN, BOB_PW).await.unwrap().rc,
        rc::SUCCESS
    );
    // A DN spelled differently is the same DN.
    assert_eq!(
        ldap.simple_bind("CN=Admin, DC=Example, DC=Com", ADMIN_PW)
            .await
            .unwrap()
            .rc,
        rc::SUCCESS
    );

    h.shutdown().await;
}

/// **Failing case.** Wrong password, unknown DN, an entry with no password,
/// and a DN with an empty password are all `invalidCredentials`, with the same
/// message — anything else would tell an attacker which DNs exist.
#[tokio::test]
async fn bind_rejects_bad_credentials_without_leaking_which_dns_exist() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let wrong_password = ldap
        .simple_bind(ADMIN_DN, "not the password")
        .await
        .unwrap();
    let unknown_dn = ldap
        .simple_bind("cn=nobody,dc=example,dc=com", "anything")
        .await
        .unwrap();
    let no_password_stored = ldap
        .simple_bind("cn=Alice,ou=People,dc=example,dc=com", "guess")
        .await
        .unwrap();

    for res in [&wrong_password, &unknown_dn, &no_password_stored] {
        assert_eq!(res.rc, rc::INVALID_CREDENTIALS, "{}", res.text);
    }
    assert_eq!(
        wrong_password.text, unknown_dn.text,
        "the failure message must not distinguish a real DN from a fake one"
    );

    // A DN with an empty password is an unauthenticated bind (RFC 4513
    // §5.1.2) and must not succeed as anonymous.
    let unauthenticated = ldap.simple_bind(ADMIN_DN, "").await.unwrap();
    assert_eq!(unauthenticated.rc, rc::INVALID_CREDENTIALS);

    // An empty DN with a password is the same mistake from the other side.
    let empty_dn_with_password = ldap.simple_bind("", "somepassword").await.unwrap();
    assert_eq!(empty_dn_with_password.rc, rc::INVALID_CREDENTIALS);

    h.shutdown().await;
}

/// **Failing case.** A failed bind drops an identity already established on
/// the connection, rather than leaving the old one in force.
#[tokio::test]
async fn a_failed_bind_drops_the_previous_identity() {
    let h = Harness::with_config(&common::default_config(true, true)).await;
    let mut ldap = h.connect().await;

    ldap.simple_bind(ADMIN_DN, ADMIN_PW)
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(
        dns(
            &mut ldap,
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)"
        )
        .await
        .len(),
        1
    );

    assert_eq!(
        ldap.simple_bind(ADMIN_DN, "wrong").await.unwrap().rc,
        rc::INVALID_CREDENTIALS
    );

    let after = ldap
        .search(
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap();
    assert_eq!(
        after.1.rc,
        rc::INSUFFICIENT_ACCESS,
        "the connection must be anonymous again after a failed bind"
    );

    h.shutdown().await;
}

/// **Failing case.** SASL is not implemented, and says so with
/// `authMethodNotSupported` rather than failing as bad credentials.
#[tokio::test]
async fn sasl_bind_is_reported_as_unsupported() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let res = ldap.sasl_external_bind().await.unwrap();
    assert_eq!(res.rc, rc::AUTH_METHOD_NOT_SUPPORTED, "{}", res.text);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// search: scope
// ---------------------------------------------------------------------------

/// **Passing case.** Each scope returns exactly the entries it should.
#[tokio::test]
async fn search_scopes_return_the_right_entries() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;
    let base = "dc=example,dc=com";

    assert_eq!(
        dns(&mut ldap, base, Scope::Base, "(objectClass=*)").await,
        vec![base]
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::OneLevel, "(objectClass=*)").await,
        vec![
            "ou=Groups,dc=example,dc=com".to_string(),
            "ou=People,dc=example,dc=com".to_string()
        ]
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(objectClass=*)")
            .await
            .len(),
        5
    );
    assert_eq!(
        dns(
            &mut ldap,
            "ou=People,dc=example,dc=com",
            Scope::OneLevel,
            "(objectClass=*)"
        )
        .await,
        vec![
            "cn=Alice,ou=People,dc=example,dc=com".to_string(),
            "cn=Bob,ou=People,dc=example,dc=com".to_string()
        ]
    );

    h.shutdown().await;
}

/// **Failing case.** A search based on an entry that does not exist is
/// `noSuchObject` with the closest existing ancestor — not an empty result.
/// The difference is what tells a client its base DN is wrong.
#[tokio::test]
async fn search_with_a_missing_base_is_no_such_object() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let res = ldap
        .search(
            "ou=Nowhere,dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap();
    assert_eq!(res.1.rc, rc::NO_SUCH_OBJECT, "{}", res.1.text);
    assert_eq!(res.1.matched, "dc=example,dc=com");
    assert!(res.0.is_empty());

    // A malformed base DN is a different, equally specific error.
    let res = ldap
        .search("not a dn", Scope::Base, "(objectClass=*)", vec!["dn"])
        .await
        .unwrap();
    assert_eq!(res.1.rc, rc::INVALID_DN_SYNTAX, "{}", res.1.text);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// search: filters
// ---------------------------------------------------------------------------

/// **Passing case.** Equality, presence, substring, negation, conjunction and
/// numeric ordering all select the entries they should.
#[tokio::test]
async fn filters_select_the_right_entries() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;
    let base = "dc=example,dc=com";

    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(cn=bob)").await,
        vec![BOB_DN],
        "equality is case-insensitive for cn"
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(mail=*)").await.len(),
        2,
        "presence"
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(mail=*@example.com)")
            .await
            .len(),
        2,
        "substring with a final anchor"
    );
    assert_eq!(
        dns(
            &mut ldap,
            base,
            Scope::Subtree,
            "(&(objectClass=person)(sn=Jones))"
        )
        .await,
        vec!["cn=Alice,ou=People,dc=example,dc=com"],
        "conjunction"
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(uidNumber>=1011)").await,
        vec!["cn=Alice,ou=People,dc=example,dc=com"],
        "integers compare numerically"
    );
    assert_eq!(
        dns(&mut ldap, base, Scope::Subtree, "(!(objectClass=person))")
            .await
            .len(),
        3,
        "negation"
    );

    h.shutdown().await;
}

/// **Failing case.** Filters that should match nothing match nothing. In
/// particular a literal `*` in an equality assertion is a value, not a
/// wildcard — if it were, this filter would return every entry with a `cn`.
#[tokio::test]
async fn filters_that_should_match_nothing_return_nothing() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;
    let base = "dc=example,dc=com";

    assert!(
        dns(&mut ldap, base, Scope::Subtree, "(cn=nobody)")
            .await
            .is_empty()
    );
    assert!(
        dns(&mut ldap, base, Scope::Subtree, "(telephoneNumber=*)")
            .await
            .is_empty()
    );
    assert!(
        dns(&mut ldap, base, Scope::Subtree, "(cn=\\2a)")
            .await
            .is_empty(),
        "an escaped asterisk is a literal value, not a wildcard"
    );
    assert!(
        dns(&mut ldap, base, Scope::Subtree, "(&(cn=bob)(cn=alice))")
            .await
            .is_empty(),
        "no entry is both"
    );

    h.shutdown().await;
}

/// **Failing case.** An assertion whose value is invalid for the attribute's
/// syntax is `Undefined`, and negating it does not turn it true. Were
/// `Undefined` folded into `false`, this filter would return the whole
/// directory.
#[tokio::test]
async fn a_negated_undefined_filter_does_not_return_everything() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;
    let base = "dc=example,dc=com";

    let matched = dns(
        &mut ldap,
        base,
        Scope::Subtree,
        "(!(uidNumber>=not-a-number))",
    )
    .await;
    assert!(
        matched.is_empty(),
        "an undefined assertion must stay undefined under negation, got {matched:?}"
    );

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// search: attributes and limits
// ---------------------------------------------------------------------------

/// **Passing case.** Attribute selection honours names, `*`, `+` and `1.1`.
#[tokio::test]
async fn attribute_selection_is_honoured() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let named = ldap
        .search(BOB_DN, Scope::Base, "(objectClass=*)", vec!["cn", "mail"])
        .await
        .unwrap()
        .success()
        .unwrap()
        .0;
    let entry = SearchEntry::construct(named[0].clone());
    assert_eq!(entry.attrs.len(), 2);
    assert!(entry.attrs.contains_key("cn"));
    assert!(entry.attrs.contains_key("mail"));

    let none = ldap
        .search(BOB_DN, Scope::Base, "(objectClass=*)", vec!["1.1"])
        .await
        .unwrap()
        .success()
        .unwrap()
        .0;
    let entry = SearchEntry::construct(none[0].clone());
    assert!(entry.attrs.is_empty(), "1.1 means the DN and nothing else");
    assert_eq!(entry.dn, BOB_DN);

    let all = ldap
        .search(BOB_DN, Scope::Base, "(objectClass=*)", vec!["*"])
        .await
        .unwrap()
        .success()
        .unwrap()
        .0;
    let entry = SearchEntry::construct(all[0].clone());
    assert!(entry.attrs.contains_key("sn"));
    assert!(entry.attrs.contains_key("uidNumber"));

    h.shutdown().await;
}

/// **Failing case.** A search that matches more entries than the size limit
/// allows returns the limit's worth and reports `sizeLimitExceeded` — it does
/// not silently truncate, which would look like a complete result set.
#[tokio::test]
async fn exceeding_the_size_limit_is_reported() {
    let h = Harness::with_config(
        r#"
[server]
listen = "127.0.0.1:0"
size_limit = 2

[backend]
kind = "memory"
suffix = "dc=example,dc=com"
"#,
    )
    .await;
    let mut ldap = h.connect().await;

    let res = ldap
        .search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap();
    assert_eq!(res.1.rc, rc::SIZE_LIMIT_EXCEEDED, "{}", res.1.text);
    assert_eq!(
        res.0.len(),
        2,
        "the limit's worth of entries is still returned"
    );

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// require_bind
// ---------------------------------------------------------------------------

/// **Failing case.** With `require_bind`, an anonymous search is refused; the
/// same search after binding succeeds.
#[tokio::test]
async fn require_bind_blocks_anonymous_searches() {
    let h = Harness::with_config(&common::default_config(true, true)).await;
    let mut ldap = h.connect().await;

    let res = ldap
        .search(
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap();
    assert_eq!(res.1.rc, rc::INSUFFICIENT_ACCESS, "{}", res.1.text);

    ldap.simple_bind(ADMIN_DN, ADMIN_PW)
        .await
        .unwrap()
        .success()
        .unwrap();
    let res = ldap
        .search(
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)",
            vec!["dn"],
        )
        .await
        .unwrap();
    assert_eq!(res.1.rc, rc::SUCCESS);

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// root DSE
// ---------------------------------------------------------------------------

/// **Passing case.** A base-scoped search of the empty DN returns the root
/// DSE, whose attributes must be asked for by name or with `+` because they
/// are operational.
#[tokio::test]
async fn root_dse_is_reachable_anonymously() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let (entries, res) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["+"])
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(res.rc, rc::SUCCESS);
    assert_eq!(entries.len(), 1);

    let entry = SearchEntry::construct(entries[0].clone());
    assert_eq!(entry.dn, "");
    assert_eq!(entry.attrs["namingContexts"], vec!["dc=example,dc=com"]);
    assert_eq!(entry.attrs["supportedLDAPVersion"], vec!["3"]);
    assert_eq!(entry.attrs["vendorName"], vec!["dyno-ldapserver"]);

    h.shutdown().await;
}

/// **Failing case.** The root DSE is not part of any subtree: a subtree search
/// of the empty DN searches the naming contexts and must not include it.
#[tokio::test]
async fn root_dse_is_not_returned_by_a_subtree_search() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let found = dns(&mut ldap, "", Scope::Subtree, "(objectClass=*)").await;
    assert!(
        !found.contains(&String::new()),
        "the root DSE must not appear in a subtree search, got {found:?}"
    );
    assert_eq!(found.len(), 5, "but the naming contexts are searched");

    h.shutdown().await;
}

// ---------------------------------------------------------------------------
// compare and extended operations
// ---------------------------------------------------------------------------

/// **Passing case.** Compare answers `compareTrue` and `compareFalse`, which
/// are distinct result codes rather than success-with-a-payload.
#[tokio::test]
async fn compare_returns_true_and_false_result_codes() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let yes = ldap.compare(BOB_DN, "cn", "BOB").await.unwrap();
    assert_eq!(yes.0.rc, rc::COMPARE_TRUE);
    assert!(yes.equal().unwrap());

    let no = ldap.compare(BOB_DN, "cn", "Alice").await.unwrap();
    assert_eq!(no.0.rc, rc::COMPARE_FALSE);
    assert!(!no.equal().unwrap());

    h.shutdown().await;
}

/// **Failing case.** Comparing against an entry that does not exist is
/// `noSuchObject`, not `compareFalse` — "no" and "no such entry" are different
/// answers.
#[tokio::test]
async fn compare_against_a_missing_entry_is_no_such_object() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let res = ldap
        .compare("cn=Ghost,ou=People,dc=example,dc=com", "cn", "Ghost")
        .await
        .unwrap();
    assert_eq!(res.0.rc, rc::NO_SUCH_OBJECT, "{}", res.0.text);

    h.shutdown().await;
}

/// **Passing case.** WhoAmI reports the identity actually in force, which is
/// empty before a bind and the bound DN afterwards.
#[tokio::test]
async fn whoami_reports_the_effective_identity() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let (exop, res) = ldap.extended(WhoAmI).await.unwrap().success().unwrap();
    assert_eq!(res.rc, rc::SUCCESS);
    let who: ldap3::exop::WhoAmIResp = exop.parse();
    assert_eq!(who.authzid, "", "anonymous before binding");

    ldap.simple_bind(ADMIN_DN, ADMIN_PW)
        .await
        .unwrap()
        .success()
        .unwrap();
    let (exop, _) = ldap.extended(WhoAmI).await.unwrap().success().unwrap();
    let who: ldap3::exop::WhoAmIResp = exop.parse();
    assert_eq!(who.authzid, format!("dn:{ADMIN_DN}"));

    h.shutdown().await;
}

/// **Failing case.** An extended operation we do not implement is reported as
/// such. StartTLS is answered `unavailable` — it is a recognised operation the
/// server cannot yet perform — while an unknown OID is a protocol error.
#[tokio::test]
async fn unsupported_extended_operations_are_reported_distinctly() {
    let h = Harness::start().await;
    let mut ldap = h.connect().await;

    let start_tls = ldap
        .extended(ldap3::exop::Exop {
            name: Some("1.3.6.1.4.1.1466.20037".to_string()),
            val: None,
        })
        .await
        .unwrap();
    assert_eq!(start_tls.1.rc, rc::UNAVAILABLE, "{}", start_tls.1.text);

    let nonsense = ldap
        .extended(ldap3::exop::Exop {
            name: Some("1.2.3.4.5.6.7.8.9".to_string()),
            val: None,
        })
        .await
        .unwrap();
    assert_eq!(nonsense.1.rc, rc::PROTOCOL_ERROR, "{}", nonsense.1.text);

    h.shutdown().await;
}

/// **Passing case.** A client that unbinds and disconnects does not disturb
/// the server: a new connection still works.
#[tokio::test]
async fn the_server_survives_a_client_disconnecting() {
    let h = Harness::start().await;

    {
        let mut ldap = h.connect().await;
        ldap.simple_bind(ADMIN_DN, ADMIN_PW)
            .await
            .unwrap()
            .success()
            .unwrap();
        ldap.unbind().await.unwrap();
    }

    let mut second = h.connect().await;
    assert_eq!(
        dns(
            &mut second,
            "dc=example,dc=com",
            Scope::Base,
            "(objectClass=*)"
        )
        .await
        .len(),
        1
    );

    h.shutdown().await;
}
