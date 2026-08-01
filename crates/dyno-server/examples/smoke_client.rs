//! A manual smoke test against a running server.
//!
//! `ldapsearch` is not installed in this environment, so this stands in for it:
//! it binds, searches, adds an object, finds it, deletes it, and confirms it is
//! gone, printing each step.
//!
//! ```text
//! cargo run -p dyno-server -- --config dyno.toml &
//! cargo run -p dyno-server --example smoke_client -- ldap://127.0.0.1:3389
//! ```

use std::collections::HashSet;

use ldap3::{LdapConnAsync, Scope, SearchEntry};

const ADMIN_DN: &str = "cn=admin,dc=example,dc=com";
const ADMIN_PW: &str = "adminpw";
const BASE: &str = "dc=example,dc=com";
const NEW_DN: &str = "cn=Carol Danvers,ou=People,dc=example,dc=com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ldap://127.0.0.1:3389".to_string());

    let (conn, mut ldap) = LdapConnAsync::new(&url).await?;
    tokio::spawn(async move { conn.drive().await });
    println!("connected to {url}");

    // Root DSE.
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["+"])
        .await?
        .success()?;
    for e in entries {
        let e = SearchEntry::construct(e);
        println!(
            "root DSE: namingContexts={:?} vendor={:?}",
            e.attrs.get("namingContexts"),
            e.attrs.get("vendorName")
        );
    }

    // Anonymous read.
    let (entries, _) = ldap
        .search(BASE, Scope::Subtree, "(objectClass=*)", vec!["dn"])
        .await?
        .success()?;
    println!("anonymous subtree search found {} entries", entries.len());

    // An anonymous write must be refused.
    let refused = ldap.add(NEW_DN, carol()).await?;
    println!(
        "anonymous add -> result code {} ({})",
        refused.rc, refused.text
    );
    assert_ne!(refused.rc, 0, "anonymous writes must not succeed");

    // Bind and write.
    ldap.simple_bind(ADMIN_DN, ADMIN_PW).await?.success()?;
    println!("bound as {ADMIN_DN}");

    ldap.add(NEW_DN, carol()).await?.success()?;
    println!("added {NEW_DN}");

    let (found, _) = ldap
        .search(BASE, Scope::Subtree, "(cn=carol*)", vec!["cn", "mail"])
        .await?
        .success()?;
    for e in found {
        let e = SearchEntry::construct(e);
        println!("  found {} mail={:?}", e.dn, e.attrs.get("mail"));
    }

    ldap.delete(NEW_DN).await?.success()?;
    println!("deleted {NEW_DN}");

    let (after, _) = ldap
        .search(BASE, Scope::Subtree, "(cn=carol*)", vec!["dn"])
        .await?
        .success()?;
    println!("entries matching (cn=carol*) after delete: {}", after.len());
    assert!(after.is_empty(), "the entry should be gone");

    ldap.unbind().await?;
    println!("smoke test passed");
    Ok(())
}

fn carol() -> Vec<(String, HashSet<String>)> {
    vec![
        (
            "objectClass".to_string(),
            ["top", "person", "inetOrgPerson"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        ),
        (
            "cn".to_string(),
            ["Carol Danvers"].iter().map(|s| (*s).to_string()).collect(),
        ),
        (
            "sn".to_string(),
            ["Danvers"].iter().map(|s| (*s).to_string()).collect(),
        ),
        (
            "mail".to_string(),
            ["carol@example.com"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        ),
    ]
}
