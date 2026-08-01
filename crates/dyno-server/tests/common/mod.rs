//! Shared harness: start a real server on an ephemeral port and connect a
//! real LDAP client to it.
//!
//! Everything happens in-process. There is no container and no fixed port, so
//! the protocol tests run in parallel with each other and on any machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

use std::sync::Arc;

use dyno_backend::{Backend, MemoryBackend};
use dyno_config::{Config, ConfigHandle};
use dyno_core::{Dn, Entry, Schema};
use dyno_server::{Handler, RunningServer, serve};
use ldap3::{Ldap, LdapConnAsync};

/// The directory every protocol test starts from.
pub const SUFFIX: &str = "dc=example,dc=com";
/// A configured administrator that may write.
pub const ADMIN_DN: &str = "cn=admin,dc=example,dc=com";
/// That administrator's password.
pub const ADMIN_PW: &str = "adminpw";
/// A user whose password lives in the directory rather than the config.
pub const BOB_DN: &str = "cn=Bob,ou=People,dc=example,dc=com";
/// Bob's password.
pub const BOB_PW: &str = "bobsecret";

/// A running server plus the address to reach it on.
pub struct Harness {
    pub server: RunningServer,
    pub url: String,
    pub backend: Arc<dyn Backend>,
}

impl Harness {
    /// Start a server with the default fixture directory.
    pub async fn start() -> Self {
        Self::with_config(&default_config(false, true)).await
    }

    /// Start a server from a TOML configuration string.
    pub async fn with_config(toml: &str) -> Self {
        let validated = Config::from_toml(toml)
            .expect("test config should parse")
            .validate()
            .expect("test config should validate");

        let schema = Arc::new(Schema::builtin());
        let backend = Arc::new(MemoryBackend::new(
            "memory",
            vec![dn(SUFFIX)],
            Arc::clone(&schema),
        ));
        for entry in fixture_entries() {
            backend.insert(entry).expect("seeding the fixture");
        }

        let backend: Arc<dyn Backend> = backend;
        let handle = Arc::new(ConfigHandle::new(validated));
        let handler = Arc::new(Handler::new(Arc::clone(&backend), handle));
        let server = serve("127.0.0.1:0".parse().expect("valid address"), handler)
            .await
            .expect("server should bind an ephemeral port");
        let url = format!("ldap://{}", server.local_addr());

        Self {
            server,
            url,
            backend,
        }
    }

    /// Open a client connection. The driver task is spawned for you.
    pub async fn connect(&self) -> Ldap {
        let (conn, ldap) = LdapConnAsync::new(&self.url)
            .await
            .expect("client should connect");
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                eprintln!("client connection driver ended: {e}");
            }
        });
        ldap
    }

    /// Open a connection already bound as the administrator.
    pub async fn connect_as_admin(&self) -> Ldap {
        let mut ldap = self.connect().await;
        ldap.simple_bind(ADMIN_DN, ADMIN_PW)
            .await
            .expect("bind request should be answered")
            .success()
            .expect("admin credentials should be accepted");
        ldap
    }

    /// Stop the server.
    pub async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// Parse a DN, panicking on failure — test fixtures are not untrusted input.
pub fn dn(s: &str) -> Dn {
    Dn::parse(s).unwrap_or_else(|e| panic!("fixture DN {s:?} is invalid: {e}"))
}

/// The default configuration: anonymous reads allowed, writes permitted for
/// authenticated clients, one configured administrator.
pub fn default_config(require_bind: bool, allow_writes: bool) -> String {
    format!(
        r#"
[server]
listen = "127.0.0.1:0"
size_limit = 100
time_limit = 30
require_bind = {require_bind}
allow_writes = {allow_writes}

[backend]
kind = "memory"
suffix = "{SUFFIX}"

[[user]]
dn = "{ADMIN_DN}"
password = "{ADMIN_PW}"
"#
    )
}

/// The fixture directory: a suffix, two organisational units, and two people.
pub fn fixture_entries() -> Vec<Entry> {
    let mut bob = Entry::new(dn(BOB_DN))
        .with("objectClass", &["top", "person", "inetOrgPerson"])
        .with("cn", &["Bob"])
        .with("sn", &["Smith"])
        .with("uid", &["bsmith"])
        .with("uidNumber", &["1010"])
        .with("mail", &["bob@example.com"]);
    bob.set("userPassword", vec![BOB_PW.into()]);

    vec![
        Entry::new(dn(SUFFIX))
            .with("objectClass", &["top", "domain"])
            .with("dc", &["example"]),
        Entry::new(dn("ou=People,dc=example,dc=com"))
            .with("objectClass", &["top", "organizationalUnit"])
            .with("ou", &["People"]),
        Entry::new(dn("ou=Groups,dc=example,dc=com"))
            .with("objectClass", &["top", "organizationalUnit"])
            .with("ou", &["Groups"]),
        bob,
        Entry::new(dn("cn=Alice,ou=People,dc=example,dc=com"))
            .with("objectClass", &["top", "person", "inetOrgPerson"])
            .with("cn", &["Alice"])
            .with("sn", &["Jones"])
            .with("uid", &["ajones"])
            .with("uidNumber", &["1011"])
            .with("mail", &["alice@example.com"]),
    ]
}
