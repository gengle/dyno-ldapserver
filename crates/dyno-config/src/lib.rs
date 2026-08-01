//! Configuration: schema, loading, validation, and the handle the server
//! reads it through.
//!
//! # The validation rule
//!
//! A configuration is parsed and *fully validated* before anything is
//! published. Every DN is parsed, every listen address resolved, every backend
//! reference checked. Only then is it swapped in. A bad config therefore logs
//! an error and changes nothing — it never half-applies, and it never takes a
//! running server down.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dyno_core::Dn;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Why a configuration was rejected.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {message}")]
    Io {
        /// Path attempted.
        path: String,
        /// OS error text.
        message: String,
    },

    /// The TOML did not parse, or did not match the schema.
    #[error("invalid TOML: {0}")]
    Toml(String),

    /// A DN in the config is not a valid DN.
    #[error("{field}: {value:?} is not a valid DN: {source}")]
    InvalidDn {
        /// Which setting.
        field: &'static str,
        /// What was written.
        value: String,
        /// The parse failure.
        source: dyno_core::DnError,
    },

    /// A listen address could not be parsed.
    #[error("server.listen: {value:?} is not a valid socket address")]
    InvalidListenAddress {
        /// What was written.
        value: String,
    },

    /// A referenced file is missing.
    #[error("{field}: file {path} does not exist")]
    MissingFile {
        /// Which setting.
        field: &'static str,
        /// The path.
        path: String,
    },

    /// A setting is required for the chosen backend but was not given.
    #[error("backend of kind {kind:?} requires {field}")]
    MissingField {
        /// Backend kind.
        kind: String,
        /// The missing setting.
        field: &'static str,
    },

    /// A semantic problem that is not any of the above.
    #[error("{0}")]
    Invalid(String),
}

/// Which backend to serve from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendConfig {
    /// A writable in-memory directory, optionally seeded from an LDIF file.
    Memory {
        /// The naming context this backend serves.
        suffix: String,
        /// Optional LDIF file to seed from at startup.
        #[serde(default)]
        seed: Option<PathBuf>,
    },
    /// A read-only directory loaded from an LDIF file.
    Ldif {
        /// Path to the file.
        path: PathBuf,
    },
}

impl BackendConfig {
    /// The config-file name of this kind, for error messages.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Memory { .. } => "memory",
            Self::Ldif { .. } => "ldif",
        }
    }
}

/// A statically configured account that may bind.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserConfig {
    /// The bind DN.
    pub dn: String,
    /// The password, in cleartext.
    ///
    /// Cleartext in a config file is a deliberate Phase 1 simplification for a
    /// server whose purpose is test fixtures. It is why [`std::fmt::Debug`] is
    /// implemented by hand below — a config dump must not print it.
    pub password: String,
}

impl std::fmt::Debug for UserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserConfig")
            .field("dn", &self.dn)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Listener and limit settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Server-side maximum number of entries per search. A client may ask for
    /// fewer; it may not ask for more.
    #[serde(default = "default_size_limit")]
    pub size_limit: usize,

    /// Server-side maximum seconds per search.
    #[serde(default = "default_time_limit")]
    pub time_limit: u64,

    /// Largest BER element accepted from a client, in bytes. The protocol
    /// library defaults to 32 KiB; raising it is a deliberate decision because
    /// it raises the cost of a hostile connection.
    #[serde(default = "default_max_ber_size")]
    pub max_ber_size: usize,

    /// Whether operations other than bind require a successful bind first.
    /// With this off, the directory is readable anonymously.
    #[serde(default)]
    pub require_bind: bool,

    /// Whether an authenticated client may write.
    #[serde(default = "default_true")]
    pub allow_writes: bool,
}

const fn default_true() -> bool {
    true
}
fn default_listen() -> String {
    "127.0.0.1:3389".to_string()
}
const fn default_size_limit() -> usize {
    1000
}
const fn default_time_limit() -> u64 {
    30
}
const fn default_max_ber_size() -> usize {
    32 * 1024
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            size_limit: default_size_limit(),
            time_limit: default_time_limit(),
            max_ber_size: default_max_ber_size(),
            require_bind: false,
            allow_writes: true,
        }
    }
}

/// The whole configuration, as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Listener and limits.
    #[serde(default)]
    pub server: ServerConfig,
    /// The backend to serve.
    pub backend: BackendConfig,
    /// Static accounts that may bind.
    #[serde(default, rename = "user")]
    pub users: Vec<UserConfig>,
}

/// A configuration whose values have been parsed and checked.
///
/// Holding one of these is proof that validation ran: the server takes
/// `SocketAddr` and [`Dn`], not strings it has to re-parse and re-handle
/// failure for on every request.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The raw config, for logging and round-tripping.
    pub raw: Config,
    /// Parsed listen address.
    pub listen: SocketAddr,
    /// Parsed static accounts.
    pub users: Vec<(Dn, String)>,
    /// The naming context, where the backend kind implies one.
    pub suffix: Option<Dn>,
}

impl ValidatedConfig {
    /// Look up a static account by bind DN, comparing DNs structurally.
    #[must_use]
    pub fn find_user(&self, dn: &Dn) -> Option<&str> {
        self.users
            .iter()
            .find(|(d, _)| d == dn)
            .map(|(_, p)| p.as_str())
    }
}

impl Config {
    /// Parse TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Toml`] if the document does not parse or does
    /// not match the schema.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))
    }

    /// Read and parse a TOML file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] if unreadable, [`ConfigError::Toml`] if malformed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Self::from_toml(&text)
    }

    /// Check everything that can be checked without starting the server.
    ///
    /// # Errors
    ///
    /// The first problem found, as a [`ConfigError`] naming the setting.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        let listen: SocketAddr =
            self.server
                .listen
                .parse()
                .map_err(|_| ConfigError::InvalidListenAddress {
                    value: self.server.listen.clone(),
                })?;

        if self.server.size_limit == 0 {
            return Err(ConfigError::Invalid(
                "server.size_limit must be at least 1; use a large value rather than 0 for 'no limit'".into(),
            ));
        }

        let mut users = Vec::with_capacity(self.users.len());
        for u in &self.users {
            let dn = Dn::parse(&u.dn).map_err(|source| ConfigError::InvalidDn {
                field: "user.dn",
                value: u.dn.clone(),
                source,
            })?;
            if dn.is_empty() {
                return Err(ConfigError::Invalid(
                    "user.dn must not be empty; the empty DN is the anonymous identity".into(),
                ));
            }
            if u.password.is_empty() {
                // RFC 4513 §5.1.2: a bind with a DN and an empty password is
                // an unauthenticated bind, not a successful one. An account
                // configured this way could never be used, so it is a config
                // error rather than a silently dead entry.
                return Err(ConfigError::Invalid(format!(
                    "user {:?} has an empty password, which can never authenticate",
                    u.dn
                )));
            }
            if users.iter().any(|(d, _): &(Dn, String)| d == &dn) {
                return Err(ConfigError::Invalid(format!(
                    "user {:?} is configured more than once",
                    u.dn
                )));
            }
            users.push((dn, u.password.clone()));
        }

        let suffix = match &self.backend {
            BackendConfig::Memory { suffix, seed } => {
                let dn = Dn::parse(suffix).map_err(|source| ConfigError::InvalidDn {
                    field: "backend.suffix",
                    value: suffix.clone(),
                    source,
                })?;
                if dn.is_empty() {
                    return Err(ConfigError::MissingField {
                        kind: "memory".into(),
                        field: "suffix",
                    });
                }
                if let Some(seed) = seed {
                    if !seed.exists() {
                        return Err(ConfigError::MissingFile {
                            field: "backend.seed",
                            path: seed.display().to_string(),
                        });
                    }
                }
                Some(dn)
            }
            BackendConfig::Ldif { path } => {
                if !path.exists() {
                    return Err(ConfigError::MissingFile {
                        field: "backend.path",
                        path: path.display().to_string(),
                    });
                }
                None
            }
        };

        Ok(ValidatedConfig {
            listen,
            users,
            suffix,
            raw: self,
        })
    }
}

/// A hot-swappable handle to the current configuration.
///
/// Readers take a snapshot; a reload publishes a new `Arc` only after the new
/// config validates. In-flight operations therefore finish against the config
/// they started with, and a bad reload changes nothing.
#[derive(Debug)]
pub struct ConfigHandle {
    current: ArcSwap<ValidatedConfig>,
    source: Option<PathBuf>,
}

impl ConfigHandle {
    /// Wrap an already-validated config.
    #[must_use]
    pub fn new(config: ValidatedConfig) -> Self {
        Self {
            current: ArcSwap::from_pointee(config),
            source: None,
        }
    }

    /// Load, validate and wrap a config file, remembering the path so it can
    /// be reloaded later.
    ///
    /// # Errors
    ///
    /// As [`Config::load`] and [`Config::validate`].
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let validated = Config::load(&path)?.validate()?;
        Ok(Self {
            current: ArcSwap::from_pointee(validated),
            source: Some(path),
        })
    }

    /// The current configuration.
    #[must_use]
    pub fn load(&self) -> Arc<ValidatedConfig> {
        self.current.load_full()
    }

    /// The file this was loaded from, if any.
    #[must_use]
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// Re-read and re-validate the source file, publishing it only if it is
    /// good.
    ///
    /// # Errors
    ///
    /// Returns the validation failure and leaves the running config in place.
    pub fn reload(&self) -> Result<Arc<ValidatedConfig>, ConfigError> {
        let Some(path) = self.source.as_ref() else {
            return Err(ConfigError::Invalid(
                "this configuration was not loaded from a file and cannot be reloaded".into(),
            ));
        };
        let validated = Arc::new(Config::load(path)?.validate()?);
        self.current.store(Arc::clone(&validated));
        Ok(validated)
    }

    /// Publish an already-validated config. Used by tests and by the future
    /// file-watch path.
    pub fn publish(&self, config: ValidatedConfig) {
        self.current.store(Arc::new(config));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[server]
listen = "127.0.0.1:3899"
size_limit = 50

[backend]
kind = "memory"
suffix = "dc=example,dc=com"

[[user]]
dn = "cn=admin,dc=example,dc=com"
password = "adminpw"
"#;

    /// Passing case: a well-formed config parses and validates, and the
    /// validated form carries parsed types rather than strings.
    #[test]
    fn accepts_a_well_formed_config() {
        let v = Config::from_toml(GOOD).unwrap().validate().unwrap();
        assert_eq!(v.listen.port(), 3899);
        assert_eq!(v.raw.server.size_limit, 50);
        assert_eq!(v.suffix, Some(Dn::parse("dc=example,dc=com").unwrap()));
        // DN lookup is structural: a differently-spelled DN still matches.
        assert_eq!(
            v.find_user(&Dn::parse("CN=Admin, DC=Example, DC=Com").unwrap()),
            Some("adminpw")
        );
    }

    /// Validation: omitted settings take documented defaults rather than
    /// failing, so a minimal config is usable.
    #[test]
    fn applies_defaults_for_omitted_settings() {
        let v = Config::from_toml("[backend]\nkind = \"memory\"\nsuffix = \"dc=x\"\n")
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(v.listen.to_string(), "127.0.0.1:3389");
        assert_eq!(v.raw.server.max_ber_size, 32 * 1024);
        assert!(!v.raw.server.require_bind);
        assert!(v.raw.server.allow_writes);
    }

    /// Failing case: a malformed DN is rejected at load time, naming the
    /// setting. Finding this at the first bind instead would be much worse.
    #[test]
    fn rejects_a_malformed_dn() {
        let toml = GOOD.replace("cn=admin,dc=example,dc=com", "not a dn");
        let err = Config::from_toml(&toml).unwrap().validate().unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::InvalidDn {
                    field: "user.dn",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Failing case: a listen address that is not an address.
    #[test]
    fn rejects_a_malformed_listen_address() {
        let toml = GOOD.replace("127.0.0.1:3899", "not-an-address");
        let err = Config::from_toml(&toml).unwrap().validate().unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidListenAddress { .. }),
            "{err}"
        );
    }

    /// Failing case: an account with an empty password can never authenticate
    /// (RFC 4513 §5.1.2 makes that an unauthenticated bind), so it is a config
    /// error rather than a quietly unusable account.
    #[test]
    fn rejects_a_user_with_an_empty_password() {
        let toml = GOOD.replace("password = \"adminpw\"", "password = \"\"");
        let err = Config::from_toml(&toml).unwrap().validate().unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
    }

    /// Failing case: an LDIF backend pointing at a file that is not there.
    #[test]
    fn rejects_a_missing_backend_file() {
        let toml = "[backend]\nkind = \"ldif\"\npath = \"/nonexistent/dir.ldif\"\n";
        let err = Config::from_toml(toml).unwrap().validate().unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::MissingFile {
                    field: "backend.path",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Failing case: an unknown backend kind is a schema error, not a silent
    /// fallback to some default backend.
    #[test]
    fn rejects_an_unknown_backend_kind() {
        let err = Config::from_toml("[backend]\nkind = \"postgres\"\n").unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)), "{err}");
    }

    /// Validation: passwords never appear in `Debug` output, which is how they
    /// would otherwise reach a log line.
    #[test]
    fn debug_output_redacts_passwords() {
        let cfg = Config::from_toml(GOOD).unwrap();
        let dumped = format!("{cfg:?}");
        assert!(
            !dumped.contains("adminpw"),
            "config debug leaked a password"
        );
        assert!(dumped.contains("<redacted>"));
    }

    /// Passing case: a failed reload leaves the running config in place. This
    /// is the whole point of validating before publishing.
    #[test]
    fn a_failed_reload_changes_nothing() {
        let dir = std::env::temp_dir().join("dyno-config-reload-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, GOOD).unwrap();

        let handle = ConfigHandle::from_file(&path).unwrap();
        assert_eq!(handle.load().listen.port(), 3899);

        // Publish a good change.
        std::fs::write(&path, GOOD.replace("3899", "3900")).unwrap();
        handle.reload().unwrap();
        assert_eq!(handle.load().listen.port(), 3900);

        // Now break it.
        std::fs::write(&path, "this is not toml {{{").unwrap();
        assert!(handle.reload().is_err());
        assert_eq!(
            handle.load().listen.port(),
            3900,
            "a broken reload must not disturb the running config"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
