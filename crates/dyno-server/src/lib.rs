//! The LDAP server: listeners, session state, and the operation pipeline.
//!
//! The binary is a thin wrapper over this library so that the whole server can
//! be started in-process by a test, on port 0, and driven with a real LDAP
//! client. Protocol tests that need a container are protocol tests nobody runs.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod convert;
pub mod handler;
pub mod rootdse;
pub mod server;
pub mod session;

use std::sync::Arc;

use dyno_backend::{Backend, LdifBackend, MemoryBackend};
use dyno_config::{BackendConfig, ValidatedConfig};
use dyno_core::Schema;

pub use handler::{Handler, Reply};
pub use server::{RunningServer, serve, serve_on};
pub use session::{AuthState, Session};

/// Why a backend could not be built from configuration.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The LDIF file named in the config could not be loaded.
    #[error("cannot load LDIF: {0}")]
    Ldif(#[from] dyno_backend::LdifError),
    /// The backend rejected its seed data.
    #[error("cannot build backend: {0}")]
    Backend(#[from] dyno_backend::BackendError),
    /// The configuration was internally inconsistent in a way validation
    /// could not catch on its own.
    #[error("{0}")]
    Config(String),
}

/// Construct the backend a validated configuration describes.
///
/// # Errors
///
/// [`BuildError`] if the seed data is unreadable or inconsistent.
pub fn build_backend(config: &ValidatedConfig) -> Result<Arc<dyn Backend>, BuildError> {
    let schema = Arc::new(Schema::builtin());
    match &config.raw.backend {
        BackendConfig::Memory { seed, .. } => {
            let suffix = config.suffix.clone().ok_or_else(|| {
                BuildError::Config("a memory backend requires a suffix".to_string())
            })?;
            let backend = match seed {
                Some(path) => {
                    let text = std::fs::read_to_string(path).map_err(|e| {
                        BuildError::Config(format!("cannot read {}: {e}", path.display()))
                    })?;
                    let entries = dyno_backend::parse_ldif(&text)?;
                    let backend =
                        MemoryBackend::new(config.raw.backend.kind_name(), vec![suffix], schema);
                    for entry in entries {
                        backend.insert(entry)?;
                    }
                    backend
                }
                None => MemoryBackend::new(config.raw.backend.kind_name(), vec![suffix], schema),
            };
            Ok(Arc::new(backend))
        }
        BackendConfig::Ldif { path } => Ok(Arc::new(LdifBackend::load(path, schema)?)),
    }
}
