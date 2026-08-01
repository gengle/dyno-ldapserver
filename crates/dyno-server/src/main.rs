//! `dyno-ldapserver` — a dynamic LDAP server.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use dyno_config::ConfigHandle;
use dyno_server::{Handler, build_backend, serve};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Command line arguments.
#[derive(Debug, Parser)]
#[command(name = "dyno-ldapserver", version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "dyno.toml")]
    config: std::path::PathBuf,

    /// Validate the configuration and exit without listening.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let handle = Arc::new(
        ConfigHandle::from_file(&args.config)
            .with_context(|| format!("loading {}", args.config.display()))?,
    );
    let config = handle.load();
    let backend = build_backend(&config).context("building the backend")?;

    if args.check {
        let contexts: Vec<String> = backend
            .naming_contexts()
            .iter()
            .map(ToString::to_string)
            .collect();
        info!(
            path = %args.config.display(),
            backend = backend.name(),
            ?contexts,
            "configuration is valid"
        );
        return Ok(());
    }

    let handler = Arc::new(Handler::new(backend, Arc::clone(&handle)));
    let running = serve(config.listen, handler)
        .await
        .with_context(|| format!("binding {}", config.listen))?;

    info!(addr = %running.local_addr(), "dyno-ldapserver ready");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
        let mut term = signal(SignalKind::terminate()).context("installing the TERM handler")?;
        loop {
            tokio::select! {
                _ = hup.recv() => reload(&handle),
                _ = term.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }

    info!("shutting down");
    running.shutdown().await;
    Ok(())
}

/// Re-read the configuration file on SIGHUP.
///
/// A file that fails to parse or validate is logged and discarded: the running
/// configuration stays exactly as it was, and no connection is dropped.
/// Listener address and backend changes are not picked up — those need a
/// restart, and pretending otherwise would leave the process describing a
/// state it is not in.
fn reload(handle: &ConfigHandle) {
    let before = handle.load();
    match handle.reload() {
        Ok(after) => {
            if after.listen != before.listen {
                warn!(
                    old = %before.listen,
                    new = %after.listen,
                    "listen address changed in the config; restart to apply it"
                );
            }
            if after.raw.backend != before.raw.backend {
                warn!("backend changed in the config; restart to apply it");
            }
            info!("configuration reloaded");
        }
        Err(e) => {
            error!(error = %e, "reload failed; keeping the running configuration");
        }
    }
}
