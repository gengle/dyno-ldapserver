//! The TCP listener and the per-connection task.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::LdapResultCode;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::handler::{Handler, disconnect_notice};
use crate::session::Session;

/// A listening server.
///
/// Dropping this does not stop the server; call [`RunningServer::shutdown`].
/// Tests bind port 0 and read [`RunningServer::local_addr`], so they never
/// race each other over a fixed port.
#[derive(Debug)]
pub struct RunningServer {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    /// The address actually bound, which matters when port 0 was requested.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting new connections and wait for the accept loop to finish.
    ///
    /// In-flight connections are not forcibly closed; they end when the client
    /// unbinds or disconnects.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

/// Bind a listener and start accepting connections.
///
/// # Errors
///
/// Whatever `TcpListener::bind` returns — in practice, the port being in use
/// or not permitted.
pub async fn serve(addr: SocketAddr, handler: Arc<Handler>) -> std::io::Result<RunningServer> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, handler)
}

/// Start accepting on an already-bound listener.
///
/// # Errors
///
/// Whatever `TcpListener::local_addr` returns.
pub fn serve_on(listener: TcpListener, handler: Arc<Handler>) -> std::io::Result<RunningServer> {
    let local_addr = listener.local_addr()?;
    let (shutdown, mut rx) = watch::channel(false);

    let task = tokio::spawn(async move {
        info!(%local_addr, "listening");
        loop {
            tokio::select! {
                // Biased so that a shutdown request is noticed even when
                // connections are arriving continuously.
                biased;
                _ = rx.changed() => {
                    if *rx.borrow() {
                        info!(%local_addr, "shutting down listener");
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let handler = Arc::clone(&handler);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, peer, handler).await {
                                    debug!(%peer, error = %e, "connection ended with an error");
                                }
                            });
                        }
                        Err(e) => {
                            // A failed accept is usually a per-connection
                            // problem (fd limits, a client that vanished).
                            // Killing the listener over it would turn a
                            // transient fault into an outage.
                            warn!(error = %e, "accept failed");
                        }
                    }
                }
            }
        }
    });

    Ok(RunningServer {
        local_addr,
        shutdown,
        task,
    })
}

/// Serve one client connection until it unbinds, disconnects, or errs.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<Handler>,
) -> std::io::Result<()> {
    let config = handler.config().load();
    // Nagle's algorithm adds latency to the small request/response exchanges
    // LDAP is made of, and there is nothing to coalesce.
    let _ = stream.set_nodelay(true);

    let codec = LdapCodec::new(Some(config.raw.server.max_ber_size), None);
    let mut framed = Framed::new(stream, codec);
    let mut session = Session::new(
        peer,
        false,
        config.raw.server.require_bind,
        config.raw.server.allow_writes,
    );

    debug!(%peer, "connection opened");

    while let Some(decoded) = framed.next().await {
        let msg = match decoded {
            Ok(msg) => msg,
            Err(e) => {
                // A decode failure means we no longer know where the next
                // message begins, so the only safe action is to say so and
                // close. Continuing would risk interpreting the remainder of a
                // malformed element as a new request.
                warn!(%peer, error = %e, "protocol error while decoding");
                let notice = disconnect_notice(
                    LdapResultCode::ProtocolError,
                    "malformed request; closing connection",
                );
                let _ = framed.send(notice).await;
                let _ = framed.close().await;
                return Ok(());
            }
        };

        let reply = handler.handle(msg, &mut session).await;
        for out in reply.messages {
            if let Err(e) = framed.send(out).await {
                error!(%peer, error = %e, "failed to send response");
                return Err(e);
            }
        }
        if reply.close {
            break;
        }
    }

    debug!(%peer, "connection closed");
    let _ = framed.close().await;
    Ok(())
}
