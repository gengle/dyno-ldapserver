//! The operation pipeline.
//!
//! One [`Handler`] is shared by every connection; per-connection state lives
//! in [`Session`]. [`Handler::handle`] takes a decoded message and returns the
//! messages to send back plus whether to keep the connection open, which makes
//! the whole pipeline testable without a socket.
//!
//! Rule stages (Phase 2) will slot in either side of the backend call, which
//! is why request conversion, the backend call and response construction are
//! kept as separate steps even where that is currently more code.

use std::sync::Arc;
use std::time::Duration;

use dyno_backend::{Backend, BackendError, BindOutcome};
use dyno_config::ConfigHandle;
use dyno_core::Dn;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedRequest, LdapExtendedResponse,
    LdapMsg, LdapOp, LdapResult, LdapResultCode, LdapSearchRequest, OID_WHOAMI,
};
use tracing::{debug, info, warn};

use crate::convert::{self, ConvertError, ServerLimits};
use crate::rootdse;
use crate::session::{OpClass, Refusal, Session};

/// The StartTLS extended operation OID (RFC 4511 §4.14).
pub const OID_START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// What the connection loop should do after a message has been handled.
#[derive(Debug)]
pub struct Reply {
    /// Messages to send, in order.
    pub messages: Vec<LdapMsg>,
    /// Whether to close the connection afterwards.
    pub close: bool,
}

impl Reply {
    fn ok(messages: Vec<LdapMsg>) -> Self {
        Self {
            messages,
            close: false,
        }
    }

    fn one(msgid: i32, op: LdapOp) -> Self {
        Self::ok(vec![LdapMsg::new(msgid, op)])
    }

    fn close_now() -> Self {
        Self {
            messages: Vec::new(),
            close: true,
        }
    }

    fn fatal(messages: Vec<LdapMsg>) -> Self {
        Self {
            messages,
            close: true,
        }
    }
}

/// Build an `LdapResult` with no matched DN or referral.
fn result(code: LdapResultCode, message: impl Into<String>) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message: message.into(),
        referral: Vec::new(),
    }
}

/// Build an `LdapResult` including a matched DN, for `noSuchObject`.
fn result_matched(
    code: LdapResultCode,
    message: impl Into<String>,
    matched: Option<&Dn>,
) -> LdapResult {
    LdapResult {
        code,
        matcheddn: matched.map(ToString::to_string).unwrap_or_default(),
        message: message.into(),
        referral: Vec::new(),
    }
}

/// Map a backend error onto the LDAP result code a client can act on.
///
/// The mapping is exhaustive by design: adding a backend error variant should
/// force a decision here rather than falling into a generic `operationsError`.
fn backend_result(err: &BackendError) -> LdapResult {
    use BackendError as E;
    match err {
        E::NoSuchObject { matched } => result_matched(
            LdapResultCode::NoSuchObject,
            err.to_string(),
            matched.as_ref(),
        ),
        E::NoSuchParent { matched } => result_matched(
            LdapResultCode::NoSuchObject,
            err.to_string(),
            matched.as_ref(),
        ),
        E::EntryAlreadyExists => result(LdapResultCode::EntryAlreadyExists, err.to_string()),
        E::NotAllowedOnNonLeaf => result(LdapResultCode::NotAllowedOnNonLeaf, err.to_string()),
        E::AttributeOrValueExists { .. } => {
            result(LdapResultCode::AttributeOrValueExists, err.to_string())
        }
        E::NoSuchAttribute { .. } => result(LdapResultCode::NoSuchAttribute, err.to_string()),
        E::ObjectClassViolation(_) => result(LdapResultCode::ObjectClassViolation, err.to_string()),
        E::ConstraintViolation(_) => result(LdapResultCode::ConstraintViolation, err.to_string()),
        E::NamingViolation(_) => result(LdapResultCode::NamingViolation, err.to_string()),
        E::Unwilling(_) => result(LdapResultCode::UnwillingToPerform, err.to_string()),
        E::Unavailable(_) => result(LdapResultCode::Unavailable, err.to_string()),
        // The only variant that becomes an opaque error, and it means a fault
        // inside the server rather than anything the client did.
        E::Internal(_) => result(LdapResultCode::OperationsError, "internal error"),
    }
}

/// Constant-time comparison for configured passwords.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Handles decoded operations against a backend and configuration.
#[derive(Debug)]
pub struct Handler {
    backend: Arc<dyn Backend>,
    config: Arc<ConfigHandle>,
}

impl Handler {
    /// Build a handler.
    #[must_use]
    pub const fn new(backend: Arc<dyn Backend>, config: Arc<ConfigHandle>) -> Self {
        Self { backend, config }
    }

    /// The backend being served.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// The configuration handle.
    #[must_use]
    pub fn config(&self) -> &Arc<ConfigHandle> {
        &self.config
    }

    /// Handle one decoded message.
    pub async fn handle(&self, msg: LdapMsg, session: &mut Session) -> Reply {
        // Message ID 0 is reserved for unsolicited notifications from the
        // server. A request carrying it cannot be answered unambiguously.
        if msg.msgid == 0 && !matches!(msg.op, LdapOp::UnbindRequest) {
            return Reply::fatal(vec![disconnect_notice(
                LdapResultCode::ProtocolError,
                "message id 0 is reserved for unsolicited notifications",
            )]);
        }

        match msg.op {
            LdapOp::BindRequest(req) => self.bind(msg.msgid, req, session).await,
            LdapOp::UnbindRequest => Reply::close_now(),
            LdapOp::SearchRequest(req) => self.search(msg.msgid, req, session).await,
            LdapOp::AddRequest(req) => self.add(msg.msgid, &req, session).await,
            LdapOp::DelRequest(dn) => self.delete(msg.msgid, &dn, session).await,
            LdapOp::ModifyRequest(req) => self.modify(msg.msgid, &req, session).await,
            LdapOp::ModifyDNRequest(req) => self.modify_dn(msg.msgid, &req, session).await,
            LdapOp::CompareRequest(req) => self.compare(msg.msgid, &req, session).await,
            LdapOp::ExtendedRequest(req) => self.extended(msg.msgid, &req, session),
            LdapOp::AbandonRequest(target) => {
                // Abandon has no response, ever. Operations here are short
                // enough that there is nothing to interrupt.
                debug!(target_msgid = target, "abandon request ignored");
                Reply::ok(Vec::new())
            }
            // Anything else is a *response* type. A client sending one is
            // either broken or probing; either way the connection is no longer
            // trustworthy.
            other => {
                warn!(op = ?std::mem::discriminant(&other), "client sent a response-type message");
                Reply::fatal(vec![disconnect_notice(
                    LdapResultCode::ProtocolError,
                    "expected a request, received a response",
                )])
            }
        }
    }

    // -- bind ---------------------------------------------------------------

    async fn bind(&self, msgid: i32, req: LdapBindRequest, session: &mut Session) -> Reply {
        // Any bind attempt, successful or not, discards the current identity
        // before it starts (RFC 4513 §5.1).
        session.deauthenticate();

        let LdapBindCred::Simple(password) = &req.cred else {
            return Reply::one(
                msgid,
                LdapOp::BindResponse(LdapBindResponse {
                    res: result(
                        LdapResultCode::AuthMethodNotSupported,
                        "only simple authentication is supported",
                    ),
                    saslcreds: None,
                }),
            );
        };

        let dn_text = req.dn.trim();

        // Anonymous bind: empty DN and empty password.
        if dn_text.is_empty() && password.is_empty() {
            info!(peer = %session.peer(), "anonymous bind");
            return Reply::one(
                msgid,
                LdapOp::BindResponse(LdapBindResponse {
                    res: result(LdapResultCode::Success, ""),
                    saslcreds: None,
                }),
            );
        }

        // An empty DN with a password is an "unauthenticated" bind
        // (RFC 4513 §5.1.2). Some servers accept it as anonymous, which means
        // a client with a typo'd DN silently gets anonymous rights instead of
        // an error. Reject it.
        if dn_text.is_empty() {
            return Reply::one(msgid, bind_failure("unauthenticated bind is not permitted"));
        }
        if password.is_empty() {
            return Reply::one(
                msgid,
                bind_failure("a bind DN was supplied with no password"),
            );
        }

        let dn = match convert::parse_dn("bind", dn_text) {
            Ok(dn) => dn,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::BindResponse(LdapBindResponse {
                        res: result(e.result_code(), e.to_string()),
                        saslcreds: None,
                    }),
                );
            }
        };

        // Configured accounts first, then the directory itself.
        let config = self.config.load();
        let authenticated = match config.find_user(&dn) {
            Some(expected) => constant_time_eq(expected.as_bytes(), password.as_bytes()),
            None => match self.backend.bind(&dn, password.as_bytes()).await {
                Ok(BindOutcome::Success) => true,
                Ok(BindOutcome::Invalid | BindOutcome::NotSupported) => false,
                Err(e) => {
                    warn!(error = %e, "backend error during bind");
                    return Reply::one(
                        msgid,
                        LdapOp::BindResponse(LdapBindResponse {
                            res: backend_result(&e),
                            saslcreds: None,
                        }),
                    );
                }
            },
        };

        if authenticated {
            info!(peer = %session.peer(), bind_dn = %dn, "bind succeeded");
            session.authenticate(dn);
            Reply::one(
                msgid,
                LdapOp::BindResponse(LdapBindResponse {
                    res: result(LdapResultCode::Success, ""),
                    saslcreds: None,
                }),
            )
        } else {
            // Deliberately the same message whether the DN exists or not.
            info!(peer = %session.peer(), bind_dn = %dn, "bind failed");
            Reply::one(msgid, bind_failure("invalid credentials"))
        }
    }

    // -- search -------------------------------------------------------------

    async fn search(&self, msgid: i32, req: LdapSearchRequest, session: &mut Session) -> Reply {
        if let Err(refusal) = session.authorise(OpClass::Read) {
            return refuse_search(msgid, &refusal);
        }

        let config = self.config.load();
        let limits = ServerLimits {
            size_limit: config.raw.server.size_limit,
            time_limit: config.raw.server.time_limit,
        };

        let search = match convert::search_request(&req, limits) {
            Ok(s) => s,
            Err(e) => return convert_failure_search(msgid, &e),
        };

        // The root DSE is synthesised, not stored: it describes the server, so
        // no backend can be the authority on it.
        if search.base.is_empty() && search.scope == dyno_core::Scope::Base {
            let entry = rootdse::build(self.backend.as_ref());
            let mut messages = Vec::new();
            if search
                .filter
                .evaluate(&entry, self.backend.schema())
                .is_true()
            {
                let projected = search.attrs.project(&entry, self.backend.schema());
                messages.push(LdapMsg::new(
                    msgid,
                    LdapOp::SearchResultEntry(convert::entry_to_proto(
                        &projected,
                        search.types_only,
                    )),
                ));
            }
            messages.push(LdapMsg::new(
                msgid,
                LdapOp::SearchResultDone(result(LdapResultCode::Success, "")),
            ));
            return Reply::ok(messages);
        }

        let deadline = Duration::from_secs(search.time_limit.unwrap_or(limits.time_limit).max(1));
        let found = match tokio::time::timeout(deadline, self.backend.search(&search)).await {
            Err(_elapsed) => {
                warn!(base = %search.base, "search exceeded its time limit");
                return Reply::one(
                    msgid,
                    LdapOp::SearchResultDone(result(
                        LdapResultCode::TimeLimitExceeded,
                        "search exceeded the time limit",
                    )),
                );
            }
            Ok(Err(e)) => {
                return Reply::one(msgid, LdapOp::SearchResultDone(backend_result(&e)));
            }
            Ok(Ok(entries)) => entries,
        };

        // The backend returns one entry past the limit as an overflow signal.
        let limit = search.size_limit.unwrap_or(usize::MAX);
        let overflowed = found.len() > limit;

        let mut messages: Vec<LdapMsg> = found
            .iter()
            .take(limit)
            .map(|e| {
                LdapMsg::new(
                    msgid,
                    LdapOp::SearchResultEntry(convert::entry_to_proto(e, search.types_only)),
                )
            })
            .collect();

        let done = if overflowed {
            result(
                LdapResultCode::SizeLimitExceeded,
                "more entries matched than the size limit allows",
            )
        } else {
            result(LdapResultCode::Success, "")
        };
        messages.push(LdapMsg::new(msgid, LdapOp::SearchResultDone(done)));
        Reply::ok(messages)
    }

    // -- writes -------------------------------------------------------------

    async fn add(
        &self,
        msgid: i32,
        req: &ldap3_proto::proto::LdapAddRequest,
        session: &mut Session,
    ) -> Reply {
        if let Err(r) = session.authorise(OpClass::Write) {
            return Reply::one(msgid, LdapOp::AddResponse(result(r.code, r.message)));
        }
        let converted = match convert::add_request(req) {
            Ok(c) => c,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::AddResponse(result(e.result_code(), e.to_string())),
                );
            }
        };
        let dn = converted.entry.dn().clone();
        match self.backend.add(converted).await {
            Ok(()) => {
                info!(%dn, actor = ?session.bound_dn().map(ToString::to_string), "entry added");
                Reply::one(
                    msgid,
                    LdapOp::AddResponse(result(LdapResultCode::Success, "")),
                )
            }
            Err(e) => Reply::one(msgid, LdapOp::AddResponse(backend_result(&e))),
        }
    }

    async fn delete(&self, msgid: i32, dn_text: &str, session: &mut Session) -> Reply {
        if let Err(r) = session.authorise(OpClass::Write) {
            return Reply::one(msgid, LdapOp::DelResponse(result(r.code, r.message)));
        }
        let dn = match convert::parse_dn("entry", dn_text) {
            Ok(dn) => dn,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::DelResponse(result(e.result_code(), e.to_string())),
                );
            }
        };
        match self.backend.delete(&dn).await {
            Ok(()) => {
                info!(%dn, actor = ?session.bound_dn().map(ToString::to_string), "entry deleted");
                Reply::one(
                    msgid,
                    LdapOp::DelResponse(result(LdapResultCode::Success, "")),
                )
            }
            Err(e) => Reply::one(msgid, LdapOp::DelResponse(backend_result(&e))),
        }
    }

    async fn modify(
        &self,
        msgid: i32,
        req: &ldap3_proto::proto::LdapModifyRequest,
        session: &mut Session,
    ) -> Reply {
        if let Err(r) = session.authorise(OpClass::Write) {
            return Reply::one(msgid, LdapOp::ModifyResponse(result(r.code, r.message)));
        }
        let converted = match convert::modify_request(req) {
            Ok(c) => c,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::ModifyResponse(result(e.result_code(), e.to_string())),
                );
            }
        };
        let dn = converted.dn.clone();
        match self.backend.modify(converted).await {
            Ok(()) => {
                info!(%dn, actor = ?session.bound_dn().map(ToString::to_string), "entry modified");
                Reply::one(
                    msgid,
                    LdapOp::ModifyResponse(result(LdapResultCode::Success, "")),
                )
            }
            Err(e) => Reply::one(msgid, LdapOp::ModifyResponse(backend_result(&e))),
        }
    }

    async fn modify_dn(
        &self,
        msgid: i32,
        req: &ldap3_proto::proto::LdapModifyDNRequest,
        session: &mut Session,
    ) -> Reply {
        if let Err(r) = session.authorise(OpClass::Write) {
            return Reply::one(msgid, LdapOp::ModifyDNResponse(result(r.code, r.message)));
        }
        let converted = match convert::modify_dn_request(req) {
            Ok(c) => c,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::ModifyDNResponse(result(e.result_code(), e.to_string())),
                );
            }
        };
        let dn = converted.dn.clone();
        match self.backend.modify_dn(converted).await {
            Ok(()) => {
                info!(%dn, actor = ?session.bound_dn().map(ToString::to_string), "entry renamed");
                Reply::one(
                    msgid,
                    LdapOp::ModifyDNResponse(result(LdapResultCode::Success, "")),
                )
            }
            Err(e) => Reply::one(msgid, LdapOp::ModifyDNResponse(backend_result(&e))),
        }
    }

    // -- compare ------------------------------------------------------------

    async fn compare(
        &self,
        msgid: i32,
        req: &ldap3_proto::proto::LdapCompareRequest,
        session: &mut Session,
    ) -> Reply {
        if let Err(r) = session.authorise(OpClass::Read) {
            return Reply::one(msgid, LdapOp::CompareResult(result(r.code, r.message)));
        }
        let converted = match convert::compare_request(req) {
            Ok(c) => c,
            Err(e) => {
                return Reply::one(
                    msgid,
                    LdapOp::CompareResult(result(e.result_code(), e.to_string())),
                );
            }
        };
        match self.backend.compare(converted).await {
            // compareTrue and compareFalse are *result codes*, not an error
            // and a success. Returning success for both loses the answer.
            Ok(true) => Reply::one(
                msgid,
                LdapOp::CompareResult(result(LdapResultCode::CompareTrue, "")),
            ),
            Ok(false) => Reply::one(
                msgid,
                LdapOp::CompareResult(result(LdapResultCode::CompareFalse, "")),
            ),
            Err(e) => Reply::one(msgid, LdapOp::CompareResult(backend_result(&e))),
        }
    }

    // -- extended -----------------------------------------------------------

    fn extended(&self, msgid: i32, req: &LdapExtendedRequest, session: &Session) -> Reply {
        match req.name.as_str() {
            OID_WHOAMI => {
                // RFC 4532: "dn:<the bound DN>", or an empty string when
                // anonymous. Not the *requested* DN — the effective one.
                let identity = session
                    .bound_dn()
                    .map(|dn| format!("dn:{dn}"))
                    .unwrap_or_default();
                Reply::one(
                    msgid,
                    LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: result(LdapResultCode::Success, ""),
                        name: None,
                        value: Some(identity.into_bytes()),
                    }),
                )
            }
            OID_START_TLS => Reply::one(
                msgid,
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    // Not `protocolError`: the operation is recognised, we
                    // simply cannot do it yet. A client can act on this.
                    res: result(
                        LdapResultCode::Unavailable,
                        "StartTLS is not yet implemented; use LDAPS when it lands in phase 4",
                    ),
                    name: Some(OID_START_TLS.to_string()),
                    value: None,
                }),
            ),
            other => Reply::one(
                msgid,
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res: result(
                        LdapResultCode::ProtocolError,
                        format!("unsupported extended operation {other}"),
                    ),
                    name: None,
                    value: None,
                }),
            ),
        }
    }
}

fn bind_failure(message: &str) -> LdapOp {
    LdapOp::BindResponse(LdapBindResponse {
        res: result(LdapResultCode::InvalidCredentials, message),
        saslcreds: None,
    })
}

fn refuse_search(msgid: i32, refusal: &Refusal) -> Reply {
    Reply::one(
        msgid,
        LdapOp::SearchResultDone(result(refusal.code.clone(), refusal.message.clone())),
    )
}

fn convert_failure_search(msgid: i32, e: &ConvertError) -> Reply {
    Reply::one(
        msgid,
        LdapOp::SearchResultDone(result(e.result_code(), e.to_string())),
    )
}

/// An unsolicited notice of disconnection (RFC 4511 §4.4.1), sent on message
/// id 0 immediately before the server closes the connection.
pub fn disconnect_notice(code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg::new(
        0,
        LdapOp::ExtendedResponse(LdapExtendedResponse {
            res: result(code, message),
            name: Some("1.3.6.1.4.1.1466.20036".to_string()),
            value: None,
        }),
    )
}
