# dyno-ldapserver — architecture and build plan

## What this is

An LDAP v3 server written entirely in Rust with three properties that together
don't exist in any off-the-shelf server:

1. **Dynamic.** Behaviour is driven by expressions evaluated per request, not by
   a static schema and ACL file. Reloading is hot; no restart, no dropped
   connections.
2. **Pluggable.** The thing that answers a query is a trait, so it can be an
   in-memory fixture, an LDIF file, or another LDAP server.
3. **Rewriting.** When the backend is an upstream LDAP server, we are a proxy
   that can lie convincingly — translating DNs, filters, and attributes in both
   directions so the client sees a directory that differs from the real one.

The motivating use cases are test fixtures that mimic a production directory,
migrations where two directory layouts must coexist, and adapting a directory
for an application that expects a different schema than the one you have.

## Implementation status

| Phase | State |
| --- | --- |
| 0 — scaffold | Done. Five crates, workspace lint table, shared error conventions. |
| 1 — read-only server | Done. TCP listener, `LdapCodec` framing, session state machine, anonymous and simple bind, search with all four scopes and full filter matching, root DSE, compare, WhoAmI. |
| 2 — dynamic behaviour | Not started. `dyno-cel` is a documented stub; `dyno-config` validates and hot-swaps, but has no rule table yet. |
| 3 — writes | Done ahead of order. Add, delete, modify and modifyDN against `MemoryBackend`, with the concurrency model settled (see below). Rule veto arrives with Phase 2. |
| 4 — transport security | Not started. `conn.tls` is always false; StartTLS answers `unavailable` rather than pretending. |
| 5 — proxy | Not started. The `Backend` trait and the DN-syntax table in `Schema` are the two pieces already in place for it. |
| 6 — hardening | Partial. BER size limit is configurable, size and time limits are enforced, writes are audit-logged. No metrics, fuzzing or benchmarks. |

Phase 3 was pulled forward because the `Backend` trait had to express writes
either way — deferring them would have meant designing the trait twice. See
`TESTING.md` for the feature-by-feature test matrix.

## Design principles

**The proxy is not a bolt-on.** A rewriting proxy is the hardest thing here, and
retrofitting it onto an architecture designed for a local store is how this
project would fail. So the core abstraction is "something that answers LDAP
operations," and the in-memory store and the upstream connection are both just
implementations of it from day one — even though the proxy is built last.

**Operate at the full protocol level.** `ldap3_proto` offers a `ServerOps`
convenience enum, but it only covers five read-ish operations and cannot express
writes. We decode to `proto::LdapOp` so that add/modify/delete and opaque
passthrough are possible without a rewrite later.

**Rules are compiled once and are pure.** CEL programs are compiled at config
load, validated against the variables they reference, and executed against a
per-request context. A rule cannot perform I/O. This keeps evaluation
predictable, fast, and safe to run on every entry of a large result set.

**Untrusted input, everywhere.** Every byte from a client is hostile until
parsed. Library crates deny `unwrap`/`panic`; BER size and depth limits are
explicit; the connection state machine rejects operations that are illegal
before a successful bind.

## Crate layout

A workspace, so the protocol and rule engine stay testable without a server
running.

| Crate | Responsibility |
| --- | --- |
| `dyno-core` | Domain types: `Dn` (parsed, normalised, comparable), `Entry`, `Attribute`, filter matching, scope evaluation, schema and matching rules. No I/O, no async. |
| `dyno-cel` | Wraps the `cel` crate: rule compilation, the variable namespace exposed to rules, custom functions, and the typed results a rule may return. |
| `dyno-backend` | The `Backend` trait plus implementations: `MemoryBackend`, `LdifBackend`, `ProxyBackend`. |
| `dyno-config` | Config schema (serde), file loading, validation, and hot reload via `ArcSwap`. |
| `dyno-server` | Binary. TCP/TLS listeners, per-connection task and session state, the operation pipeline, observability. |

`dyno-core` having no async and no I/O is deliberate: DN normalisation and
filter matching are the subtlest correctness problems in the project, and they
should be testable as pure functions with property tests.

## The request pipeline

Every operation follows the same path:

```
  client
    │  LdapMsg (decoded by LdapCodec)
    ▼
  session state machine        ── rejects ops illegal in the current bind state
    ▼
  request rules (CEL)          ── deny / rewrite base DN / rewrite filter
    ▼
  Backend                      ── memory, LDIF, or upstream LDAP
    ▼
  response rules (CEL)         ── drop entry / rewrite DN / add, remove, edit attrs
    ▼
  client
```

Request rules and response rules are separate stages with different contexts and
different permitted return values. That separation is what makes proxy rewriting
tractable: the request stage translates the client's view into the upstream's
view, and the response stage translates back.

### What a rule sees

The CEL context is built from a serializable struct via `cel::to_value`, so it
stays in sync with the Rust types automatically. Roughly:

```
conn.remote_ip, conn.tls, conn.bound_dn, conn.authenticated
op.kind                        // "search" | "bind" | "modify" | ...
op.msgid
req.base, req.scope, req.filter, req.attrs        // search
entry.dn, entry.attrs                             // response stage only
```

`Program::references()` tells us which of these a given rule actually reads, so
we only pay to build the expensive parts of the context (a full entry
serialization, say) for rules that touch them.

### What a rule returns

Not just a boolean. A rule returns a typed decision:

- **Predicate rules** return a bool — used for access control and for matching
  (`when:` clauses).
- **Transform rules** return a value that is applied to the entry or request —
  a rewritten DN string, an attribute value list, or a map merged into the entry.

The config binds these together, so a rewriting rule reads as a `when` predicate
plus a set of actions, rather than one enormous expression.

### Why CEL

CEL is non-Turing-complete and has bounded evaluation cost, which matters when a
rule runs once per entry across a result set of unknown size. Rhai or Lua would
be more expressive and strictly more dangerous — a rule that can loop can hang a
connection. The `cel` crate also gives compile-time reference analysis, which we
use for load-time validation. If some future action genuinely needs unbounded
computation, it belongs in a Rust-side custom function registered on the
`Context`, not in a general-purpose scripting language.

## Config and hot reload

TOML (a YAML reader can come later; TOML avoids a whole class of parsing
surprises). A sketch of the intended shape, not yet a committed schema:

```toml
[server]
listen = "0.0.0.0:3389"
base_dn = "dc=example,dc=com"

[backend]
kind = "ldif"          # "memory" | "ldif" | "proxy"
path = "fixtures/directory.ldif"

[[rule]]
name  = "anonymous cannot read userPassword"
stage = "response"
when  = '!conn.authenticated'
remove_attrs = ["userPassword"]

[[rule]]
name  = "present staff as a flat ou"
stage = "response"
when  = 'entry.dn.endsWith("ou=staff,dc=corp,dc=internal")'
set_dn = 'entry.attrs.uid[0] + ",ou=people,dc=example,dc=com"'
```

Reload is by explicit signal (`SIGHUP`) and optionally by file watch. The new
config is parsed and *fully validated* — every CEL program compiled, every
referenced variable checked — before anything is swapped in. Only then does an
`ArcSwap` publish it. A bad config therefore logs an error and changes nothing,
and in-flight operations finish against the config they started with.

## Proxy and rewriting

This is the deep end, so it gets designed carefully before it gets built. The
naive version — string-replace the base DN — breaks in at least these places:

- **DN-valued attributes.** `member`, `memberOf`, `manager`, `owner`,
  `seeAlso` contain DNs in the upstream's namespace that must be rewritten on
  the way out and un-rewritten on the way in. This needs schema knowledge of
  which attributes are DN-syntax, not a regex.
- **Filters.** A client searching `(member=cn=bob,ou=people,dc=example,dc=com)`
  must have that assertion value translated to the upstream namespace before the
  query is forwarded, which means walking the `LdapFilter` tree.
- **Attribute renaming is not symmetric.** If we present upstream `uid` as
  `sAMAccountName`, then requested-attribute lists, filters, and returned entries
  all need mapping, and a filter on an attribute that doesn't exist upstream
  must resolve to something sane rather than an error.
- **Referrals and continuation references** carry upstream URLs and DNs.
- **Controls.** Paged results (1.2.840.113556.1.4.319), sort, and deref have
  state that must be forwarded coherently. Rewriting is incompatible with
  blindly forwarding a page cookie if we also filter entries out — dropping
  entries changes page sizes. Initial approach: forward paging untouched and
  document that entry-dropping rules interact badly with it; solve properly
  later.
- **Bind passthrough.** Does a client bind authenticate against upstream, or
  locally? Both are legitimate. This must be explicit config, and credentials
  must never be logged or cached to disk.

So the rewriting layer is a **bidirectional DN mapper plus an attribute mapper**
that both the request and response stages consult, with CEL rules layered on top
for the cases a declarative mapping can't express. The mapper is pure and lives
in `dyno-core`; it is property-testable with a round-trip invariant
(`inbound(outbound(dn)) == dn`), which is exactly the kind of bug that is
otherwise found in production.

Upstream connections use a pool with health checking and reconnect. `ldap3`
(0.12) is the client, and `ProxyBackend` implements the same `Backend` trait as
everything else.

## Build plan

Each phase ends with something demonstrably working, because an LDAP server that
half-speaks the protocol is indistinguishable from a broken one.

**Phase 0 — scaffold.** Workspace, the five crates, CI (`fmt`, `clippy -D
warnings`, `test`), `tracing` set up. Nothing but wiring.

**Phase 1 — a real read-only server.** TCP listener, `LdapCodec` framing,
per-connection task, session state machine, anonymous and simple bind against a
static config, search over `MemoryBackend` seeded from LDIF. Correct scope
handling (`base`/`one`/`sub`) and correct filter matching including substring
and presence. RootDSE. This is the phase where DN normalisation and filter
matching get their property tests. *Done when a real LDAP client can bind and
search and gets RFC-correct answers.*

**Phase 2 — dynamic behaviour.** `dyno-cel`, the rule context, the config
schema, load-time validation, `ArcSwap` hot reload, and the request/response
rule stages wired into the pipeline. *Done when editing a rule file changes what
a live client sees, with no restart.*

**Phase 3 — writes.** Add, modify, delete, modifyDN against `MemoryBackend`,
with rules able to veto or rewrite them. Concurrency model for the store settled
here.

**Phase 4 — transport security.** `rustls` for LDAPS and StartTLS, client
certificate handling, and `conn.tls` exposed to rules. Pure Rust, because this
environment has no OpenSSL headers.

**Phase 5 — proxy.** `ProxyBackend` over `ldap3`, connection pooling, then the
bidirectional DN and attribute mappers, then filter rewriting, then controls.
Integration-tested against a real OpenLDAP in Docker, which is also how we get
`ldapsearch` without needing sudo on the host.

**Phase 6 — hardening.** Metrics, structured audit logging, connection and
request limits, fuzzing the decoder, benchmarks.

## Testing

- **Unit and property tests** in `dyno-core` for DN normalisation, filter
  matching, and the DN mapper round-trip. These are where correctness lives.
- **Protocol tests** driving the server through the `ldap3` client crate, in
  process — fast, no containers.
- **Integration tests** against OpenLDAP in Docker for the proxy phase, plus
  interop checks with real clients.
- **Fuzzing** the BER decode path, since it is the one place where a hostile
  client reaches parsing code directly.

## Decisions settled while building phases 1 and 3

These were open questions; they are not any more. Each is recorded with the
reason, because the reason is the part that gets lost.

**Multi-backend routing: one backend per server instance.** `Backend` takes no
naming-context argument. Routing, when it is needed, is a `Backend`
implementation that owns several others and dispatches on the base DN — the
same shape as the proxy. Putting routing in the trait signature would have made
every implementation carry a concern only one of them has.

**Filter evaluation is three-valued, not boolean.** `True`/`False`/`Undefined`
per RFC 4511 §4.5.1.7. Collapsing `Undefined` into `False` at the leaves is
cheap and wrong: `(!(uidNumber>=abc))` then matches every entry in the
directory. This is enforced by a test at the domain layer and again over the
wire.

**Schema is open, but matching rules are not.** An unknown attribute is usable
and gets `caseIgnoreMatch`. Known attributes get the right rule, which is what
keeps `userPassword` from being case-folded and lets `member` compare as a DN.
The DN-syntax flag in `Schema` is also exactly what the proxy will need to know
which values to rewrite, so it earns its place now rather than later.

**Entry validation lives in the backend, not in a schema checker.** Add and
modify enforce four things: the entry contains the values that name it, it has
an `objectClass`, single-valued attributes hold one value, and a modify cannot
strip the RDN value. Full objectClass validation stays out until rules exist,
since a fixture server frequently wants entries a real schema would reject.

**Concurrency: one `RwLock` over the whole store, changes applied to a clone.**
Reads are concurrent, writes serialise, and the lock is never held across an
`await`. A modify list that fails half way through leaves the entry untouched
because the failure happens on the clone. For a fixture directory, atomicity is
worth more than write throughput.

**Anonymous clients may never write**, independently of `require_bind`. A
directory that anyone can modify without identifying themselves has no useful
audit trail.

**Size limits are reported, never silently applied.** A backend returns one
entry past the limit as an overflow signal, so the server can answer
`sizeLimitExceeded` with a partial result rather than a truncated result that
looks complete.

**DN comparison folds case for every attribute**, rather than consulting each
attribute's own matching rule. This keeps `Dn` free of a schema reference so it
can implement `Eq` and `Hash`, and it matches what directory servers do in
practice. Documented on `Dn` itself, since it is a real (if small) deviation.

**LDIF loads content records only.** A `changetype:` record describes an
operation, not a state; loading one as an entry would produce a directory that
does not match the file. URL-valued attributes are refused because loading a
fixture should not perform I/O of its own.

## Open questions

Still genuinely undecided, and deliberately so:

- How much of a real schema do we need for DN-syntax attribute detection in the
  proxy? The built-in table in `Schema::builtin` covers the common cases;
  reading the upstream's schema is correct but much more work.
- Paged results combined with entry-dropping rules — is there a correct answer,
  or is it documented as unsupported?
- Whether `MemoryBackend` should persist. Today it is seeded from LDIF at
  startup and changes are lost on restart, which is right for a fixture and
  wrong for anything else.
- Whether rules should be able to *see* a failed operation, or only successful
  ones. Affects where the response stage sits relative to error paths.
