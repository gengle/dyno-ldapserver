# dyno-ldapserver

A dynamic LDAP server in pure Rust. Serves directory data from pluggable backends,
shapes every request and response through user-supplied CEL expressions, and can
sit in front of an upstream LDAP server as a rewriting proxy.

Status: greenfield. Nothing is implemented yet — see `DESIGN.md` for the
architecture and the phased build plan.

## Environment

**Build and run this project from WSL2 (Ubuntu-24.04), not from Windows.**
The repo lives on an NTFS path that WSL sees as
`/mnt/c/Users/grege/source/dyno-ldapserver`.

Toolchain present in WSL: `cargo`/`rustc` 1.96.0, `git`, `cc`, `docker`.

Two things are *not* available, and they constrain design choices:

- **`sudo` requires a password**, so no `apt install` in an automated session.
  If a system package is genuinely needed, ask the user to run it themselves.
- **`pkg-config` and OpenSSL headers are absent.** Prefer pure-Rust crates.
  For TLS this means `rustls`, never `native-tls`/`openssl`.
- **`ldapsearch` is not installed.** Use an LDAP client from a Docker container
  for manual testing rather than expecting host binaries.

Building on `/mnt/c` is slow because of the 9p filesystem crossing. If build
times get painful, point `CARGO_TARGET_DIR` at a Linux-native path
(e.g. `~/.cache/cargo-target/dyno-ldapserver`) rather than moving the repo.

## Commands

```bash
cargo check --workspace --all-targets   # fast feedback loop
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo fmt --all
```

## Conventions

- Rust edition 2024, MSRV 1.85 (floor set by `ldap3_proto` 0.8).
- Async runtime is `tokio`, multi-threaded.
- Errors: `thiserror` in library crates, `anyhow` only in the binary.
- Logging: `tracing`. Never log credentials or full entry contents at `info` or
  above — `ldap3_proto` deliberately redacts passwords in its `Debug` impls and
  we should not undo that.
- Deny `unwrap`/`panic` in library crates; the LDAP surface is untrusted input.

## Key dependency facts

These were verified against the actual crate sources, not from memory. Re-verify
before trusting them if the versions move.

### `ldap3_proto` 0.8.0 (Kanidm) — the LDAP wire protocol

- Edition 2024, MSRV 1.85, MPL-2.0. Features: `strict` (default), `serde`.
- `tokio-util` is a *hard* dependency, so `LdapCodec` is always available —
  there is no `tokio` feature flag to enable.
- `LdapCodec::new(max_ber_size: Option<usize>, max_ber_depth: Option<usize>)`,
  implements `Decoder<Item = LdapMsg, Error = io::Error>` and
  `Encoder<LdapMsg, Error = io::Error>`. Default max BER size is 32 KiB
  (`DEFAULT_MAX_BER_SIZE`) — raise it deliberately if large entries are needed.
- **Two API levels, and the choice matters:**
  - `simple::ServerOps` is a convenience enum covering only `Search`,
    `SimpleBind`, `Unbind`, `Whoami`, `Compare`. `TryFrom<LdapMsg>` returns
    `Err(())` for anything else. Easy, but it cannot express writes.
  - `proto::LdapOp` is the full protocol: bind, search, modify, add, del,
    modifyDN, compare, abandon, extended, intermediate.
  - **We work at the `LdapOp` level**, because writes and proxy passthrough are
    both project goals. `ServerOps` is fine for early prototyping only.
- Response builders live on the `simple` request structs: `gen_success`,
  `gen_result_entry`, `gen_operror`, `gen_error(code, msg)`,
  `gen_invalid_cred`, `gen_compare_true`/`false`, and
  `DisconnectionNotice::gen_response`. At the `LdapOp` level you construct
  `LdapMsg { msgid, op, ctrl }` yourself.
- `LdapFilter` variants: `And`, `Or`, `Not`, `Equality`, `Substring`,
  `GreaterOrEqual`, `LessOrEqual`, `Present`, `Approx`, `Extensible`.
- `parse_ldap_filter_str` is re-exported at the crate root — useful for tests
  and for filters written in config.
- Ships an `examples/tokio` server example worth reading.

### `cel` 0.14.1 — the dynamic rule engine

This is the renamed continuation of `cel-interpreter`; use `cel`, not the older
name.

- `Program::compile(&str) -> Result<Program, ParseErrors>` then
  `program.execute(&Context) -> ResolveResult`. **Compile once at config load,
  execute per request** — compilation must never be on the hot path.
- `Context::add_variable` / `add_variable_from_value` / `add_function`,
  `Context::new_inner_scope()` for per-request scoping over a shared base.
- `cel::to_value` serializes any `serde::Serialize` type into a CEL `Value`, so
  request-context structs can be handed to CEL directly without hand-marshalling.
- `Program::references()` reports which variables an expression touches — use it
  to validate rules at load time and to skip building context a rule won't read.

## Working agreements

- Prefer verifying a crate's API from its source in
  `~/.cargo/registry/src/*/<crate>-<version>/` over recalling it.
- Keep `DESIGN.md` current when architecture decisions change; it is the
  contract this codebase is being built against.
