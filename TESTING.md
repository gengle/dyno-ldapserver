# Testing

Every feature is documented by a **pair** of tests: one showing it working, and
one showing it correctly refusing. The negative half is the more valuable of
the two — a directory server that answers every question with "yes" passes any
test suite made only of positive cases, and an access-control check that is
never exercised in the refusing direction is not a check.

Each table below reads: *feature* → *the test that proves it works* → *the test
that proves it fails in the right way* → *what the validation actually is*.

```bash
cargo test --workspace                      # everything, ~161 tests, under a second
cargo test -p dyno-core                     # pure domain logic and property tests
cargo test -p dyno-server --test protocol   # over a socket, with a real LDAP client
cargo test -p dyno-server --test write_operations
cargo clippy --workspace --all-targets -- -D warnings
```

## Layers

| Layer | Where | What it proves |
| --- | --- | --- |
| Unit | `#[cfg(test)]` in each module | The rule is implemented as stated, including its edge cases. |
| Property | `crates/dyno-core/tests/dn_properties.rs` | Invariants hold for inputs nobody thought to write down. |
| Protocol | `crates/dyno-server/tests/` | A real client, over a real socket, gets RFC-correct answers. |
| Smoke | `cargo run -p dyno-server --example smoke_client` | The shipped binary works when started by hand. |

The protocol tests start the server in-process on port 0 and drive it with the
`ldap3` client. No container, no fixed port, so they run in parallel and on any
machine.

---

## Distinguished names (`dyno-core::dn`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Parse a DN | `parses_a_plain_dn` | `rejects_an_rdn_without_a_value` | An RDN must contain `=`. |
| Empty RDNs | `empty_dn_is_the_root_dse` | `rejects_an_empty_rdn` | `cn=a,,dc=x` and `,dc=x` are errors; the *empty* DN is not. |
| Attribute types | `parses_a_plain_dn` (`2.5.4.3=Bob` accepted) | `rejects_a_malformed_attribute_type` | RFC 4512 `descr` or `numericoid`; `c_n` and `1..2` rejected. |
| Escaping | `round_trips_escaped_values` | `rejects_unescaped_reserved_characters` | A bare `"`, `<`, `>` in a value is a syntax error, not a guess. |
| Hex escapes | `round_trips_escaped_values` | `rejects_a_truncated_hex_escape` | `\4z` is ambiguous between `\4` and `\41`, so it is refused. |
| Hex values | — | `rejects_a_malformed_hex_value` | `#0` is not a whole octet. |
| Multi-valued RDN | `multi_valued_rdn_is_order_independent` | `rejects_a_duplicate_type_in_one_rdn` | An RDN is a set; `cn=a+cn=b` is not legal. |
| Comparison | `comparison_ignores_case_and_insignificant_space` | `rdn_order_is_significant` | Case and spacing are noise; RDN order is structure. |
| Significant space | `escaped_space_is_preserved_but_not_significant_for_comparison` | (same test, both halves) | `\ ` survives parsing and rendering but folds away for comparison, per RFC 4518. |
| Containment | `tree_relationships_hold` | `suffix_string_match_is_not_containment` | `dc=notexample,dc=com` ends with `dc=com` as a string but is not inside it. |
| Ordered storage | `sort_key_groups_subtrees_together` | (same test: sibling context sorts outside) | The key a range-scan backend depends on. |

Property tests: `render_parse_round_trips`, `normalisation_agrees_with_equality`,
`child_parent_and_containment_agree`, `containment_is_transitive`,
`scopes_are_consistent`, and `parsing_arbitrary_input_never_panics` — the last
of which matters because the DN in a bind request is attacker-controlled.

## Matching rules and schema (`dyno-core::schema`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Case-insensitive match | `case_ignore_folds_case_and_whitespace` | `octet_string_attributes_do_not_fold_case` | `cn` folds case; `userPassword` must not. |
| DN-valued attributes | `dn_syntax_attributes_compare_structurally` | `dn_syntax_rejects_a_non_dn_value` | `member` values compare as DNs; garbage is a syntax error, not "unequal". |
| Numeric ordering | `integers_order_numerically` | (same test asserts text sorts `9 > 10`) | The bug the integer rule exists to prevent. |
| Unorderable syntaxes | — | `unorderable_syntaxes_are_declared` | DN and boolean have no ordering rule, so `>=` must be Undefined. |
| Open schema | `unknown_attributes_get_the_default_rule` | — | An unknown attribute is usable, not an error. |
| Operational attributes | `operational_attributes_are_flagged` | — | Feeds the withholding rule below. |

## Filters (`dyno-core::filter`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Equality | `equality_matches_case_insensitively` | `equality_rejects_non_matching_and_absent` | Absent attribute is `False`, not an error. |
| DN equality | `dn_valued_equality_is_structural` | `invalid_assertion_syntax_is_undefined_and_stays_undefined` | **`Not(Undefined)` is `Undefined`.** Folding it to `False` early makes `(!(member=junk))` return the whole directory. |
| Presence | `presence_tracks_whether_the_attribute_exists` | (same test, both directions) | |
| Substring | `substring_matches_anchors_and_fragments` | `substring_requires_ordered_non_overlapping_fragments` | Fragments must appear in order and must not overlap the anchors — the two mistakes a naive `contains` loop makes. |
| Substring syntax | — | `substring_on_a_dn_syntax_is_undefined` | No substring rule for DN syntax. |
| Ordering | `ordering_on_integers_is_numeric` | `ordering_is_undefined_where_no_ordering_exists` | |
| Boolean algebra | `empty_and_is_true_and_empty_or_is_false` | `undefined_propagates_per_rfc_truth_tables` | The RFC 4511 §4.5.1.7 truth tables, asserted directly. |
| Extensible match | `extensible_match_uses_the_named_rule`, `extensible_match_can_search_dn_components` | `extensible_match_rejects_wrong_case_and_unknown_rules` | An unknown matching rule is Undefined, not an error. |

## Scope (`dyno-core::scope`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| All four scopes | `each_scope_admits_the_right_entries` | `each_scope_excludes_the_right_entries` | one-level excludes the base and grandchildren; children excludes the base; nothing admits a look-alike sibling context. |

## Entries and attribute selection (`dyno-core::entry`, `::ops`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Case-insensitive attributes | `attribute_lookup_ignores_case` | `absent_attribute_is_not_an_empty_value` | "Absent" and "present but empty" stay distinguishable. |
| Values are a set | `adding_a_duplicate_value_is_a_no_op` | `duplicate_detection_respects_the_matching_rule` | Two `userPassword` values differing in case *are* distinct. |
| Empty attributes | `removing_the_last_value_removes_the_attribute` | `setting_no_values_removes_the_attribute` | An attribute with no values cannot be stored. |
| Default selection | `empty_attribute_list_means_all_user_attributes` | `operational_attributes_are_withheld_by_default` | A client that receives `createTimestamp` it never asked for is a bug. |
| `1.1` selector | `no_attributes_selector_returns_only_the_dn` | `no_attributes_selector_is_ignored_when_combined` | RFC 4511 §4.5.1.8: `1.1` alongside a real attribute is ignored. |
| Binary values | `text_value_round_trips` | `binary_value_has_no_text_view` | Values are octet strings, not `String`. |
| Credential hygiene | — | `debug_redacts_binary_octets`, `debug_output_redacts_passwords` | `Debug` output reaches logs; passwords must not. |

## In-memory backend (`dyno-backend::memory`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Subtree search | `subtree_search_returns_the_subtree` | `subtree_search_does_not_leak_sibling_contexts` | The range scan must not spill into `dc=other,dc=com`. |
| Missing base | — | `search_with_a_missing_base_reports_the_closest_ancestor` | `noSuchObject` + `matchedDN`, not an empty result. |
| Size limit | `size_limit_returns_one_extra_entry_as_an_overflow_signal` | (same test) | One entry past the limit distinguishes "exactly n" from "more than n". |
| Add | `add_creates_a_searchable_entry` | `add_rejects_a_duplicate_dn`, `add_rejects_a_missing_parent`, `add_rejects_an_entry_that_contradicts_its_own_rdn`, `add_rejects_an_entry_without_an_object_class` | No implicit parent creation; an entry must contain the value that names it. |
| Delete | `delete_removes_a_leaf` | `delete_refuses_a_non_leaf`, `delete_rejects_a_missing_entry` | A delete that took the subtree with it would make one typo catastrophic. |
| Modify | `modify_applies_each_change_kind` | `a_failed_modification_leaves_the_entry_untouched` | **Atomicity**: the first change is rolled back with the second. |
| Modify vs. naming | — | `modify_cannot_remove_the_rdn_value` | An entry may not be stripped of the value that names it. |
| ModifyDN | `modify_dn_renames_and_updates_the_rdn_attribute`, `modify_dn_moves_descendants` | `modify_dn_refuses_to_move_an_entry_beneath_itself` | Children follow the move; a move under self would detach the subtree. |
| Bind | `bind_accepts_the_right_password` | `bind_rejects_everything_else_identically` | Wrong password, missing entry and no stored password give the *same* answer — a different one is a DN oracle. |
| Password schemes | — | `a_stored_hash_is_not_a_usable_password` | If `{SSHA}xyz` matched the literal string `{SSHA}xyz`, reading the directory would be enough to bind as anyone. |
| Compare | `compare_answers_true_and_false` | (same test) | |

## LDIF (`dyno-backend::ldif`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Parse a document | `parses_a_well_formed_document` | `rejects_a_record_without_a_dn` | Folded lines join without a separator; base64 values decode. |
| DN validity | — | `rejects_an_invalid_dn` | Reported with the line number. |
| Base64 | — | `rejects_invalid_base64` | A truncated password hash must not load as a blank one. |
| Change records | — | `rejects_change_records` | `changetype:` describes an operation, not a state. |
| URL values | — | `rejects_url_valued_attributes` | `jpegPhoto:< file:///etc/passwd` would make loading a fixture perform I/O. |
| Duplicates | — | `rejects_duplicate_entries` | Detected after DN normalisation, so different spellings still collide. |
| Continuations | — | `rejects_a_dangling_continuation` | |
| Read-only backend | `ldif_backend_serves_reads` | `ldif_backend_refuses_writes` | Writes get `unwillingToPerform` rather than vanishing into memory at restart. |

## Configuration (`dyno-config`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Load and validate | `accepts_a_well_formed_config` | `rejects_a_malformed_dn`, `rejects_a_malformed_listen_address`, `rejects_a_missing_backend_file`, `rejects_an_unknown_backend_kind` | Everything checkable is checked at load, not at the first request. |
| Defaults | `applies_defaults_for_omitted_settings` | — | A minimal config is usable. |
| Unusable accounts | — | `rejects_a_user_with_an_empty_password` | An account that could never authenticate is a config error, not a silently dead entry. |
| Hot reload | `a_failed_reload_changes_nothing` | (same test) | Validate fully, then publish. A broken file leaves the running server exactly as it was. |

## Protocol conversion (`dyno-server::convert`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Search conversion | `converts_a_search_request` | `rejects_a_malformed_base_dn` | |
| Limit clamping | `client_size_limit_is_clamped_not_trusted` | (same test) | A client may lower the server's limit, never raise it; a negative limit is not a huge unsigned one. |
| `(cn=*)` | `empty_substring_filter_becomes_presence` | — | |
| Filter injection | — | `literal_asterisk_is_not_a_wildcard` | An equality assertion of `*` is a value. |
| Add conversion | `converts_an_add_request` | `rejects_an_add_with_a_valueless_attribute` | |
| ModifyDN | — | `rejects_a_multi_rdn_newrdn` | A full DN in `newrdn` is a client bug, not a silent move. |
| `typesOnly` | `types_only_omits_values` | (same test) | Values are omitted server-side, not discarded client-side. |

## Session and authorisation (`dyno-server::session`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Anonymous read | `anonymous_reads_are_allowed_when_configured` | `anonymous_reads_are_refused_when_bind_is_required` | |
| Anonymous write | — | `anonymous_writes_are_always_refused` | Refused independently of `require_bind`: a directory anyone can modify unidentified has no audit trail. |
| Read-only server | — | `a_read_only_server_refuses_authenticated_writes` | `unwillingToPerform` ("not here") rather than an access error ("not you"). |
| Identity lifecycle | — | `deauthenticating_drops_a_previous_identity` | RFC 4513 §5.1. |

## Over the wire (`dyno-server/tests/protocol.rs`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Bind | `bind_accepts_valid_credentials` | `bind_rejects_bad_credentials_without_leaking_which_dns_exist` | Configured accounts and directory passwords both work; every failure mode returns the same code *and the same message*. |
| Unauthenticated bind | — | (same test) | A DN with an empty password must not succeed as anonymous — RFC 4513 §5.1.2. |
| Failed bind | — | `a_failed_bind_drops_the_previous_identity` | The connection is anonymous again afterwards, verified by a search that now fails. |
| SASL | — | `sasl_bind_is_reported_as_unsupported` | `authMethodNotSupported`, not "bad credentials". |
| Scopes | `search_scopes_return_the_right_entries` | `search_with_a_missing_base_is_no_such_object` | |
| Filters | `filters_select_the_right_entries` | `filters_that_should_match_nothing_return_nothing` | |
| Undefined filters | — | `a_negated_undefined_filter_does_not_return_everything` | The three-valued logic, observed from outside the process. |
| Attributes | `attribute_selection_is_honoured` | (same test: `1.1`) | |
| Size limit | — | `exceeding_the_size_limit_is_reported` | `sizeLimitExceeded` plus a partial result, never a silent truncation. |
| `require_bind` | `require_bind_blocks_anonymous_searches` | (same test, both halves) | |
| Root DSE | `root_dse_is_reachable_anonymously` | `root_dse_is_not_returned_by_a_subtree_search` | It is not part of any subtree. |
| Compare | `compare_returns_true_and_false_result_codes` | `compare_against_a_missing_entry_is_no_such_object` | "No" and "no such entry" are different answers. |
| WhoAmI | `whoami_reports_the_effective_identity` | — | Reports the identity in force, not the one requested. |
| Extended ops | — | `unsupported_extended_operations_are_reported_distinctly` | StartTLS is `unavailable` (recognised, not yet possible); an unknown OID is a protocol error. |
| Connection churn | `the_server_survives_a_client_disconnecting` | — | |

## Writes over the wire (`dyno-server/tests/write_operations.rs`)

| Feature | Passing test | Failing test | Validation |
| --- | --- | --- | --- |
| Add | `add_creates_an_entry_that_search_can_find` | `add_is_refused_for_an_anonymous_client`, `add_rejects_a_duplicate_entry`, `add_rejects_malformed_requests` | The refused add is followed by a search proving nothing was created. |
| Add, missing parent | — | `add_rejects_a_missing_parent_and_reports_the_matched_dn` | `matchedDN` names the deepest existing ancestor. |
| Delete | `delete_removes_an_entry` | `delete_rejects_a_missing_entry`, `delete_refuses_a_non_leaf_and_leaves_children_intact`, `delete_is_refused_for_an_anonymous_client` | Every refusal is followed by a check that the data survived. |
| **Add/remove round trip** | `objects_can_be_added_and_removed_repeatedly` | (same test) | Three cycles of absent → added → found → deleted → absent, with the entry count returning to its original value each time. |
| Cross-connection visibility | `writes_are_visible_to_other_connections` | — | A per-connection store would pass every other test here. |
| Modify | `modify_applies_each_change_kind` | `a_failed_modify_applies_nothing` | Atomicity, observed through the protocol. |
| ModifyDN | `modifydn_renames_an_entry` | `modifydn_refuses_to_overwrite_an_existing_entry` | Both entries survive a refused rename. |
| Read-only server | — | `a_read_only_server_refuses_all_writes` | |
| Credential sources | `a_directory_user_can_bind_and_write` | — | A directory password and a configured one are equivalent downstream. |

## Manual smoke test

`ldapsearch` is not installed in this environment, so the shipped binary is
exercised by an example client instead:

```bash
cargo run -p dyno-server -- --config dyno.toml --check    # validate config only
cargo run -p dyno-server -- --config dyno.toml &
cargo run -p dyno-server --example smoke_client -- ldap://127.0.0.1:3389
```

Expected output:

```
connected to ldap://127.0.0.1:3389
root DSE: namingContexts=Some(["dc=example,dc=com"]) vendor=Some(["dyno-ldapserver"])
anonymous subtree search found 6 entries
anonymous add -> result code 50 (anonymous clients may not modify the directory)
bound as cn=admin,dc=example,dc=com
added cn=Carol Danvers,ou=People,dc=example,dc=com
  found cn=Carol Danvers,ou=People,dc=example,dc=com mail=Some(["carol@example.com"])
deleted cn=Carol Danvers,ou=People,dc=example,dc=com
entries matching (cn=carol*) after delete: 0
smoke test passed
```

## Not yet covered

Named so that the gaps are deliberate rather than forgotten:

- **CEL rules** — Phase 2; `dyno-cel` is a documented stub.
- **TLS** — Phase 4. `conn.tls` is always false and StartTLS answers `unavailable`.
- **Proxy** — Phase 5, including the DN-mapper round-trip property test the
  design calls for.
- **Fuzzing the BER decoder** — Phase 6. `parsing_arbitrary_input_never_panics`
  covers the DN parser only; the decoder itself is `ldap3_proto`'s.
- **Abandon** — accepted and ignored, since operations here complete faster
  than a client could abandon them.
- **Paged results and other controls** — decoded by the protocol library,
  ignored by the handler.
