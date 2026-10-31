# Robustness cases

A robustness case is a class of malformed, hostile or degenerate input that a
protocol implementation has to survive, together with the outcome required of
this one. Each case is cited in the source next to the guard that enforces it
and pinned by a named test, so that removing the guard breaks a test rather than
passing quietly. New robustness findings are tracked as issues in this
repository.

The required outcome is always one of the same small set: return an error,
reject the input, or report a condition — never panic, never read past a
buffer, never loop without bound, and never leave partial state behind.

## `iec61850-asn1`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| The indefinite BER length form `0x80`, and a long form of three or more length bytes | `LengthTooLong`. The indefinite form is rejected outright rather than scanned for an end-of-contents marker, which a decoder that accepted it would search for without bound | `decode_indefinite_length_rejected`, `decode_long_form_3_bytes_rejected` in `crates/iec61850-asn1/src/length.rs` |
| A nesting depth bomb: constructed values nested without bound | Capped at the smaller of the local limit of 32 and the depth negotiated for the association, so the stack cannot be exhausted | `effective_nesting_cap` tests in `crates/iec61850-asn1/src/depth.rs` |

## `iec61850-mms`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A TPKT header whose `packet_len` is 4 or less, leaving no COTP payload | `TpktLengthTooSmall`, before any payload slice is taken | `packet_len_4_rejected`, `packet_len_0_rejected`, `packet_len_3_rejected` in `crates/iec61850-mms/src/iso/tpkt.rs`; fuzz target `cotp_parse` |
| A peer that keeps sending COTP DT TPDUs with EOT=0, so the TSDU never ends | `TsduTooLarge` once the reassembled payload passes `DEFAULT_MAX_TSDU_SIZE`, or the limit set through `set_max_tsdu_size`; the reassembly buffer is cleared and the connection moves to `Closed` | `recv_data_default_limit_bounds_reassembly`, `recv_data_accepts_tsdu_at_default_limit`, `recv_data_rejects_tsdu_over_limit` in `crates/iec61850-mms/src/iso/cotp.rs` |
| A Session or ACSE PDU shorter than one tag byte plus one length byte | `TooShort`, before either byte is read | `empty_buf_too_short`, `one_byte_aarq_too_short`, `one_byte_rlrq_too_short` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz targets `session_parse`, `acse_parse` |
| An AARQ TLV, outer or inner, whose declared length runs past the buffer | An error, with no read past the end | `aarq_outer_length_overflow`, `aarq_inner_length_overflow`, `aarq_multibyte_length_overflow` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz target `acse_parse` |
| The same overrun inside an AARE, including its result and user-information fields | An error, with no read past the end | `aare_outer_length_overflow`, `aare_result_inner_length_overflow`, `aare_user_info_length_overflow` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz target `acse_parse` |
| A Presentation PDU carrying an unknown tag with length 0, or a declared length running past the buffer | An unknown element is skipped by a cursor that always advances, so parsing terminates; an overlong length returns `LengthOverflow` | `length_zero_unknown_tag_no_infinite_loop`, `length_overflow_returns_err` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A CP PDU carrying no normal-mode-parameters (`0xa2`) | `MissingNormalModeParameters`, not a silently empty association | `malformed_missing_normal_mode_params` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A CP PDU whose normal-mode-parameters carries no user-data (`0x61`), reached through either CP PDU shape | `MissingUserData` | `malformed_missing_user_data` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A `servicesSupported` BIT STRING whose leading padding-count byte a decoder might read as data | The padding byte is skipped, so the service bitmap is not shifted by one byte | `bit_string_padding_skipped` in `crates/iec61850-mms/src/mms/pdu/initiate.rs`; `bit_string_padding_byte_not_treated_as_data` in `crates/iec61850-mms/tests/mms_pdu_core_roundtrip.rs` |
| A `Data` bit-string or boolean-array whose padding count is above 7, or non-zero with no data byte | `InvalidPdu`; only the padding counts ITU-T X.690 allows are decoded | `bit_string_invalid_padding_rejected`, `bit_string_padding_at_bounds_accepted` in `crates/iec61850-mms/src/mms/pdu/common.rs` |
| A TLV whose declared length reaches past the enclosing PDU, or a length field truncated by the end of the buffer | Rejected without reading past the buffer; every member is bounds-checked against the enclosing end before it is taken | `oversized_length_returns_err`, `truncated_length_returns_err` in `crates/iec61850-mms/src/mms/pdu/common.rs`; `oversized_length_no_panic`, `truncated_length_no_panic` in `crates/iec61850-mms/tests/mms_read_roundtrip.rs` |
| A nesting depth bomb: `Data` or `listOfData` structures nested past the limit | Rejected at the cap, so the stack cannot be exhausted | `depth_bomb_err`, `depth_at_limit_ok` in `crates/iec61850-mms/src/mms/pdu/common.rs`; `write_depth_bomb_err` in `crates/iec61850-mms/src/mms/pdu/write.rs`; `access_result_depth_bomb_err` in `crates/iec61850-mms/tests/mms_read_roundtrip.rs`; `write_listofdata_depth_bomb_err` in `crates/iec61850-mms/tests/mms_write_roundtrip.rs` |
| A Read or Write request whose `alternateAccess` nests `selectAlternateAccess` without bound | `NestingLevelExceeded` before the next level is read, at the local limit of 32, or at the negotiated depth when the request is decoded with `decode_with_negotiated_cap` and that depth is smaller, so the stack cannot be exhausted | `alt_access_depth_bomb_rejected`, `alt_access_chain_one_past_depth_cap_rejected`, `alt_access_negotiated_cap_clamps_chain_depth` in `crates/iec61850-mms/src/mms/pdu/common.rs`; `read_request_negotiated_cap_bounds_alternate_access` in `crates/iec61850-mms/src/mms/pdu/read.rs`; `write_request_negotiated_cap_bounds_alternate_access` in `crates/iec61850-mms/src/mms/pdu/write.rs`; `read_request_alternate_access_depth_bomb_err` in `crates/iec61850-mms/tests/mms_read_roundtrip.rs` |
| The indefinite BER length form inside an MMS PDU, including on a response tag | An error, not an unbounded scan | `indefinite_length_returns_err`, `indefinite_length_response_tag_returns_err` in `crates/iec61850-mms/tests/mms_pdu_core_roundtrip.rs` |
| A Confirmed-RequestPDU arriving before the Initiate exchange completes, such as one carried in the AARQ user information in place of the Initiate-RequestPDU | Reject(pdu-error/invalid-pdu); the request never reaches the service dispatcher | `confirmed_request_before_initiate_rejected` in `crates/iec61850-mms/src/mms/server/dispatch.rs` |
| An encoded PDU larger than the size negotiated for the association | `PduTooLarge`: the PDU is refused, never truncated; a PDU of exactly the negotiated size is sent | `pdu_at_the_negotiated_size_is_sent_and_one_above_is_refused` in `crates/iec61850-client/tests/mms_association_e2e.rs` |
| A confirmed answer under an invokeID that matches no outstanding request, including the late answer to a request that timed out | Discarded with a warning; the request it does not belong to keeps waiting for its own answer, and the identifiers given up on are bounded at 64, the oldest forgotten first | `answer_under_another_invoke_id_is_discarded`, `unanswered_request_times_out_and_leaves_the_association_usable` in `crates/iec61850-mms/tests/mms_client_wire_e2e.rs`; `abandoned_invoke_ids_are_bounded_and_the_oldest_is_forgotten` in `crates/iec61850-mms/src/mms/client/connection.rs` |
| Unconfirmed PDUs arriving faster than the application reads them while confirmed calls are in flight | Held up to `max_pending_unconfirmed`, 1024 by default; the oldest is dropped with a warning | `pending_unconfirmed_pdus_are_bounded` in `crates/iec61850-mms/tests/mms_client_wire_e2e.rs` |
| An Unconfirmed PDU with no content (`a3 00`), which lacks the mandatory unconfirmedService | Discarded with a warning; it is neither stashed nor handed to the caller | `unconfirmed_pdu_without_content_is_discarded` in `crates/iec61850-mms/tests/mms_client_wire_e2e.rs` |

## `iec61850-goose`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A TLV whose declared length reaches past the enclosing PDU | Rejected without reading past the buffer | `element_length_overflow_rejected` in `crates/iec61850-goose/src/pdu.rs`; `malformed_element_length_returns_err` in `crates/iec61850-goose/src/receiver.rs`; seeds in `crates/iec61850-goose/fuzz/bin/gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| An INTEGER or UNSIGNED element inside `allData` declaring more than 8 content bytes | Rejected, rather than truncated into an `i64` or `u64` | `reject_integer_too_long` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| A five-octet header INTEGER, such as an stNum, whose first octet is not `0x00` | Rejected with a warning, rather than truncated to its low 32 bits | `five_byte_integer_with_nonzero_lead_is_rejected` in `crates/iec61850-goose/tests/receive_path.rs` |
| A BIT STRING with no padding-count byte | Rejected; content is only ever taken from a bounds-checked slice | `reject_invalid_bit_string_padding` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| The indefinite BER length form `0x80` | Rejected | `indefinite_length_rejected` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| `stNum` reaching the end of its range | `stNum` wraps to 1, never to 0, which subscribers read as an uninitialized publisher | `st_num_wraps_to_one_not_zero` in `crates/iec61850-goose/src/publisher.rs` |

## `iec61850-sv`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A sample longer than 127 bytes, whose length needs the long BER form | The total PDU length is computed from the long form, so the frame encodes and decodes intact | `large_sample_ber_length` in `crates/iec61850-sv/src/pdu.rs` and `crates/iec61850-sv/tests/sv_pdu_roundtrip.rs`; fuzz target `sv_pdu_parse` |
| A zero-length sample OCTET STRING | Decoded as an empty sample rather than treated as a length underflow | Seed `sample_size_zero.bin` from `crates/iec61850-sv/fuzz/bin/gen_corpus.rs`; fuzz target `sv_pdu_parse` |
| A forged first frame whose sample has a different length from the real stream | The frame decides nothing about later ones: a subscriber checks every ASDU against the length it is built with, or, built without one, delivers each ASDU with its own bounds-checked sample | `forged_first_frame_does_not_lock_sample_length`, `q4_sample_size_mismatch_skips_callback` in `crates/iec61850-sv/tests/sv_subscriber_dispatch.rs` |
| A savPdu whose noASDU is absent, differs from the number of ASDUs it carries, or is a multi-byte count whose low octet alone would match, or whose sequence of ASDU holds more than `MAX_ASDU_PER_FRAME` ASDUs, or that repeats either member | The frame is dropped with `MissingRequiredField`, `InvalidFieldLength`, `TooManyAsdus` or `DuplicateField`; every content octet of noASDU is decoded, and no ASDU past the limit is parsed | `no_asdu_count_mismatch_rejected`, `no_asdu_absent_rejected`, `no_asdu_matching_count_accepted`, `asdu_sequence_past_limit_rejected`, `duplicate_sav_pdu_member_rejected` in `crates/iec61850-sv/src/pdu.rs`; seeds `no_asdu_count_mismatch.bin`, `no_asdu_multi_octet.bin` from `crates/iec61850-sv/fuzz/bin/gen_corpus.rs`; fuzz target `sv_pdu_parse` |

## `iec61850-server`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A logical node name and data object name that together exceed a fixed-size item identifier buffer | The reference is formatted into an allocated `String`, so any length is safe and no buffer is overrun | `long_names_no_panic` in `crates/iec61850-server/src/control/object.rs` |
| `vendorName`, `modelName` or `revision` far longer than any fixed buffer, including the exact boundary length | The response is built in owned buffers, so a long string neither overflows nor overruns the stack | `identify_long_strings_no_stack_overflow`, `identify_at_fixed_buffer_boundary` in `crates/iec61850-server/src/service/mod.rs` |
| An object reference or domain name longer than the 64-byte MMS identifier limit, including the exact boundary | An error, never a silent truncation; two logical devices resolving to the same name are an error too | `long_do_da_path_no_overflow`, `domain_at_max_len_ok` in `crates/iec61850-server/src/mapping.rs` |
| A storage error part way through writing a log entry | The error is propagated; no partially written entry is left behind | `error_is_propagated_not_partial_state` in `crates/iec61850-server/src/logging/lcb.rs` |
| A report too large for one PDU | Segmented, each segment within the negotiated limit, `moreFollows` set on every segment but the last | `segmented_report_correct` in `crates/iec61850-server/src/reporting/pdu.rs` |
| A thread that already holds the data model lock locking it again | `Err(AlreadyLocked)`, so the caller chooses to wait or give up, instead of deadlocking | `lock_data_model_reentry_returns_err` in `crates/iec61850-server/src/server.rs` |
| A peer closing the association while one of its requests is still in flight | Invalidation and access are mutually exclusive: the MMS state is taken out from under the mutex, and background work is counted so a release waits for it to reach zero | `invalidate_marks_inactive`, `invalidated_connection_set_block_requests_returns_false` in `crates/iec61850-server/src/connection.rs` |
| An update whose value type does not match the data attribute's current type | `TypeMismatch` at run time, rather than an assertion a release build would drop | `update_boolean_type_mismatch_returns_err_no_engine_trigger` in `crates/iec61850-server/tests/reporting_update_hook.rs` |
| A SetDataSetValues whose data set includes a member the write access policy refuses, or whose value for a member has the wrong type | Each member is written through the single-write path and answered as a Write naming it alone would be; a refused member keeps its value | `set_data_set_values_applies_member_write_access`, `set_data_set_values_refuses_a_mistyped_member` in `crates/iec61850-server/src/service/mod.rs` |
| A Write, or a SetDataSetValues member, carrying a bit string whose length does not fit the declared size of the attribute, such as 13 bits or none for a two-bit `Dbpos` | `type-inconsistent`, and the attribute keeps its value; a read handler value of such a length is not sent and the read answers `object-value-invalid` | `write_to_fixed_size_bit_string_checks_length`, `write_to_bounded_bit_string_checks_upper_bound`, `set_data_set_values_checks_member_length`, `read_handler_bit_string_of_other_length_refused`, `read_handler_bit_string_checks_upper_bound` in `crates/iec61850-server/tests/bit_string_length_e2e.rs`; `write_boolean_array_of_other_length_returns_type_inconsistent`, for the same bit string sent as a boolean-array, in `crates/iec61850-server/src/service/write.rs` |
| An AARQ whose user information is a confirmed request rather than an Initiate-RequestPDU | Answered with an associate reject and the socket closed; the request is never dispatched | `request_in_place_of_initiate_is_not_executed` in `crates/iec61850-server/tests/association_lifecycle.rs` |
| A peer that resets its socket, or sends a malformed TPKT, after reserving a URCB, opening a setting group edit session or selecting a control object | All are released when the connection task ends, whichever layer ended it | `transport_error_releases_association_state` in `crates/iec61850-server/tests/association_lifecycle.rs` |
| Many sockets that connect and then send nothing, or stop part way through association setup | Each holds one of the `max_mms_connections` slots from accept, and is closed once `association_setup_timeout_ms` passes without an Initiate response | `unassociated_socket_counts_against_the_limit`, `stalled_setup_is_closed_after_the_setup_timeout` in `crates/iec61850-server/tests/association_lifecycle.rs`; `over_max_connections_drops_socket` in `crates/iec61850-server/tests/initiate_handshake.rs`; `stalled_tls_handshake_is_closed_after_the_setup_timeout` in `crates/iec61850-server/tests/server_tls_handshake.rs` |
| An established association that falls silent while holding a connection slot | Aborted once `association_idle_timeout_ms` passes with no PDU received or sent; a client that only receives reports stays open | `silent_client_is_aborted_at_the_idle_timeout`, `report_only_client_outlives_the_idle_timeout`, `requesting_client_outlives_the_idle_timeout` in `crates/iec61850-server/src/lifecycle.rs` |
| A peer that stops reading while the server has PDUs to send | The blocked write ends the connection once it exceeds `association_send_timeout_ms`; the slot and the association's reservations are released | `peer_that_stops_reading_is_closed_after_the_send_timeout`, `reading_peer_outlasts_the_send_timeout` in `crates/iec61850-server/src/lifecycle.rs` |
| DefineNamedVariableList repeated under new names | Refused with `resource capability-unavailable` beyond `max_dynamic_datasets` across the server or `max_dynamic_datasets_per_association` for one open association | `define_named_variable_list_is_bounded_per_association`, `define_named_variable_list_is_bounded_in_total` in `crates/iec61850-server/src/service/mod.rs`; `data_set_limit_applies_per_association` in `crates/iec61850-server/tests/association_lifecycle.rs` |
| A Read whose alternate access, or a Write whose data, nests deeper than the association's negotiated `dataStructureNestingLevel` | Refused as undecodable with a confirmed error before any service runs | `read_alternate_access_is_bounded_by_the_negotiated_nesting_level`, `write_data_is_bounded_by_the_negotiated_nesting_level` in `crates/iec61850-server/src/service/mod.rs` |
| A TSDU larger than the association's negotiated maximum PDU size plus its envelope | The connection is closed once the reassembled TSDU passes the bound, and the request is not answered | `tsdu_is_bounded_by_the_negotiated_pdu_size` in `crates/iec61850-server/src/lifecycle.rs` |

## `iec61850-client`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A report handler removed while its own callback is still running | The callback receives an owned snapshot, so removing a handler mid-callback cannot invalidate what the callback is reading | `uaf_resistance_uninstall_during_callback`, `callback_signature_is_owned_snapshot` in `crates/iec61850-client/src/report/dispatch.rs` |
| A report whose member count differs from the `DatasetDirectory` the handler was installed with | Rejected before it reaches the subscription state or the callback | `report_with_another_member_count_than_expected_is_rejected` in `crates/iec61850-client/src/report/dispatch.rs` |
| A server that keeps reporting more names in GetNameList, repeating the same page or sending new names without end | The walk fails with an error when a page does not advance past the previous continuation, or past one million names | `name_list_walk_that_does_not_advance_is_an_error`, `name_list_walk_past_the_name_limit_is_an_error` in `crates/iec61850-client/tests/directory_scripted_e2e.rs` |

## `iec61850-scl`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A DOType that reaches itself through its `<SDO>` chain, directly or through other DOTypes | `SemanticConflict` naming the cycle when the file is resolved, before any model is built, so the build cannot recurse without bound | `dotype_sdo_self_cycle_is_rejected`, `dotype_sdo_indirect_cycle_is_rejected` in `crates/iec61850-scl/tests/model_build_checks.rs` |
| A DOType sub-object chain or a DAType nesting deeper than 32 levels | `SemanticConflict` when the file is resolved, so a deep but acyclic chain cannot exhaust the stack; 32 levels still build | `sdo_chain_of_1000_levels_is_rejected`, `da_type_chain_of_1000_levels_is_rejected`, `chains_at_the_bound_build` in `crates/iec61850-scl/tests/type_nesting.rs` |

## `iec61850-sntp`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A datagram longer than the 48-octet header, such as a request with an authenticator or one larger than the receive buffer | The header is decoded and answered, or the datagram dropped; the server keeps serving | `request_with_an_authenticator_is_answered`, `datagram_longer_than_the_buffer_does_not_stop_the_server` in `crates/iec61850-sntp/tests/datagram_handling.rs` |
| A receive error that concerns one datagram, such as the ICMP port unreachable a reply meets | Logged as a warning, and the server keeps serving; only a failure of the socket itself ends `run()` | `receive_loop_decision_follows_the_raw_os_error` in `crates/iec61850-sntp/src/server.rs` |

## `iec61850-tls`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A peer certificate absent from the allow-only-known list, a certificate that differs from a listed one in a single byte, and an allow list that is empty | All rejected. An empty list rejects every peer rather than admitting all of them | `allow_only_known_empty_list_rejects`, `allow_only_known_peer_in_list_accepts`, `allow_only_known_peer_not_in_list_rejects`, `allow_only_known_disabled_passes_chain_only`, `allow_only_known_compares_every_byte_of_the_leaf` in `crates/iec61850-tls/src/tests/allow_only_known.rs` |
| A client that presents no certificate to a server in allow-only-known mode | Refused during the handshake | `client_without_certificate_is_refused_when_only_known_peers_are_allowed` in `crates/iec61850-tls/tests/handshake.rs` |
| An expired or not-yet-valid peer certificate while validity-time checking is switched off | Accepted only when it passes every other check at a time inside its validity period, and the downgrade is reported through the event handler. A certificate from an untrusted issuer, one outside the allow-only-known list, a bad signature, and an expiry error that carries no validity period are still rejected | `expired_cert_with_time_validation_rejects`, `expired_cert_with_time_validation_off_passes_with_warning`, `bad_signature_with_time_validation_off_still_rejects`, `expired_cert_from_an_untrusted_ca_with_time_validation_off_rejects`, `expiry_without_context_with_time_validation_off_rejects`, `chain_needing_three_verifications_with_time_validation_off_passes` in `crates/iec61850-tls/src/tests/validity_time_override.rs`; `client_with_time_validation_off_rejects_an_expired_certificate_from_an_untrusted_ca`, `expired_unknown_server_is_refused_in_allow_only_known_mode_with_time_validation_off` in `crates/iec61850-tls/tests/handshake.rs` |
| A TLS 1.2 session running indefinitely on one key | A renegotiation interval bounds it | `renegotiation_interval` in `crates/iec61850-tls/src/config.rs`. **Not applied** — see below |

## Cases with a gap

One row above does not fully meet the premise this document sets out in its
opening paragraph. It is recorded here rather than presented as satisfied.

**The renegotiation interval is not applied.** The interval is accepted at
`crates/iec61850-tls/src/config.rs`, and building a configuration with it set
logs a warning, but `rustls`
offers no server-initiated renegotiation, so no HelloRequest is ever sent and a
TLS 1.2 session is not in fact rekeyed on the interval. Bounding a session's
lifetime therefore has to come from the application closing and reopening the
association. TLS 1.3 replaces the mechanism with key updates and is not subject
to the case.

## Fuzz targets

Nine `cargo-fuzz` targets exercise the same decoders with generated input. Each
target asserts that the decoder returns rather than panics, and that a
successful decode round-trips where a round trip is defined.

| Crate | Targets |
|---|---|
| `iec61850-mms` | `cotp_parse`, `session_parse`, `presentation_parse`, `acse_parse`, `mms_pdu_decode` |
| `iec61850-goose` | `goose_frame_parse`, `goose_pdu_parse` |
| `iec61850-sv` | `sv_frame_parse`, `sv_pdu_parse` |

Run one with:

```sh
cd crates/iec61850-goose/fuzz && cargo fuzz run goose_pdu_parse
```

The Sampled Values seed corpus is checked in under
`crates/iec61850-sv/fuzz/corpus/`. The GOOSE corpus is regenerated on demand,
because its seeds are produced rather than collected:

```sh
cd crates/iec61850-goose/fuzz && cargo run --bin gen_corpus
```

Each seed has a fixed file name, so a corpus the fuzzer has grown is not
overwritten. Seeds carrying a robustness case describe it in their doc comment.

## Adding a case

1. Add the guard, with a comment stating the malformed-input class and the
   required outcome — not what the next line does.
2. Add a test named for what it pins, such as `element_length_overflow_rejected`.
   Where a case is already covered by an existing behavioral test, state the
   required outcome in that test's doc comment instead of duplicating it.
3. Where the case is reachable from a decoder that has a fuzz target, add a seed
   to that target's corpus generator.
4. Add a row to the table for the crate that owns the guard.
