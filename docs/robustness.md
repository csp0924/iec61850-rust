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
| A Session or ACSE PDU shorter than one tag byte plus one length byte | `TooShort`, before either byte is read | `empty_buf_too_short`, `one_byte_aarq_too_short`, `one_byte_rlrq_too_short` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz targets `session_parse`, `acse_parse` |
| An AARQ TLV, outer or inner, whose declared length runs past the buffer | An error, with no read past the end | `aarq_outer_length_overflow`, `aarq_inner_length_overflow`, `aarq_multibyte_length_overflow` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz target `acse_parse` |
| The same overrun inside an AARE, including its result and user-information fields | An error, with no read past the end | `aare_outer_length_overflow`, `aare_result_inner_length_overflow`, `aare_user_info_length_overflow` in `crates/iec61850-mms/tests/acse_robustness.rs`; fuzz target `acse_parse` |
| A Presentation PDU carrying an unknown tag with length 0, or a declared length running past the buffer | An unknown element is skipped by a cursor that always advances, so parsing terminates; an overlong length returns `LengthOverflow` | `length_zero_unknown_tag_no_infinite_loop`, `length_overflow_returns_err` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A CP PDU carrying no normal-mode-parameters (`0xa2`) | `MissingNormalModeParameters`, not a silently empty association | `malformed_missing_normal_mode_params` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A CP PDU whose normal-mode-parameters carries no user-data (`0x61`), reached through either CP PDU shape | `MissingUserData` | `malformed_missing_user_data` in `crates/iec61850-mms/src/iso/presentation.rs`; fuzz target `presentation_parse` |
| A `servicesSupported` BIT STRING whose leading padding-count byte a decoder might read as data | The padding byte is skipped, so the service bitmap is not shifted by one byte | `bit_string_padding_skipped` in `crates/iec61850-mms/src/mms/pdu/initiate.rs`; `bit_string_padding_byte_not_treated_as_data` in `crates/iec61850-mms/tests/mms_pdu_core_roundtrip.rs` |
| A TLV whose declared length reaches past the enclosing PDU, or a length field truncated by the end of the buffer | Rejected without reading past the buffer; every member is bounds-checked against the enclosing end before it is taken | `oversized_length_returns_err`, `truncated_length_returns_err` in `crates/iec61850-mms/src/mms/pdu/common.rs`; `oversized_length_no_panic`, `truncated_length_no_panic` in `crates/iec61850-mms/tests/mms_read_roundtrip.rs` |
| A nesting depth bomb: `Data` or `listOfData` structures nested past the limit | Rejected at the cap, so the stack cannot be exhausted | `depth_bomb_err`, `depth_at_limit_ok` in `crates/iec61850-mms/src/mms/pdu/common.rs`; `write_depth_bomb_err` in `crates/iec61850-mms/src/mms/pdu/write.rs`; `access_result_depth_bomb_err` in `crates/iec61850-mms/tests/mms_read_roundtrip.rs`; `write_listofdata_depth_bomb_err` in `crates/iec61850-mms/tests/mms_write_roundtrip.rs` |
| The indefinite BER length form inside an MMS PDU, including on a response tag | An error, not an unbounded scan | `indefinite_length_returns_err`, `indefinite_length_response_tag_returns_err` in `crates/iec61850-mms/tests/mms_pdu_core_roundtrip.rs` |
| An encoded PDU larger than the size negotiated for the association | `PduTooLarge`: the PDU is refused, never truncated | **Not pinned** — see [Cases with a gap](#cases-with-a-gap) |

## `iec61850-goose`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A TLV whose declared length reaches past the enclosing PDU | Rejected without reading past the buffer | `element_length_overflow_rejected` in `crates/iec61850-goose/src/pdu.rs`; `malformed_element_length_returns_err` in `crates/iec61850-goose/src/receiver.rs`; seeds in `crates/iec61850-goose/fuzz/bin/gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| An INTEGER or UNSIGNED element inside `allData` declaring more than 8 content bytes | Rejected, rather than truncated into an `i64` or `u64` | `reject_integer_too_long` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| A BIT STRING with no padding-count byte | Rejected; content is only ever taken from a bounds-checked slice | `reject_invalid_bit_string_padding` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| The indefinite BER length form `0x80` | Rejected | `indefinite_length_rejected` in `crates/iec61850-goose/src/pdu.rs`; seed in `gen_corpus.rs`; fuzz target `goose_pdu_parse` |
| `stNum` reaching the end of its range | `stNum` wraps to 1, never to 0, which subscribers read as an uninitialized publisher | `st_num_wraps_to_one_not_zero` in `crates/iec61850-goose/src/publisher.rs` |

## `iec61850-sv`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A sample longer than 127 bytes, whose length needs the long BER form | The total PDU length is computed from the long form, so the frame encodes and decodes intact | `large_sample_ber_length` in `crates/iec61850-sv/src/pdu.rs` and `crates/iec61850-sv/tests/sv_pdu_roundtrip.rs`; fuzz target `sv_pdu_parse` |
| A zero-length sample OCTET STRING | Decoded as an empty sample rather than treated as a length underflow | Seed `sample_size_zero.bin` from `crates/iec61850-sv/fuzz/bin/gen_corpus.rs`; fuzz target `sv_pdu_parse` |

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

## `iec61850-client`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A report handler removed while its own callback is still running | The callback receives an owned snapshot, so removing a handler mid-callback cannot invalidate what the callback is reading | `uaf_resistance_uninstall_during_callback`, `callback_signature_is_owned_snapshot` in `crates/iec61850-client/src/report/dispatch.rs` |

## `iec61850-tls`

| Malformed input | Required outcome | Pinned by |
|---|---|---|
| A peer certificate absent from the allow-only-known list, and an allow list that is empty | Both rejected. An empty list rejects every peer rather than admitting all of them | `allow_only_known_empty_list_rejects`, `allow_only_known_peer_in_list_accepts`, `allow_only_known_peer_not_in_list_rejects`, `allow_only_known_disabled_passes_chain_only` in `crates/iec61850-tls/src/tests/allow_only_known.rs` |
| An expired or not-yet-valid peer certificate while validity-time checking is switched off | Only the expiry error is downgraded, and the downgrade is reported through the event handler. Every other chain error, a bad signature included, is still rejected | `expired_cert_with_time_validation_rejects`, `expired_cert_with_time_validation_off_passes_with_warning`, `bad_signature_with_time_validation_off_still_rejects` in `crates/iec61850-tls/src/tests/validity_time_override.rs` |
| A TLS 1.2 session running indefinitely on one key | A renegotiation interval bounds it | `renegotiation_interval` in `crates/iec61850-tls/src/config.rs`. **Partly implemented** — see below |

## Cases with a gap

Two rows above do not fully meet the premise this document sets out in its
opening paragraph. Both are recorded here rather than presented as satisfied.

**The renegotiation interval is not fully implemented.** The interval is
accepted and recorded at `crates/iec61850-tls/src/config.rs`, but `rustls`
offers no server-initiated renegotiation, so no HelloRequest is ever sent and a
TLS 1.2 session is not in fact rekeyed on the interval. Bounding a session's
lifetime therefore has to come from the application closing and reopening the
association. TLS 1.3 replaces the mechanism with key updates and is not subject
to the case.

**The PDU-size refusal is implemented but not pinned by a test.** The guard is
real: `send_mms_pdu` in `crates/iec61850-mms/src/mms/client/connection.rs`
measures the encoded PDU against `negotiated_max_pdu_size`, logs a warning and
returns `ClientError::PduTooLarge` before anything is sent. No test drives a PDU
through that path, though. The one test on that error,
`pdu_too_large_error_can_be_constructed` in
`crates/iec61850-mms/tests/mms_client_integration.rs`, builds the error value
and checks its `Display` text; it does not exercise the guard, so deleting the
size check would not fail it. The segmentation half of the case is genuinely
pinned. Closing this means driving an oversized PDU through `send_mms_pdu`
against a negotiated size small enough to trip it.

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
