# Contributing

Contributions are welcome: bug reports, protocol corrections, interoperability
findings, tests and documentation as much as code. A correction backed by a
clause of the standard or a capture from real equipment is especially useful.

Do not open a public issue for a suspected vulnerability. [`SECURITY.md`](SECURITY.md)
has the private reporting channel.

## Getting set up

The toolchain is stable Rust; `rust-toolchain.toml` pins the channel and pulls
in `rustfmt` and `clippy`. The minimum supported version is `1.88`, declared
once in the workspace manifest.

```sh
git clone https://github.com/csp0924/iec61850-rust
cd iec61850-rust
cargo build --workspace
cargo test --workspace
```

No system libraries are needed for the default build. Two optional paths do have
requirements: the `ethernet-pcap` and `ethernet-windows-npcap` features of
`iec61850-hal` need libpcap on Linux or the NPCAP runtime on Windows, and the
`sqlite-backend` feature of `iec61850-server` compiles a bundled SQLite, which
takes longer to build than the rest of the workspace.

## Checks CI enforces

The first four run on both Linux and Windows for a pull request; `cargo deny
check` runs once, on Linux, as a separate job. A failure in any of them blocks
the merge, so run them locally before opening one.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
```

`cargo clippy` runs with warnings denied, so a new warning is a failure. The
documentation build denies rustdoc warnings too, which catches a broken intra-doc
link or a malformed code block.

`cargo deny check` covers advisories, the license allow list, duplicate versions
and dependency sources. No advisories stand open against `0.1.0`; a change must
not introduce one. Adding a crate under a license outside the allow list, or
suppressing an advisory, needs the reason recorded in `deny.toml` next to the
entry.

Cross-compilation is worth running when you touch a crate that supports it. All
six build for `thumbv7em-none-eabihf`:

```sh
cargo check -p iec61850-asn1   --target thumbv7em-none-eabihf --no-default-features --features alloc
cargo check -p iec61850-model  --target thumbv7em-none-eabihf --no-default-features --features embedded
cargo check -p iec61850-hal    --target thumbv7em-none-eabihf --no-default-features --features alloc,transport
cargo check -p iec61850-mms    --target thumbv7em-none-eabihf --no-default-features --features embedded
cargo check -p iec61850-client --target thumbv7em-none-eabihf --no-default-features --features minimal,embedded
cargo check -p iec61850-server --target thumbv7em-none-eabihf --no-default-features --features minimal,embedded
```

CI does not run these, so a bare-metal regression is only caught by whoever
runs them.

## Contracts

These are not preferences. A change that breaks one does not get merged.

**Library code does not panic.** Every fallible path returns `Result<T, E>`.
No `unwrap`, no `expect`, no indexing that can be out of range, no arithmetic
that can overflow in a release build, and no assertion standing in for error
handling — an assertion a release build drops is not a check. `unwrap` in a test
is fine. If you find a panic reachable from library code, document it honestly
in the item's `# Panics` section and add a `// TODO:` naming the gap.

**External input is never sliced directly.** Writing `&buf[n..m]` on bytes that
came off the wire is the defect this rule exists to prevent. Take bytes through
the bounds-checked reader, which returns an error when a declared length reaches
past the buffer.

**Decoding is bounded.** Nesting depth is capped by the smaller of the local
limit and the depth negotiated for the association. The indefinite BER length
form is rejected rather than scanned.

**Strings are validated UTF-8.** A string field is `&str` or `String`.
Arbitrary bytes are an octet string, typed as one.

**Time values carry their unit.** Name a duration or timestamp with a `_ns`,
`_ms` or `_s` suffix. A bare `u64` is never a time value.

**Errors are not silent.** A rejected PDU or a dropped frame gets a
`tracing::warn!` before it is discarded.

**`unsafe` stays where it is.** It exists in the Linux `AF_PACKET` backend of
`iec61850-hal` and the real-time publish loop of `iec61850-sv`, each block with
a safety argument. Five crates carry `#![forbid(unsafe_code)]`. Introducing
`unsafe` anywhere else needs a case made in the pull request.

## Comment style

Comments state what the code guarantees, not how it came to be. American
English, third person, present tense, declarative. No first person, no emoji, no
markdown headers inside inline comments, and no history — not "originally", not
"used to", not "was changed because". A reader wants the contract, not the
changelog; the changelog is in `CHANGELOG.md` and the reasoning is in the pull
request.

**Module headers (`//!`)** — every `lib.rs` and every module that exports items
carries two to eight lines: what the module implements and the part of the
standard it maps to, its wire or protocol scope, and the invariants a caller
relies on.

**Item docs (`///`)** — every public item. The first line is one sentence ending
in a period. After that, only what adds information: a short semantics
paragraph; `# Errors` naming the variants and when each occurs; `# Panics` only
if the item can panic; `# Examples` where one is genuinely clarifying. A plain
field or enum variant gets one line. Keep a doc comment under about ten lines
unless the contract really is that involved.

**Inline (`//`)** — only for a non-obvious *why*: a protocol corner case, an
invariant, an ordering constraint, an interoperability accommodation, the safety
argument for an `unsafe` block. Never restate what the next line does. Three
lines at most; longer reasoning belongs in the item doc. `// TODO: <concrete gap>`
is allowed and is the one exception to the no-history rule. Do not add
speculative ones.

**Standards citations** — cite as `IEC 61850-8-1 §8.1.3.2`,
`IEC 61850-7-2 Table 25`, `ISO 9506-2`, `ISO 8823 (Presentation)`,
`ISO 8073 / RFC 1006 (COTP over TCP)`, `IEC 62351-4`, `RFC 5246`. Give a clause,
table or figure number only when you have checked it in the document. Citing the
part alone (`per IEC 61850-8-1`) is always acceptable; an invented clause number
is a defect, because a reader who follows it up loses their trust in every other
citation in the file.

**Terminology** — IED, logical device (LD), logical node (LN), data object (DO),
data attribute (DA), functional constraint (FC), data set, RCB, URCB, BRCB,
GoCB, SvCB, LCB, SGCB; ACSI service names as in IEC 61850-7-2 (GetNameList,
Read, Write, Select, SelectWithValue, Operate, Cancel); MMS PDU names as in
ISO 9506 (Initiate-RequestPDU, Confirmed-ResponsePDU); object references in
`ldName/lnName.doName.daName` form.

**Runtime-visible strings** — error `Display` text, `tracing` messages, test
panic messages and command-line help are English lowercase fragments with no
trailing period.

Identifiers — module, type, function, variable and test names — are English.

## Tests

A change to protocol behavior comes with a test that fails without it. Encoders
and decoders get a round trip; a decoder also gets its malformed input. Prefer a
byte-level vector over a constructed value where the wire format is what is
being pinned, and keep the vector in the test rather than behind a helper, so
that a reader can see what is on the wire.

Do not change an existing byte-level test vector to make a change pass. If a
vector is wrong, that is its own finding, and it needs the standard cited in the
pull request.

Tests that need two peers use loopback and pick a port at run time; nothing in
the suite needs hardware, elevated privileges or an external server. A test that
would need a real NIC belongs in an example named `*_live` instead.

## Adding a robustness case

A robustness case is a class of malformed or hostile input with a required
outcome, pinned by a test. [`docs/robustness.md`](docs/robustness.md) is the
catalog; new findings are tracked as issues in this repository.

1. Add the guard. Comment it with the malformed-input class and the required
   outcome — for example, "a member whose declared length exceeds the enclosing
   PDU is rejected without reading past the buffer."
2. Add a test named for what it pins, such as `element_length_overflow_rejected`.
   Where an existing behavioral test already covers the case, state the required
   outcome in that test's doc comment instead of duplicating it.
3. If the case is reachable from a decoder that has a fuzz target, add a seed.
   `iec61850-goose` and `iec61850-sv` keep a corpus generator at
   `crates/<crate>/fuzz/bin/gen_corpus.rs`; add the seed there. The
   `iec61850-mms` fuzz package has no generator, so a seed for one of its five
   targets goes into that target's corpus directory as a file.
4. Add a row to `docs/robustness.md`: the malformed input, the required
   outcome and the test that holds it. If the guard ships without a
   test that actually drives it, say so in the "Cases with a gap" section rather
   than citing a test that only touches the error type.

## Pull requests

Keep a pull request to one change. A protocol fix, a refactor and a
documentation pass are three pull requests, because a reviewer checking a
protocol fix against the standard should not be reading a rename at the same
time.

Write the commit message in the imperative mood, with a subject under about
seventy characters and a body explaining what the change does and, where the
answer is not obvious, why. Cite the clause of the standard that a protocol
change follows.

Say in the description what you ran and what you saw. "Tests pass" is worth
less than the command and its output, and a reviewer cannot verify a claim that
has no evidence behind it.
