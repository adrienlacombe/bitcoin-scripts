# Original HASH160 Winternitz

This is the original configurable verifier/converter implementation and its
`Wots` / `CompactWots` wrappers. It retains the existing wire format and test
vectors. For new typed base-16 profiles see [base16/](../base16/README.md);
compare total costs in the [overview](../README.md).

## Parameters and API

The `Wots4`, `Wots16`, `Wots32`, `Wots64`, and `Wots80` wrappers use four-bit
digits, 20-byte HASH160 chains, and a 20-byte secret. The low-level
`Parameters` and `Winternitz<V, C>` types select digit geometry, verifier
strategy, and output conversion; use `Parameters` to derive checksum and
chain counts. This implementation does not use the typed `Preimage16` mode.

`api.rs` defines the high-level traits and fixed arrays. `verification.rs`
contains parameter handling, list-pick/brute-force verification, and output
converters. `signing.rs` contains the original signing helpers; `utils.rs`
contains digit and stack representation utilities. Low-level module paths
are `winternitz::legacy::{api, signing, verification, utils}`. Existing
high-level types remain exported from `winternitz`.

## Script metrics

The following historical 32-byte measurements use secret `[0x42;20]` and a
zero-message witness. They are regression fixtures, not a typical-message
comparison. Locking fragments include endpoints, chain checks, checksum,
and the stated recovery/cleanup contract. Witness sizes include the complete
serialized item vector. The final predicate and transaction framing are
excluded. Add script and witness bytes to compare the same boundary.

| Configuration | Locking script | Unlocking witness (zero / upper bound) | Maximum stack items |
| --- | ---: | ---: | ---: |
| Legacy list-pick, recover message | <!-- metric:wots32_lock -->4908<!-- /metric:wots32_lock --> bytes | <!-- metric:wots32_witness -->1477<!-- /metric:wots32_witness --> / <!-- metric:wots32_witness_max -->1542<!-- /metric:wots32_witness_max --> bytes | <!-- metric:wots32_stack -->143<!-- /metric:wots32_stack --> |
| Legacy list-pick, clear message | <!-- metric:wots32_clear_lock -->4844<!-- /metric:wots32_clear_lock --> bytes | same as legacy recovery | <!-- metric:wots32_clear_stack -->143<!-- /metric:wots32_clear_stack --> |
| Legacy list-pick, terminal | <!-- metric:wots32_clear_static_opcodes -->3166<!-- /metric:wots32_clear_static_opcodes --> |

## Witness, hints, and stack contract

The standard witness is `[chain_0, digit_0, ...]`, with 134 signature items
for 32 bytes and **0 auxiliary hints**. All coexist at entry; the measured
combined main/alt-stack peak is 143. Recovery returns 64 message nibbles;
`checksig_verify_and_clear_stack` consumes them. Append the caller’s terminal
predicate. Converter choice changes the output representation and must match
the consumer. Compact signing omits explicit digit items and uses the
brute-force recovery strategy; its costs are not the list-pick rows above.

## Security

Keys are strictly one-time; these APIs do not enforce durable seed lifecycle
or prevent signing twice. HASH160 has an 80-bit generic collision bound,
which is not an end-to-end signature-security claim. These are classic
unkeyed chains, not WOTS+. The list-pick strategy clamps digits above their
maximum: it authenticates the normalized message and permits raw witness
aliases. Do not use it as a strict raw-digit range check. Signature proof-byte
consumers must use the authenticated output, not a separately supplied value.

## Script compatibility and standardness

Published metrics are `locally-reproduced`, `research-unlimited`: the metric
helper executes tapscript with stack checks disabled. Separate strict local
tests do not establish Bitcoin Core consensus or relay-policy validity. The
measured scripts exceed legacy opcode limits for bare Script, P2SH, and
P2WSH. No complete transaction or Core differential harness is included.

## Tests and knowledge links

[tests/api.rs](tests/api.rs), [tests/signing.rs](tests/signing.rs), and
[tests/verification.rs](tests/verification.rs) cover the original interfaces.
[tests/vectors.json](tests/vectors.json) retains the original fixed vectors.
Run `cargo test --locked --lib signatures::winternitz::legacy`.

See the [primitive page](../../../../knowledge/primitives/winternitz-base16.md),
[cost model](../../../../knowledge/cost-model.md), and catalog record
`signature/winternitz-base16`.
