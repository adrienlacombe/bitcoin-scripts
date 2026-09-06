# Fast base-16 Winternitz signatures

Implements a fixed-message-length Winternitz path with HASH160 (default),
SHA-256, or SHA-256 chains with HASH160 endpoint commitments, optional
16-byte initial secrets, a consuming one-time key API,
domain-separated chain starts, canonical host-side message
encoding, bitwise locking-size verifiers, lookup verifiers, a speed-oriented
exact-hash verifier, and terminal variants.

- **Original HASH160 question:** for 32-byte messages and 20-byte public endpoints fixed in the
  locking fragment, can tapscript verification execute exactly the required
  chain suffix while keeping script and stack costs close to the existing
  list-pick implementation?
- **Comparison objective:** minimize policy-produced locking-script bytes for
  a fixed recovered-message or terminal contract, while reporting serialized
  witness bytes and their sum to expose onchain tradeoffs. Also report
  components, executed HASH160 calls, static non-push opcodes, combined stack
  peak, and any accepted-relation tradeoff.
- **Original HASH160 position:** the smallest recovery profile supplies canonical digit bits,
  shares complementary 8/4/2/1 conditional hashes, and reconstructs each
  authenticated nibble. A `[8, 8, 16]` mixed-radix checksum covers the 0–960
  `FastWots32` range. The terminal profile
  accumulates remaining distances directly and avoids digit reconstruction;
  its first authenticated bit initializes the accumulator without an extra
  entry stack item.
- **Representative FullWidth result:** `FastWots32` bitwise recovery is 4,325 bytes, or
  4,206 bytes when the message is consumed, with 1,680-byte and 1,938-byte
  deterministic zero-message witnesses and measured peaks of 334 and 333
  items respectively. Clamped lookup recovery is 4,465 bytes, or 4,403 bytes
  when consumed. Strict numeric lookup recovery is 4,599 bytes;
  strict-chain lookup is 4,934 bytes and
  exact-hash recovery is 5,267 bytes. The exact-hash terminal fragment is
  5,205 bytes.
- **FullWidth HASH160 combined on-chain size:** clamped lookup has the smallest measured sums
  for the deterministic zero message and signer-node witness upper bounds.
  Its recovery totals are 5,941 and 6,007 bytes; its terminal totals are
  5,879 and 5,945 bytes. The strict numeric counterparts total 6,075/6,141
  recovery or 6,013/6,079 terminal bytes. Bitwise totals are 6,005/6,267
  recovery or 6,144/6,148 terminal bytes. These are fragment-plus-data
  comparisons; complete transaction framing and a terminal predicate are
  excluded on both sides. The smallest locking script is not necessarily
  the smallest on-chain encoding.
- **Clamped relation:** `checksig_verify_clamped` and its terminal variant
  authenticate `min(raw_digit, chain_max)`, including the checksum. This
  explicitly adopts the legacy upper-clamping relation while preserving the
  signed message and all existing signer-produced witnesses. Negative and
  oversized numbers still fail, but above-range raw encodings can represent
  a maximum digit. The strict profiles remain available. Removing the strict
  upper rejection saves 134 script bytes with no extra witness items.
- **Compatible verifier improvements:** the exact ladder carries the residual
  digit above the chain node and hashes when each bit is unset, avoiding an
  explicit complement. Staging checksum digits together enables one Horner
  reduction. The terminal verifier collects verified digits before reducing
  them, saving repeated accumulator transfers. These changes reduce the exact
  recovery and terminal fragments by 75 and 203 bytes respectively without
  changing key derivation, signatures, range checks, or output contracts.
  Numeric lookup verifiers now build complete tables for checksum digits of
  at most three bits and retain half tables for four-bit digits. This removes
  the narrow-table selector branch without changing the witness. Strict
  lookup also relies on `OP_PICK` to reject negative indices, while retaining
  its upper bound so an index cannot reach preceding witness items. These
  changes save six HASH160 clamped/strict numeric bytes and 73 strict lookup
  bytes; SHA-256 saves two and 69 bytes respectively. Executed HASH160 calls
  on the balanced lookup vector rise from 729 to 733: the objective is bytes.
  The numeric size/clamped combined peak rises from 141 to 143 items because
  the narrow checksum table is larger; the strict lookup peak remains 143.
- **Legacy comparison:** bitwise recovery is 583 bytes (11.9%) smaller than the
  4,908-byte legacy list-pick path and preserves the recovered-message
  contract. The terminal profile is 638 bytes (13.2%) smaller than the
  4,844-byte legacy terminal fragment. Both Fast bitwise profiles use
  canonical `MINIMALIF` bits. They omit explicit chain-item length checks;
  strict-chain lookup retains those checks.
- **Evidence:** `locally-reproduced` by host key/signature generation, retained Script
  verifier profiles, separately generated fixed Python hash vectors,
  malformed-input tests, checksum mutation with recomputed valid chains, and
  checked metric snapshots.
- **Execution:** `research-unlimited`. Metrics use the local tapscript executor
  through `execute_raw_script_with_inputs`, which disables the stack limit.
  Separate local tests execute the same compositions with the strict-stack
  helper below 1,000 items, but there is no pinned Bitcoin Core transaction or
  policy reproduction.
- **Security boundary:** this is classic unkeyed hash-chain Winternitz, not
  WOTS+. RFC 8391's WOTS+ uses addressed keyed chain functions. Keys remain
  strictly one-time, raw in-range ScriptNum canonicality is a caller obligation,
  and durable prevention of seed reuse is outside the consuming Rust type.
- **Size-profile boundary:** the default HASH160 signer emits 20-byte nodes;
  `Preimage16` emits 16 bytes at digit zero and 20 bytes thereafter. Bitwise
  and numeric size verifiers accept arbitrary-length preimages whenever at
  least one hash executes. A maximum digit compares directly with its native
  endpoint. This changes raw signature canonicality, not the authenticated
  digit relation. SHA-256 uses the corresponding 32-byte native width.
  `Sha256Hash160` applies a final commitment hash even at the maximum digit,
  so its size profiles also admit arbitrary raw widths at that digit. Strict
  exact and strict lookup keep the selected start/intermediate width checks.
- **Compatibility:** `[8,8,16]` checksum endpoints replace the earlier Fast
  draft's three full base-16 checksum chains. Persisted public keys and
  signatures from that draft require regeneration and are not wire-compatible.
- **Stack contract:** numeric profiles consume 134 witness items. Bitwise
  profiles consume 333 items and peak at 334 for recovery or 333 for
  terminal verification, below the 1,000-item local strict ceiling. Recovery
  leaves 64 message nibbles in high/low byte order; terminal
  verification consumes them and requires a caller-supplied final predicate.
  Every profile requires zero auxiliary hint items. All witness/data items
  coexist at entry, so unrelated protocol state must also fit within the
  combined 1,000-item limit.

See the [implementation README](../../src/signatures/winternitz/README.md),
[legacy Winternitz page](winternitz-base16.md),
[signature comparison](../comparisons/signatures.md), RFC 8391 source
`rfc-8391`, BIP 342 source `bip-342`, and catalog record
`signature/winternitz-fast-base16`.

## Hash selection and measured tradeoffs

`FastWinternitz<N, Hash160>` defaults to 20-byte nodes and endpoints;
`FastWinternitz<N, Sha256>` defaults to 32-byte nodes and endpoints.
`FastWinternitz<N, Sha256Hash160>` uses 32-byte SHA-256 nodes and commits to
each completed endpoint with HASH160, producing a 20-byte public commitment.
The optional
third type parameter `Preimage16` shortens initial secrets only, as described
below. All nine existing Fast profiles support all three choices; the old aliases and the
legacy implementation retain HASH160. The selected hash controls both
host derivation and Script steps, with separate key-derivation domains and
hash-typed keys. Changing hashes requires new public commitments and witnesses.

For the same 32-byte zero message, seed `[0x42;32]`, explicit `FullWidth`
starts, final compilation policy, and fragment-only boundary:

| Profile | HASH160 script / witness / sum | SHA-256 script / witness / sum | Combined peak |
| --- | ---: | ---: | ---: |
| Clamped recovery | 4,465 / 1,476 / 5,941 | 5,009 / 2,280 / 7,289 | 143 |
| Clamped terminal | 4,403 / 1,476 / 5,879 | 4,947 / 2,280 / 7,227 | 143 |
| Bitwise recovery | 4,325 / 1,680 / 6,005 | 4,668 / 2,484 / 7,152 | 334 |
| Bitwise terminal | 4,206 / 1,938 / 6,144 | 4,549 / 2,742 / 7,291 | 333 |

SHA-256 grows 67 endpoint pushes and 67 witness nodes by 12 bytes each, but
compiler pair fusion removes 461 bytes from exact/bitwise scripts and 260
from lookup scripts. Net script-plus-witness increases are 1,147 and 1,348
bytes respectively. Thus HASH160 is cheaper for matching profiles; SHA-256
changes the internal ranking: bitwise wins zero-message recovery, clamped
wins zero-message terminal. SHA-256 clamped/bitwise terminal signer-node bounds
are 7,293 and 7,295 bytes respectively. Full tables and metric markers are in the implementation
README. This is not transaction weight and does not fix arbitrary hostile
witness lengths.

Both choices need zero auxiliary hints, with 134 numeric or 333 bitwise data
items present together at entry and included in the peaks. Measurements are
`locally-reproduced`, `research-unlimited` because the metric helper disables
the stack limit in tapscript. Separate strict-stack tests cover all profiles
and SHA-256 message lengths 1, 4, 16, 32, 64, and 80. Hash derivation is also
compared with independent Python stdlib vectors; this does not establish
Bitcoin Core consensus or policy validation.

HASH160's idealized preimage/collision bounds are 160/80 bits; SHA-256's are
256/128 bits. `Sha256Hash160` retains the 160-bit commitment width and roughly
80-bit generic collision bound, despite its 32-byte intermediate nodes.
These are hash-level bounds, not a security proof for custom
unkeyed Winternitz; multi-target and chain losses remain open under OP-009.
The implementation does not claim RFC 8391 WOTS+ security for any hash choice.

## Smaller scripts with separate endpoint commitments

`Sha256Hash160` separates the width of a chain node from the public commitment.
The host computes `HASH160(SHA256^max(start))`, and every verifier first
completes the selected SHA-256 chain and then applies the same HASH160
commitment. A fresh derivation domain prevents reinterpretation of existing
SHA-256 keys. Native SHA-256 pairs compile to one `OP_HASH256`; the final
20-byte commitment preserves the original HASH160 endpoint push cost.

The bitwise terminal fragment is 3,812 policy-produced bytes, 394 bytes
smaller than the corresponding 4,206-byte HASH160 fragment. For seed
`[0x42;32]` and message `[0;32]`, its FullWidth witness is 2,742 bytes and the
sum is 6,554 bytes. With `Preimage16`, the witness is 1,686 bytes and the sum
is 5,498. Both modes use 333 coexisting data items, zero auxiliary hints, a
333-item combined peak, and 2,192 static non-push opcodes. The smaller script
therefore has a witness tradeoff: intermediate openings grow to 32 bytes.

The additional `checksig_verify_strided_and_clear` profile uses
`to_strided_witness()`, whose chunks are `[digit / 2, node, 1 - (digit % 2)]`.
A canonical low-bit branch performs an optional first hash. The quotient
selects from a table containing every second subsequent chain node, allowing
SHA-256 pairs to compile to `OP_HASH256`. The verifier authenticates
`2 * min(raw_quotient, chain_max / 2) + 1 - bit` in both its chain and checksum.
Negative and oversized quotients fail; an above-range quotient aliases either
of the two largest digits depending on the canonical bit. This is an explicit
new witness relation. Existing keys and signatures can use its serializer;
existing numeric and bitwise witness encodings remain unchanged.

For `Sha256Hash160`, this terminal fragment measures 3,961 bytes, with a
2,413-byte FullWidth zero-message witness or a 1,357-byte Preimage16 witness.
The respective sums are 6,374 and 5,318 bytes. It uses 201 data items at entry,
zero auxiliary hints, a 209-item combined peak, and 2,480 static non-push
opcodes. For comparison, the hybrid clamped terminal uses 4,210 script bytes,
2,280/1,224 FullWidth/Preimage16 witness bytes, and totals 6,490/5,434 bytes.
It consumes 134 data items, zero auxiliary hints, peaks at 143, and has 2,668
static non-push opcodes. Within these measured
terminal configurations, bitwise minimizes locking bytes while strided plus
Preimage16 minimizes the zero-message script-plus-witness sum. This is not an
optimum over all messages or signature constructions.

Both terminal fragments leave no result and require the caller's final
predicate. All data items coexist at entry, and their combined peaks include
the checksum accumulator and lookup table; unrelated protocol state must fit
within the same 1,000-item bound. These measurements are `locally-reproduced`
and `research-unlimited`: the tapscript metric helper disables the stack
limit. Separate strict-stack tests do not establish Bitcoin Core consensus or
policy validation. Complete-leaf framing and transaction overhead remain
excluded on both sides.

The hybrid retains HASH160's 160-bit commitment output and approximately
80-bit generic collision bound. Its 32-byte internal nodes do not establish
SHA-256's 128-bit collision bound for the commitment. A 16-byte initial secret
still caps generic single-target secret search at 128 bits before chain and
multi-target losses. Those distinct properties and the one-time-key obligation
remain part of the protocol security analysis.


## Default 16-byte initial secrets

`FastWinternitz<N, H, Preimage16>` selects a 16-byte chain start while retaining
native `H` outputs: 20 bytes for HASH160 and 32 for either SHA-256 choice. A signature reveals
the short start exactly when its authenticated digit is zero. Other digits
reveal full-width hash outputs; public commitments retain the selected
commitment width (20 bytes for HASH160 or `Sha256Hash160`, 32 for SHA-256).
This does not truncate a hash after each step or create 16-byte commitments.

The default third parameter is now `Preimage16`, including every `FastWots*`
alias. Restore old native-width keys with explicit `FullWidth` on the verifier,
signing key, public key, and signature types; do not reinterpret persisted
keys using the changed default. `Preimage16` uses a separate derivation namespace:
`H("bitcoin-lab/winternitz-preimage16/v1" || H::DOMAIN || seed || BE64(N))`.
Chain-index derivation retains its existing order; only its initial output is
truncated to the first 16 bytes. The mode is part of the key/signature/public-key
types. Persist it alongside the hash choice; switching modes requires new
commitments and signatures.

The numeric size, clamped, and bitwise profiles already allow a short input
when a hash executes, so the mode adds no validation opcodes to those scripts.
Strict exact and strict lookup profiles instead check 16 bytes for digit zero
and the native width otherwise. The width helper grows from 4 to 11 compiled
bytes per chain, adding 469 measured bytes to a 67-chain strict fragment. For the zero-message
fixture, strict exact terminal total grows by 205 bytes with HASH160 but
shrinks by 587 bytes with SHA-256. Strict raw-width validation remains an explicit cost choice.

Witness savings are `(H::VALUE_BYTES - 16) * zero_digit_count`, including
checksum digits. The zero-message Wots32 fixture has 66 zero digits and one
nonzero checksum digit, so its measured serialized numeric witness is
1,212 bytes with HASH160 or 1,224 with SHA-256: 264 or 1,056 bytes smaller than
`FullWidth`. The corresponding measured clamped terminal totals are
5,615 and 6,171 bytes, from 5,879 and 7,227. These are fragment-plus-data sums,
with the same consumer and transaction framing excluded.
There is no constant saving for every message: only zero-valued digits reveal
16-byte items, and the existing full-width witness upper bounds remain safe
without claiming tightness for this mode.

For the same seed `[0x42;32]` and zero-message fixture, policy-produced
measurements are:

| Preimage16 profile | HASH160 script / witness / sum | SHA-256 script / witness / sum | Combined peak | Static non-push opcodes HASH160 / SHA-256 |
| --- | ---: | ---: | ---: | ---: |
| Clamped terminal | 4,403 / 1,212 / 5,615 | 4,947 / 1,224 / 6,171 | 143 | 2,861 / 2,601 |
| Bitwise recovery | 4,325 / 1,416 / 5,741 | 4,668 / 1,428 / 6,096 | 334 | 2,716 / 2,255 |
| Strict exact terminal | 5,674 / 1,212 / 6,886 | 6,017 / 1,224 / 7,241 | 137 | 3,665 / 3,204 |

These results are `locally-reproduced` and `research-unlimited`: the metric
helper runs tapscript with the stack limit disabled. They are not Bitcoin
Core consensus or policy validation. The full-width numeric witness upper
bounds, 1,542/2,346 bytes, and bitwise bounds, 1,942/2,746 bytes for
HASH160/SHA-256, remain safe bounds for this mode.

Shortening items adds no witness or auxiliary hint items. Numeric witnesses
still contain 134 data items and bitwise witnesses 333, all coexisting at
entry; every profile requires zero auxiliary hints. Existing size-profile
stack schedules are unchanged; the measured strict exact terminal peak of
137 includes the new conditional width check. Width savings alone do not increase the number of
items that fit under the combined 1,000-item limit.

A 16-byte start limits generic single-target classical secret search to at
most 128 bits. This reduces the start-search margin relative to full-width
starts; it does not establish a 128-bit forgery bound for the whole scheme.
Native hash collision bounds remain about 80 bits for HASH160 and 128 bits
for SHA-256. Collision resistance and recovery of a fixed secret are distinct
properties; see the [NIST hash-property definitions](https://csrc.nist.gov/Projects/hash-functions).
Concrete chain and multi-target losses for both start modes remain under
[OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).
