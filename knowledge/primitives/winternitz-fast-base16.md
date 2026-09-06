# Fast base-16 Winternitz signatures

Implements a fixed-message-length HASH160 Winternitz path with a consuming
one-time key API, domain-separated chain starts, canonical host-side message
encoding, bitwise locking-size verifiers, lookup verifiers, a speed-oriented
exact-hash verifier, and terminal variants.

- **Question:** for 32-byte messages and 20-byte public endpoints fixed in the
  locking fragment, can tapscript verification execute exactly the required
  chain suffix while keeping script and stack costs close to the existing
  list-pick implementation?
- **Comparison objective:** minimize locking-script plus serialized witness
  bytes for a fixed recovered-message or terminal contract; also report their
  components, executed HASH160 calls, static non-push opcodes, combined stack
  peak, and any accepted-relation tradeoff.
- **Position:** the smallest recovery profile supplies canonical digit bits,
  shares complementary 8/4/2/1 conditional hashes, and reconstructs each
  authenticated nibble. A `[8, 8, 16]` mixed-radix checksum minimizes checksum
  chain and Horner bytes for the 0–960 `FastWots32` range. The terminal profile
  accumulates remaining distances directly and avoids digit reconstruction;
  its first authenticated bit initializes the accumulator without an extra
  entry stack item.
- **Representative result:** `FastWots32` bitwise recovery is 4,325 bytes, or
  4,206 bytes when the message is consumed, with 1,680-byte and 1,938-byte
  deterministic zero-message witnesses and measured peaks of 334 and 333
  items respectively. Clamped lookup recovery is 4,471 bytes, or 4,409 bytes
  when consumed. Strict numeric lookup recovery is 4,605 bytes;
  strict-chain lookup is 5,007 bytes and
  exact-hash recovery is 5,267 bytes. The exact-hash terminal fragment is
  5,205 bytes.
- **Combined on-chain size:** clamped lookup has the smallest measured sums
  for the deterministic zero message and signer-node witness upper bounds.
  Its recovery totals are 5,947 and 6,013 bytes; its terminal totals are
  5,885 and 5,951 bytes. The strict numeric counterparts total 6,081/6,147
  recovery or 6,019/6,085 terminal bytes. Bitwise totals are 6,005/6,267
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
- **Legacy comparison:** bitwise recovery is 583 bytes (11.9%) smaller than the
  4,908-byte legacy list-pick path and preserves the recovered-message
  contract. The terminal profile is 638 bytes (13.2%) smaller than the
  4,844-byte legacy terminal fragment. Both Fast bitwise profiles use
  canonical `MINIMALIF` bits. They omit explicit chain-item length checks;
  strict-chain lookup retains those checks.
- **Evidence:** `locally-reproduced` by host key/signature generation, two Script
  verifier families, a separately generated fixed Python HASH160 vector,
  malformed-input tests, checksum mutation with recomputed valid chains, and
  checked metric snapshots.
- **Execution:** `research-unlimited`. Metrics use the local tapscript executor
  through `execute_raw_script_with_inputs`, which disables the stack limit.
  Separate local tests execute the same compositions with the strict-stack
  helper below 1,000 items, but there is no pinned Bitcoin Core transaction or
  policy reproduction.
- **Security boundary:** this is classic unkeyed HASH160-chain Winternitz, not
  WOTS+. RFC 8391's WOTS+ uses addressed keyed chain functions. Keys remain
  strictly one-time, raw in-range ScriptNum canonicality is a caller obligation,
  and durable prevention of seed reuse is outside the consuming Rust type.
- **Size-profile boundary:** signer-produced chain nodes are 20 bytes, but the
  bitwise and numeric size verifiers accept arbitrary-length HASH160 preimages
  whenever at least one hash executes. A maximum digit compares directly with
  its 20-byte endpoint. This changes raw signature canonicality, not the
  authenticated digit relation.
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
