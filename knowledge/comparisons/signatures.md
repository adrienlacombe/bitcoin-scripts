# Signature verification and one-time authentication

## Point locks

| Construction | Script family | Script bytes | Revelation data | Setup / security boundary |
| --- | --- | ---: | ---: | --- |
| Schnorr adaptor signature | Tapscript | 34 for the ordinary x-only-key/checksig leaf | 66 for a default 64-byte signature | Interactive adaptor transcript; discrete-log/adaptor security |
| ECDSA `G/2` small-R | Legacy, P2SH, or P2WSH | 40 | 62 representative and maximum | Non-interactive; conservatively about 80-bit security, not locally established |
| Three-check ECDSA | Bare legacy or P2SH | 79 | 60-byte representative signature; 61-byte bare scriptSig | `T` alone; DLP hiding and related-scriptCode reduced-sighash collision resistance |
| Committed ECDSA | Legacy or P2SH only | 71 | 73 representative, at most 74 for low-S | Off-chain ZK proof of the SHA-256/DER-r relation; SHA-256 binding |

All rows are complete success predicates but exclude refund branches and
wrapper/control-block costs. The first row is only the ordinary on-chain
BIP340 check; adaptor creation and validation are off chain. The small-R row
uses the 21-byte x-coordinate of `G/2`. The committed row hashes the exact
`DER(r,s) || 0x03` item and relies on the pre-SegWit SIGHASH_SINGLE bug; it is
not a P2WSH construction. The three-check row is a legacy scriptSig boundary,
not witness serialization; its size guard eliminates the `r+n` coordinate
case rather than enforcing a small nonce. See the
[point-lock page](../primitives/point-locks.md) for extraction equations and
evidence qualifications.

## Secp256k1 Schnorr

| Construction | Public-input boundary | Script bytes | Witness bytes/items | Stack peak | Execution |
| --- | --- | ---: | ---: | ---: | --- |
| Native `OP_CHECKSIG` | Spend-time BIP340 signature and transaction digest | 34-byte x-only-key/checksig template, excluding spend context | signature-dependent | signature-dependent | consensus opcode; not measured here |
| Explicit affine CSFS | Public key fixed; 32-byte message and signature selected in witness | 8,292,228 | 81,740 / 32,556 | 33,589 | `research-unlimited`; known consensus-incompatible resource use |
| Explicit CSFS + conceptual `2^32` low-`s` taptree | As above, with one 32-bit signature chunk fixed by the selected leaf | 7,850,893 representative leaf | 77,869 arithmetic/input witness; depth-32 control block adds 1,026 versus depth zero | not remeasured; still far above 1,000 | `research-unlimited`; full tree not constructed |
| Native-field instance proof | Key, 32-byte message, and signature fixed before leaf generation | 58,596 | 1,039 / 346 | 882 | strict local tapscript; unclassified deployment |

These are not substitutes on the same boundary. The explicit CSFS row really
does place `r`, `s`, and the message in the witness, computes the tagged hash,
validates the supplied even nonce, and checks `sG-eP=R`; its size, stack, and
weight make it a research circuit rather than a deployable opcode replacement.
The native-field instance construction is useful only when a protocol needs an
explicit, inspectable field certificate for an already-fixed BIP340 instance.
Its GLV/wNAF/Jacobian engine runs in the trusted deterministic generator;
Script certifies only the final affine equation. Ordinary transaction-context
signatures should use `OP_CHECKSIG`.

The gigantic-taptree row moves four of the generator scalar's fixed-position
windows into leaf selection. The locally executed representative saves 441,335
script bytes and 3,871 arithmetic-witness bytes; after the 1,026-byte serialized
control-path penalty, the revealed-path saving is 444,180 bytes. The conceptual
tree requires `2^32` distinct leaves and roughly 33.7 PB of naïve leaf material,
so this is a lookup thought experiment, not a deployment path.

Within the explicit field certificate, the retained 2M/1S schedule has a
57,241-byte raw-certified core. It is 5,978 bytes smaller than a three-general-
product shared batch and 8,075 bytes smaller than three isolated general
multipliers. The specialized square also lowers peak stack use from 993 to 882.

## Custom Ed25519-style BLAKE3 slope verifier

These rows share one fixed public key and one fixed 32-byte benchmark message,
use digest bytes 0 through 15 of a custom BLAKE3 transcript as the challenge,
and end in a clean truth predicate. They are **not RFC 8032 Ed25519** and do
not authorize a Bitcoin transaction. The disclosed fixture secret
`a=987654321` makes each exact benchmark leaf forgeable.

| Configuration | Policy-produced Script | Exact argument witness | Entry data / auxiliary hints | Combined stack peak |
| --- | ---: | ---: | --- | ---: |
| Historical H16/G29 quotient carriers | 3,828,057-byte policy-compliant projection | 3,958 bytes | 704 data + 88 hints = 792 coexisting items; 2 hints per each of 44 transitions | 999 strict peak-equivalent schedule |
| Historical H16/G29 q-free | 3,896,335-byte policy-compliant projection | 3,561 bytes | 712 coexisting data items; 0 hints per transition and total | 912 analytical |
| **Current H16/G32 hybrid-u5 q-free** | **2,834,653 bytes** | **3,863 bytes** | **803 coexisting data items; 0 hints per each of 47 transitions and total** | **995 analytical** |

The current G32 leaf uses 31 response transitions and 16 challenge
transitions, a canonical 51-digit radix-32 `Rtilde` hash boundary,
symmetry-specialized squaring, and two phase-local Script-authored power pools.
Those pools are constants created by the locking Script, not witness hints, and
are included in the 995-item main-plus-alt-stack account. Its disjoint
component sizes sum exactly to 2,834,653 bytes: response 1,821,324; challenge
945,029; BLAKE3 67,137; recoder 389; and scalar validator 774. The whole
leaf exceeds 32 KiB and therefore uses `CompileOptions::NONE`; the reported
whole size is unoptimized by upstream fixpoint passes.

The current serialization contains 1,663,690 static non-push opcodes and is
165,330 bytes (5.511%) smaller than the `f7bb0c2` G32 baseline. Partial-word
decoding, fused sparse passes, Horner quotient reduction, the larger first
power pool, and endpoint table selection account for that reduction.

The two G29 totals are additive projections after applying the current hash
compilation policy; their corrected whole Scripts were not regenerated. Their
superseded pre-policy whole serializations were 3,826,949 and 3,895,323 bytes.

At that size, the exact fixture produces a 2,838,555-byte complete witness, a
2,838,933-WU target, and a 2,839,701-WU minimum-block projection, leaving
1,160,299 WU below four million. This is generation and serialization evidence,
not deployment evidence: the complete multi-megabyte Script has not been
executed or checked by Bitcoin Core. The overall construction is `inspected`
and `unclassified`; its square, transition, routing, hash, and host-witness
components have focused local or differential validation. See the
[construction page](../primitives/ed25519-blake3-montgomery-slope.md) for the
exact boundary and security obligations.

## One-time authentication

The original Winternitz rows below use HASH160 with full-width 20-byte starts
and nodes. Optional `Preimage16` comparisons follow the hash comparison.

| Construction | Authenticated object | Script bytes | Witness bytes (zero / upper bound) | Stack peak | Verification work / missing protocol work |
| --- | --- | ---: | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | not recorded | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 809 | 280 | not recorded | Message-to-index derivation |
| Legacy Wots32 list-pick | 32-byte message | 4,908 | 1,477 / 1,542 | 143 | 15 hashes for digits below 8, seven otherwise; clamps above-range digits |
| Legacy Wots32 list-pick + clear | 32-byte message | 4,844 | 1,477 / 1,542 | 143 | Direct checksum reduction; consumes message; terminal predicate excluded |
| FastWots32 clamped lookup | 32-byte message | 4,471 | 1,476 / 1,542 | 141 | Legacy-style upper saturation; recovers authenticated clamped digits |
| FastWots32 clamped lookup + clear | 32-byte message | 4,409 | 1,476 / 1,542 | 141 | Same clamped relation; consumes message; terminal predicate excluded |
| FastWots32 bitwise | 32-byte message | 4,325 | 1,680 / 1,942 | 334 | Canonical bits; exact suffix hashes; relaxed chain-item length; recovers message |
| FastWots32 bitwise + clear | 32-byte message | 4,206 | 1,938 / 1,942 | 333 | Branch-fused checksum; consumes message; terminal predicate excluded |
| FastWots32 size lookup | 32-byte message | 4,605 | 1,476 / 1,542 | 141 | Strict numeric digits; relaxed raw chain-item length; recovers message |
| FastWots32 size lookup + clear | 32-byte message | 4,543 | 1,476 / 1,542 | 141 | Same chain relation; consumes message; terminal predicate excluded |
| FastWots32 exact | 32-byte message | 5,267 | 1,476 / 1,542 | 137 | Residual-digit exact suffix hashes; 498 on the balanced vector |
| FastWots32 strict lookup | 32-byte message | 5,007 | 1,476 / 1,542 | 143 | 729 hashes on the balanced vector; explicit range check |
| FastWots32 exact + clear | 32-byte message | 5,205 | 1,476 / 1,542 | 137 | Staged digits and Horner checksum; terminal predicate excluded |

Locking figures are `fragment-only`; witness figures are full serialized item
vectors. Recorded Winternitz stack peaks are from complete local compositions, but the metric
executor disables the consensus stack check and therefore remains
`research-unlimited`. Separate strict local tests stay below 1,000 items. The
balanced-vector message and all other boundaries are recorded in the
[implementation README](../../src/signatures/winternitz/README.md).

There is no universal winner. The Fast bitwise recovery fragment is 583 bytes
(11.9%) smaller than the legacy list-pick recovery fragment; its terminal form
is 638 bytes (13.2%) smaller than the legacy terminal fragment. Canonical
`MINIMALIF` bits drive complementary hash
blocks, a `[8,8,16]` checksum covers the 0–960 range, and recovery rebuilds the
same 64 nibbles. The gain costs 333 witness items and a larger serialized
witness. Like the numeric size profile, it omits an explicit 20-byte check on
each chain item: a maximum digit equality forces 20 bytes, while smaller digits
admit an arbitrary-length HASH160 preimage before the first hash. The
strict-encoding lookup profile retains explicit 20-byte checks at 5,007 bytes.

The exact ladder and staged checksum preserve existing Fast witnesses while
reducing recovery by 75 bytes and terminal verification by 203 bytes.
All listed Fast profiles require zero auxiliary hint items; the 134 numeric or
333 bitwise data items are present together at script entry.

Legacy terminal verification also avoids recovering digits that it will
immediately discard, reducing its locking fragment by 96 bytes. This preserves
the legacy clamped-digit relation and its 134-item witness layout with zero
auxiliary hints.

For on-chain byte cost, the locking fragment and serialized data witness must
be added. The zero-message and signer-node upper-bound sums are:

| FastWots32 profile | Script + zero-message witness | Script + maximum signer-node witness |
| --- | ---: | ---: |
| Clamped lookup recovery | 5,947 | 6,013 |
| Clamped lookup terminal | 5,885 | 5,951 |
| Numeric size recovery | 6,081 | 6,147 |
| Bitwise recovery | 6,005 | 6,267 |
| Numeric size terminal | 6,019 | 6,085 |
| Bitwise terminal | 6,144 | 6,148 |

Clamped lookup minimizes both stated total-cost boundaries. It accepts an
above-range raw digit as the chain maximum and authenticates that clamped
value in the checksum, matching the legacy behavior; strict upper rejection
remains a separate profile. The witness format and honest recovered message
are unchanged. Ordering can depend on the message: for `[0xff; 32]`, bitwise
terminal totals 5,892 bytes versus 5,948 clamped. These sums exclude the same
script/control-block framing, consumer, and transaction overhead; they are not
complete transaction weights.

The legacy and Fast rows are not wire-compatible: chain-start derivation,
message digit order, checksum digit order, and witness pair order differ. All
constructions are one-time. Comparing them as interchangeable signatures also
requires fixing key/public commitment cost, forgery target, durable reuse
policy, raw ScriptNum canonicality, whether the recovered value must remain on
the stack, and whether tapscript `MINIMALIF` is available.

### HASH160 versus SHA-256 Winternitz

Every Fast profile also supports `FastWinternitz<32, Sha256>`. SHA-256 uses
32-byte nodes and endpoints, while HASH160 uses 20. These rows use the
default `FullWidth` start mode. The following zero-message comparisons include fragment plus serialized data
witness, excluding the same terminal consumer and transaction framing:

| Profile | HASH160 sum | SHA-256 sum | SHA-256 signer-node bound |
| --- | ---: | ---: | ---: |
| Clamped recovery | 5,947 | 7,291 | 7,357 |
| Clamped terminal | 5,885 | 7,229 | 7,295 |
| Bitwise recovery | 6,005 | 7,152 | 7,414 |
| Bitwise terminal | 6,144 | 7,291 | 7,295 |

HASH160 is cheaper for matching profiles. SHA-256's larger hash width offers
higher idealized hash-level security bounds, but is not a WOTS+ security
claim. Adjacent SHA-256 steps compile into HASH256: exact/bitwise profiles
save 461 script bytes from pair fusion, lookup profiles 264. This makes
bitwise the lowest zero-message recovery cost within SHA-256; clamped is the
lowest zero-message terminal cost. Keys are hash-typed and domain-separated;
changing the hash changes both keys and witnesses.

The SHA-256 numeric and bitwise witnesses still have 134 and 333 coexisting
entry data items and zero auxiliary hints. Corresponding stack peaks are
unchanged (137–143 numeric, 334/333 bitwise). All metric rows remain
`research-unlimited` under the stack-limit-disabled tapscript helper, with
separate strict-stack tests and no Core/policy validation. See the
[full hash comparison](../../src/signatures/winternitz/README.md#sha-256-onchain-comparison)
for script, witness, static opcode counts, security assumptions and boundaries.


### Initial-secret width

`FastWinternitz<32, H, Preimage16>` shortens only digit-zero signature values
to 16 bytes. Every hash output and endpoint retains the selected native
width. It is a separately domain-separated mode; the default `FullWidth`
keys and witnesses remain compatible with the tables above.

For the same zero-message fixture, 66 of 67 digits are zero. The following
measurements use the same fragment plus serialized data-witness boundary and
excluded transaction framing:

| Clamped terminal mode | Script bytes | Witness bytes | Sum | Saving from FullWidth |
| --- | ---: | ---: | ---: | ---: |
| HASH160 + Preimage16 | 4,409 | 1,212 | 5,621 | 264 |
| SHA-256 + Preimage16 | 4,949 | 1,224 | 6,173 | 1,056 |

Numeric size, clamped, and bitwise profiles need no new width validation and
retain their existing stack schedules. Strict exact and lookup profiles pay
469 extra script bytes for digit-dependent width checks, so a
smaller witness need not lower their total cost. Savings for other messages
are four bytes per zero digit with HASH160 and 16 with SHA-256, counting the
checksum; the all-zero fixture is not a uniform-message average.

Numeric signatures retain 134 coexisting entry data items and bitwise 333,
with zero auxiliary hints in every profile. Narrower items do not reduce
these counts or relax the 1,000-item combined stack bound. Consult the
[Fast primitive page](../primitives/winternitz-fast-base16.md#optional-16-byte-initial-secrets)
for metric evidence when comparing profiles. The table is `locally-reproduced`
and `research-unlimited`: the tapscript metric helper disables the stack
limit. It does not establish Core consensus or policy validation.

The smaller secret restricts generic single-target classical search to at
most 128 bits, with concrete chain/multi-target losses still unresolved. It
does not change the native hash-output collision bounds (roughly 80 bits for
HASH160, 128 for SHA-256) or make the two security profiles interchangeable.
