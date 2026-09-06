# Winternitz one-time signatures

This module contains two base-16 HASH160 Winternitz implementations. The
compatibility API preserves the original list-pick, brute-force, and binary-
search verifiers. The new `FastWinternitz<N>` API is an independent fixed-size
implementation with separate locking-size, verification-latency, strict chain-
encoding, and terminal-cleanup profiles, plus low-allocation host key generation
and an explicit one-time-key lifecycle.

This is a classic unkeyed HASH160-chain construction, not WOTS+. WOTS+ as
specified by RFC 8391 has addressed, keyed chain functions and different
security assumptions.

## Parameters

- Base: 16; each message byte becomes high then low nibble.
- Chain function: `HASH160`, with 20-byte chain values and 15 links.
- Fast signing seed: 32 bytes.
- Fast chain namespace: `HASH160(domain || seed || message_bytes_be64)`, where
  the domain is `bitcoin-lab/winternitz-hash160/v1`; chain `i` starts at
  `HASH160(namespace || i_be32)`. Computing the namespace once keeps every
  per-chain derivation within one SHA-256 block.
- Fast checksum: `sum(15 - message_digit)`, encoded in the minimum number of
  bits and split into mixed power-of-two digits of at most four bits. For
  `FastWots32`, the checksum radices are `[8, 8, 16]` and digits are
  least-significant first.
- Fast typed message sizes: 4, 16, 32, 64, and 80 bytes; arbitrary nonzero
  const-generic sizes are supported.
- Representative configuration: `FastWots32`, with 64 message digits, three
  checksum digits, and 67 chains.

## Optimization objectives

The primary objective is serialized locking-script plus signature-witness bytes
for a fixed 32-byte message and 20-byte HASH160 public endpoints. Both contribute
equally to tapscript witness weight. Script-only size, stack peak, and executed
hashes are reported separately. A parameter sweep over
bases 16, 32, 64, 128, and 256 confirmed that base 16 is smallest among the
implemented radices: reducing the endpoint count at a higher base costs more
hash/list opcodes than it saves.

The numeric size witness uses `[chain, digit]` pairs and orders the checksum pairs
so Script can use one short Horner pass. Its symmetric eight-value lookup
strictly rejects numeric digits outside `0..=15`. It intentionally omits a
separate chain-item length check. At digit 15 the direct endpoint equality
already forces 20 bytes; below 15 at least one HASH160 normalizes the selected
value before equality. The signer always emits 20-byte nodes, but the accepted
relation also includes arbitrary-length HASH160 preimages for digits below 15.
That is a deliberate four-byte-per-chain locking-size tradeoff, not a claim of
canonical raw witness encoding.

The clamped profiles use the same numeric size witness but normalize each
supplied digit with `min(digit, chain_max)` before authenticating it. That
normalized value drives the chain lookup, checksum, and recovered message.
This saves 134 locking bytes for 67 chains, with identical signer-produced
witnesses and stack use. Negative indices and oversized numbers still fail.
Upper-range raw values are accepted as aliases of the maximum digit, matching
the legacy list-pick behavior. Use the existing strict profiles when the raw
digit bound itself is part of the protocol contract.

The smallest locking-script profiles replace each numeric message digit with four canonical
witness bits. `OP_NOTIF` applies the complementary 8/4/2/1 hash blocks, so
tapscript `MINIMALIF` simultaneously authenticates the digit range. The
recovery profile reconstructs each nibble and fuses the checksum bits through
a mixed-radix Horner pass. The terminal profile instead accumulates remaining
hash distances inside the branches. This trades a larger witness and stack
peak for the minimum measured locking fragment.

The speed profile minimizes executed HASH160 calls while keeping one copy of
each public endpoint in the locking fragment. For digit `d`, it executes
exactly `15 - d` hashes by sharing 8/4/2/1 conditional blocks. The final
conditional is also the tapscript-consensus `MINIMALIF` range check: inputs
outside `0..=15` leave a residual other than canonical false or true and fail.

The minimal profile instead builds an eight-value lookup list. It is smaller,
but executes 15 hashes when `d < 8` and seven otherwise. It explicitly checks
the numeric digit range before `OP_PICK`. Both profiles validate that every
chain input is exactly 20 bytes.

Host key generation streams the domain and chain index into HASH160 and keeps
each chain value in a fixed-size array. It performs no secret-vector clone,
per-chain heap allocation, or collision-list sort. `FastSigningKey` is neither
`Copy` nor `Clone`, and `sign` consumes it.

## Script metrics

Locking sizes are `fragment-only`: chain checks, embedded public endpoints,
checksum verification, and the documented message/cleanup postcondition are
included. A terminal protocol predicate is excluded. Witness sizes are full
Bitcoin witness-vector serialization for a deterministic 32-byte zero message,
using Fast seed `[0x42; 32]` and legacy secret `[0x42; 20]`;
the maximum is the signer-produced maximum with 20-byte chain nodes and every
digit item one byte. It is not the size profile's maximum accepted adversarial
item length. The stack fixtures append a message consumer or `OP_TRUE` so
execution ends cleanly.

| `Wots32` configuration | Locking script | Unlocking witness (zero / upper bound) | Maximum stack items |
| --- | ---: | ---: | ---: |
| Legacy list-pick, recover message | <!-- metric:wots32_lock -->4908<!-- /metric:wots32_lock --> bytes | <!-- metric:wots32_witness -->1477<!-- /metric:wots32_witness --> / <!-- metric:wots32_witness_max -->1542<!-- /metric:wots32_witness_max --> bytes | <!-- metric:wots32_stack -->143<!-- /metric:wots32_stack --> |
| Legacy list-pick, clear message | <!-- metric:wots32_clear_lock -->4844<!-- /metric:wots32_clear_lock --> bytes | same as legacy recovery | <!-- metric:wots32_clear_stack -->143<!-- /metric:wots32_clear_stack --> |
| Fast bitwise, recover message | <!-- metric:fast_wots32_bitwise_lock -->4325<!-- /metric:fast_wots32_bitwise_lock --> bytes | <!-- metric:fast_wots32_bitwise_witness_zero -->1680<!-- /metric:fast_wots32_bitwise_witness_zero --> bytes | <!-- metric:fast_wots32_bitwise_stack -->334<!-- /metric:fast_wots32_bitwise_stack --> |
| Fast bitwise, clear message | <!-- metric:fast_wots32_bitwise_clear_lock -->4206<!-- /metric:fast_wots32_bitwise_clear_lock --> bytes | <!-- metric:fast_wots32_bitwise_terminal_witness_zero -->1938<!-- /metric:fast_wots32_bitwise_terminal_witness_zero --> bytes | <!-- metric:fast_wots32_bitwise_clear_stack -->333<!-- /metric:fast_wots32_bitwise_clear_stack --> |
| Fast clamped lookup, recover message | <!-- metric:fast_wots32_clamped_lock -->4471<!-- /metric:fast_wots32_clamped_lock --> bytes | 1,476 / 1,542 bytes | <!-- metric:fast_wots32_clamped_stack -->141<!-- /metric:fast_wots32_clamped_stack --> |
| Fast clamped lookup, clear message | <!-- metric:fast_wots32_clamped_clear_lock -->4409<!-- /metric:fast_wots32_clamped_clear_lock --> bytes | 1,476 / 1,542 bytes | <!-- metric:fast_wots32_clamped_clear_stack -->141<!-- /metric:fast_wots32_clamped_clear_stack --> |
| Fast size lookup, recover message | <!-- metric:fast_wots32_size_lock -->4605<!-- /metric:fast_wots32_size_lock --> bytes | same | <!-- metric:fast_wots32_size_stack -->141<!-- /metric:fast_wots32_size_stack --> |
| Fast size lookup, clear message | <!-- metric:fast_wots32_size_clear_lock -->4543<!-- /metric:fast_wots32_size_clear_lock --> bytes | same | <!-- metric:fast_wots32_size_clear_stack -->141<!-- /metric:fast_wots32_size_clear_stack --> |
| Fast exact-hash, recover message | <!-- metric:fast_wots32_exact_lock -->5267<!-- /metric:fast_wots32_exact_lock --> bytes | <!-- metric:fast_wots32_witness_zero -->1476<!-- /metric:fast_wots32_witness_zero --> bytes | <!-- metric:fast_wots32_exact_stack -->137<!-- /metric:fast_wots32_exact_stack --> |
| Fast eight-value lookup, recover message | <!-- metric:fast_wots32_minimal_lock -->5007<!-- /metric:fast_wots32_minimal_lock --> bytes | same | <!-- metric:fast_wots32_minimal_stack -->143<!-- /metric:fast_wots32_minimal_stack --> |
| Fast exact-hash, clear message | <!-- metric:fast_wots32_clear_lock -->5205<!-- /metric:fast_wots32_clear_lock --> bytes | same | <!-- metric:fast_wots32_clear_stack -->137<!-- /metric:fast_wots32_clear_stack --> |

For onchain cost, add the script and serialized signature witness: both are
witness-weight bytes in a tapscript spend. Script-item framing, the control
block, and the enclosing transaction are excluded equally here. The clamped
recovery profile totals <!-- metric:fast_wots32_clamped_total_zero -->5947<!-- /metric:fast_wots32_clamped_total_zero -->
bytes for the zero vector, with a signer-node upper bound of
<!-- metric:fast_wots32_clamped_total_max -->6013<!-- /metric:fast_wots32_clamped_total_max -->.
The clamped terminal profile totals
<!-- metric:fast_wots32_clamped_clear_total_zero -->5885<!-- /metric:fast_wots32_clamped_clear_total_zero -->
and <!-- metric:fast_wots32_clamped_clear_total_max -->5951<!-- /metric:fast_wots32_clamped_clear_total_max -->
bytes respectively. These minimize the measured zero-message totals and
signer-node upper bounds for their output contracts. The winner can depend on
the actual message: for an all-`ff` message the bitwise terminal profile totals
5,892 bytes, compared with 5,948 for clamped numeric. The bitwise profiles also
minimize the script alone.
Their static non-push counts are
<!-- metric:fast_wots32_clamped_static_opcodes -->2927<!-- /metric:fast_wots32_clamped_static_opcodes -->
and <!-- metric:fast_wots32_clamped_clear_static_opcodes -->2865<!-- /metric:fast_wots32_clamped_clear_static_opcodes -->.

The legacy terminal fragment contains
<!-- metric:wots32_clear_static_opcodes -->3166<!-- /metric:wots32_clear_static_opcodes -->
static non-push opcodes.

The Fast maximum serialized witness is
<!-- metric:fast_wots32_witness_max -->1542<!-- /metric:fast_wots32_witness_max -->
bytes. The exact, lookup, and clear fragments contain respectively
<!-- metric:fast_wots32_exact_static_opcodes -->3325<!-- /metric:fast_wots32_exact_static_opcodes -->,
<!-- metric:fast_wots32_minimal_static_opcodes -->3262<!-- /metric:fast_wots32_minimal_static_opcodes -->,
and <!-- metric:fast_wots32_clear_static_opcodes -->3263<!-- /metric:fast_wots32_clear_static_opcodes -->
static non-push opcodes. The size recovery and terminal fragments contain
<!-- metric:fast_wots32_size_static_opcodes -->3061<!-- /metric:fast_wots32_size_static_opcodes -->
and <!-- metric:fast_wots32_size_clear_static_opcodes -->2999<!-- /metric:fast_wots32_size_clear_static_opcodes -->
respectively.

The bitwise recovery and terminal fragments contain
<!-- metric:fast_wots32_bitwise_static_opcodes -->2716<!-- /metric:fast_wots32_bitwise_static_opcodes -->
and <!-- metric:fast_wots32_bitwise_clear_static_opcodes -->2586<!-- /metric:fast_wots32_bitwise_clear_static_opcodes -->
static non-push opcodes. Their signer-node witness upper bound is
<!-- metric:fast_wots32_bitwise_witness_max -->1942<!-- /metric:fast_wots32_bitwise_witness_max -->
bytes.

Relative to the previous numeric size profiles, clamped verification reduces
the same witness's combined cost by 134 bytes: recovery 6,081 → 5,947 and
terminal 6,019 → 5,885 for the zero vector. Relative to the previous best
zero-message recovery total (bitwise, 6,005), it saves 58 bytes. The signer-node
upper bounds improve from the previous numeric 6,147/6,085 to 6,013/5,951.

The compatible exact-hash ladder and staged Horner checksum reduce recovery
from 5,342 to 5,267 script bytes and terminal verification from 5,408 to 5,205.
Direct checksum reduction also reduces the legacy terminal from 4,940 to 4,844.
First-bit initialization saves two bytes and one stack item in the bitwise
terminal, 4,208 → 4,206. Existing public keys and witness layouts are unchanged.

For the deterministic balanced message
`00112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0`,
the exact profile executes
<!-- metric:fast_wots32_exact_hashes -->498<!-- /metric:fast_wots32_exact_hashes -->
HASH160 calls; the lookup profile executes
<!-- metric:fast_wots32_minimal_hashes -->729<!-- /metric:fast_wots32_minimal_hashes -->.
These are algorithmic counts derived from the authenticated digits, not the
executor's currently unimplemented opcode counter. For uniformly distributed
message digits, the exact message-chain expectation is 7.5 hashes per digit,
versus 11 for the lookup profile.

Metrics use pinned `bitcoin-scriptexec` commit
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1` in tapscript context. The metric
helper disables the stack limit, so these rows are `research-unlimited` even
though separate strict-stack unit tests execute the same profiles below the
1,000-item ceiling. They are not Bitcoin Core consensus or policy validation.

## Security

Every key is strictly one-time. Signing twice with the same seed and message
length can expose chain nodes that enable a new valid digit vector despite the
checksum. The consuming Rust API reduces accidental reuse but cannot protect
against restoring a seed, copying it before construction, crash rollback, or
concurrent signers; durable state is a protocol obligation.

HASH160 gives 160-bit outputs, at most generic 160-bit preimage resistance and
80-bit collision resistance before multi-target losses. The custom chain-start
domain separates message lengths and chain indices, but subsequent chain links
are unkeyed and unaddressed. This implementation has not received the analysis
of standardized WOTS+ parameter sets.

Numeric verifiers authenticate mixed-radix digits; the clamped profiles normalize
upper-range raw numbers first, while the strict profiles reject them. Bitwise witnesses
are canonical false/true under tapscript `MINIMALIF`. The signer emits canonical
ScriptNum encodings, but the exact verifier does not bind raw byte
serialization: a nonminimal encoding of an in-range number can represent the
same authenticated digit when minimal-number policy is not enforced. The new
exact ladder rejects nonminimal raw zero/one at its final `MINIMALIF`; larger
in-range digits can be normalized by subtraction. Raw encoding acceptance is
therefore not uniform. Protocols
that commit to raw witness encodings must add their own canonicality rule.

## Script compatibility and standardness

- Bare and P2SH: unsuitable; the fragments and opcode counts exceed the
  relevant legacy limits and ordinary output templates.
- P2WSH: unsuitable for the same opcode-count and standardness constraints.
- Tapscript: opcode-compatible, and the exact profile intentionally depends on
  tapscript's consensus `MINIMALIF` behavior. Local tests are not a deployment
  classification.

No complete transaction, Bitcoin Core regtest fixture, relay-policy check, or
mining-policy check is included. Treat all Fast profiles as tapscript research
fragments.

## Witness and hints

Speed/strict witness order is
`[digit_0, chain_0, digit_1, chain_1, ...]`. Script consumes pairs backwards,
so the 20-byte chain value is on top and can be size-checked before the numeric
digit is used. A zero digit is an empty item; positive digits use canonical
one-byte ScriptNum items. Size witness order is message `[chain_i, digit_i]` pairs
followed by checksum pairs in reverse chain-index order; callers must use
`to_size_optimized_witness` with a numeric size verifier. Bitwise recovery
chunks are `[bit_1, bit_2, ..., chain]`; terminal chunks interleave the chain
before `bit_1` so each selected conditional exposes the chain node. Callers
must use the matching bitwise witness serializer. The clamped profiles use
`to_size_optimized_witness` without any serialization changes. All profiles
require **0 auxiliary hint items**: the 134 numeric or 333 bitwise items are
signature data, all present at entry. The measured configurations contain one
signature. Any composition must include other live state in the same
1,000-item main-plus-alt-stack budget.

The mixed-radix checksum changes the last checksum endpoints from the earlier
all-base-16 Fast draft. Persisted Fast public keys or signatures from that draft
must not be mixed with this revision; regenerate the one-time key set.

The legacy standard witness uses `[chain_0, digit_0, ...]`; its list-pick
verifier clamps digits above 15 before authenticating the recovered value. That
does not produce a different recovered message, but it admits witness
malleability and should not be treated as strict raw-digit validation.

## Stack contract

- `FastWots32::checksig_verify`: consumes 134 witness items and leaves 64
  authenticated nibbles on the main stack in message high/low order.
- `FastWots32::checksig_verify_minimal`: same external contract with the lookup
  time/size tradeoff.
- `FastWots32::checksig_verify_size_optimized`: consumes the custom size witness
  and leaves the same 64 authenticated nibbles with strict numeric bounds.
- `FastWots32::checksig_verify_size_optimized_and_clear`: consumes the custom
  size witness and leaves an empty stack.
- `FastWots32::checksig_verify_clamped` and `checksig_verify_clamped_and_clear`:
  consume the same 134-item size witness, leave 64 nibbles or an empty stack,
  and peak at 141 combined items for the metric vector.
- `FastWots32::checksig_verify_bitwise_size_optimized`: consumes 333 witness
  items and leaves the same 64 authenticated nibbles with the smallest measured
  recovery fragment.
- `FastWots32::checksig_verify_bitwise_size_optimized_and_clear`: consumes its
  terminal-specific 333-item witness and leaves an empty stack with the
  smallest measured terminal fragment.
- `FastWots32::checksig_verify_and_clear`: consumes the signature, reduces
  staged authenticated digits through the checksum, and leaves an empty stack.
  The caller must append a terminal predicate.

All internal altstack state is balanced. Extra witness items remain below the
fixed input and are rejected by tapscript cleanstack only when the fragment is
composed into a complete leaf.

## Test coverage and limitations

Tests cover all verifier profiles, both terminal paths, every documented
stack postcondition, a separately generated Python HASH160 vector, wrong chain
values, wrong public endpoints, a valid-chain/invalid-checksum signature,
negative and above-range digits, oversized ScriptNums, noncanonical bit items,
exhaustive checksum values and carry boundaries, and the local strict stack
ceiling. Exhaustive digit/chain-pair tests cover exact and clamped selection;
forwarded-chain forgeries and hostile raw maximum aliases exercise the clamped
checksum boundary. A policy-disabled test preserves the legacy single-checksum
raw-encoding rule and surrounding stack state. The legacy vectors remain unchanged.

`cargo test --locked --test primitive_metrics winternitz_metrics_are_current`
checks the focused snapshots during ordinary test runs; intentional metric
updates use `UPDATE_PRIMITIVE_METRICS=1` with that same command.

`cargo bench --bench winternitz` runs the host-side release diagnostic for
legacy/Fast public-key generation and signing. It reports median, p10, and p90
nanoseconds over 31 samples of 200 operations. Timings are machine diagnostics,
not consensus metrics; record the CPU and toolchain whenever quoting them.

The implementation does not provide a many-time Merkle tree, crash-safe key
index, WOTS+ keyed masks, aggregate public key, policy-valid transaction, or
Bitcoin Core differential harness.

## Knowledge-base integration

See the [Winternitz knowledge page](../../../knowledge/primitives/winternitz-base16.md),
[one-time authentication comparison](../../../knowledge/comparisons/signatures.md),
[cost model](../../../knowledge/cost-model.md), and catalog record
`signature/winternitz-base16`.
