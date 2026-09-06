# Winternitz one-time signatures

For **20-byte messages**, the best tested combined-cost profile is
**constant-sum HASH160**: a **2,680-byte script** and **3,624-byte maximum
script + signature witness**. The hybrid has the smallest script at
**2,381 bytes**, with a larger **3,898-byte maximum combined cost**.
The reversible encoding preserves all 20 message bytes.

The first table compares terminal verifiers that consume the signature, with
**16-byte initial secrets** and seed `[0x42;32]`. Witness columns include full
signature-data serialization. Varied byte `i` is `(37*i) mod 256`.
Maximum means the attained signer-witness maximum.

| Terminal profile | Script bytes | Varied witness | Maximum signer witness | Script + maximum witness |
| --- | ---: | ---: | ---: | ---: |
| Constant-sum HASH160 | <!-- metric:w20_sum_hash160_script -->2680<!-- /metric:w20_sum_hash160_script --> | <!-- metric:w20_sum_hash160_witness_varied -->924<!-- /metric:w20_sum_hash160_witness_varied --> | <!-- metric:w20_sum_hash160_witness_max -->944<!-- /metric:w20_sum_hash160_witness_max --> | <!-- metric:w20_sum_hash160_total_max -->3624<!-- /metric:w20_sum_hash160_total_max --> |
| Constant-sum HASH160, bounded | <!-- metric:w20_sum_bounded_hash160_script -->2853<!-- /metric:w20_sum_bounded_hash160_script --> | <!-- metric:w20_sum_bounded_hash160_witness_varied -->924<!-- /metric:w20_sum_bounded_hash160_witness_varied --> | <!-- metric:w20_sum_bounded_hash160_witness_max -->944<!-- /metric:w20_sum_bounded_hash160_witness_max --> | <!-- metric:w20_sum_bounded_hash160_total_max -->3797<!-- /metric:w20_sum_bounded_hash160_total_max --> |
| Base-16 HASH160 clamped | <!-- metric:w20_base16_hash160_script -->2819<!-- /metric:w20_base16_hash160_script --> | <!-- metric:w20_base16_hash160_witness_varied -->960<!-- /metric:w20_base16_hash160_witness_varied --> | <!-- metric:w20_base16_hash160_witness_max -->990<!-- /metric:w20_base16_hash160_witness_max --> | <!-- metric:w20_base16_hash160_total_max -->3809<!-- /metric:w20_base16_hash160_total_max --> |
| Constant-sum hybrid | <!-- metric:w20_sum_hybrid_script -->2381<!-- /metric:w20_sum_hybrid_script --> | <!-- metric:w20_sum_hybrid_witness_varied -->1430<!-- /metric:w20_sum_hybrid_witness_varied --> | <!-- metric:w20_sum_hybrid_witness_max -->1517<!-- /metric:w20_sum_hybrid_witness_max --> | <!-- metric:w20_sum_hybrid_total_max -->3898<!-- /metric:w20_sum_hybrid_total_max --> |
| Constant-sum SHA-256 | <!-- metric:w20_sum_sha256_script -->2832<!-- /metric:w20_sum_sha256_script --> | <!-- metric:w20_sum_sha256_witness_varied -->1430<!-- /metric:w20_sum_sha256_witness_varied --> | <!-- metric:w20_sum_sha256_witness_max -->1517<!-- /metric:w20_sum_sha256_witness_max --> | <!-- metric:w20_sum_sha256_total_max -->4349<!-- /metric:w20_sum_sha256_total_max --> |

These policy-compiled fragments include commitments, chain verification,
checksum or fixed-sum checks, and cleanup. The terminal predicate, script-item
framing, control block, and transaction overhead are excluded equally.
Metrics are `locally-reproduced`, `research-unlimited`; the metric helper
executes tapscript with the stack limit disabled. No Core or policy validation
is established. All signature items coexist at entry and there are **0 hints**:
HASH160 constant-sum uses 82 items and peaks at 93 across both stacks; its
base-16 baseline uses 86/95; SHA-256 constant-sum profiles use 123/133.
See [encoding and verification tradeoffs](#lossless-20-byte-messages-with-a-constant-sum-encoding)
for the omitted individual upper bounds, bounded alternative, and hash choices.

## 32-byte terminal comparison

The following table compares our size-focused **terminal verifiers**: every row verifies
and consumes a **32-byte message**, using the default **16-byte initial secrets**.
Totals are **exact script + serialized signature-witness bytes** for each stated
message, not averages or witness-size bounds. “Mixed” is the byte sequence
`00 01 02 … 1f`; the other columns use 32 bytes of `00` or `ff`.
Rows are ordered by mixed-message total.

| Chain / commitment | Verifier | Script bytes | Mixed witness bytes | **Mixed total** | All-`00` total | All-`ff` total |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| HASH160 / 20-byte endpoint | Clamped | <!-- metric:overview_hash160_clamped_script -->4403<!-- /metric:overview_hash160_clamped_script --> | <!-- metric:overview_hash160_clamped_mixed_witness -->1442<!-- /metric:overview_hash160_clamped_mixed_witness --> | <!-- metric:overview_hash160_clamped_mixed_total -->5845<!-- /metric:overview_hash160_clamped_mixed_total --> | <!-- metric:overview_hash160_clamped_zero_total -->5615<!-- /metric:overview_hash160_clamped_zero_total --> | <!-- metric:overview_hash160_clamped_ff_total -->5930<!-- /metric:overview_hash160_clamped_ff_total --> |
| HASH160 / 20-byte endpoint | Strided | <!-- metric:overview_hash160_strided_script -->4355<!-- /metric:overview_hash160_strided_script --> | <!-- metric:overview_hash160_strided_mixed_witness -->1525<!-- /metric:overview_hash160_strided_mixed_witness --> | <!-- metric:overview_hash160_strided_mixed_total -->5880<!-- /metric:overview_hash160_strided_mixed_total --> | <!-- metric:overview_hash160_strided_zero_total -->5700<!-- /metric:overview_hash160_strided_zero_total --> | <!-- metric:overview_hash160_strided_ff_total -->5952<!-- /metric:overview_hash160_strided_ff_total --> |
| HASH160 / 20-byte endpoint | Bitwise | <!-- metric:overview_hash160_bitwise_script -->4206<!-- /metric:overview_hash160_bitwise_script --> | <!-- metric:overview_hash160_bitwise_mixed_witness -->1779<!-- /metric:overview_hash160_bitwise_mixed_witness --> | <!-- metric:overview_hash160_bitwise_mixed_total -->5985<!-- /metric:overview_hash160_bitwise_mixed_total --> | <!-- metric:overview_hash160_bitwise_zero_total -->5880<!-- /metric:overview_hash160_bitwise_zero_total --> | <!-- metric:overview_hash160_bitwise_ff_total -->5880<!-- /metric:overview_hash160_bitwise_ff_total --> |
| SHA-256 / 20-byte HASH160 commitment | Strided | <!-- metric:overview_hybrid_strided_script -->3961<!-- /metric:overview_hybrid_strided_script --> | <!-- metric:overview_hybrid_strided_mixed_witness -->2089<!-- /metric:overview_hybrid_strided_mixed_witness --> | <!-- metric:overview_hybrid_strided_mixed_total -->6050<!-- /metric:overview_hybrid_strided_mixed_total --> | <!-- metric:overview_hybrid_strided_zero_total -->5318<!-- /metric:overview_hybrid_strided_zero_total --> | <!-- metric:overview_hybrid_strided_ff_total -->6326<!-- /metric:overview_hybrid_strided_ff_total --> |
| SHA-256 / 20-byte HASH160 commitment | Bitwise | <!-- metric:overview_hybrid_bitwise_script -->3812<!-- /metric:overview_hybrid_bitwise_script --> | <!-- metric:overview_hybrid_bitwise_mixed_witness -->2343<!-- /metric:overview_hybrid_bitwise_mixed_witness --> | <!-- metric:overview_hybrid_bitwise_mixed_total -->6155<!-- /metric:overview_hybrid_bitwise_mixed_total --> | <!-- metric:overview_hybrid_bitwise_zero_total -->5498<!-- /metric:overview_hybrid_bitwise_zero_total --> | <!-- metric:overview_hybrid_bitwise_ff_total -->6254<!-- /metric:overview_hybrid_bitwise_ff_total --> |
| SHA-256 / 20-byte HASH160 commitment | Clamped | <!-- metric:overview_hybrid_clamped_script -->4210<!-- /metric:overview_hybrid_clamped_script --> | <!-- metric:overview_hybrid_clamped_mixed_witness -->2006<!-- /metric:overview_hybrid_clamped_mixed_witness --> | <!-- metric:overview_hybrid_clamped_mixed_total -->6216<!-- /metric:overview_hybrid_clamped_mixed_total --> | <!-- metric:overview_hybrid_clamped_zero_total -->5434<!-- /metric:overview_hybrid_clamped_zero_total --> | <!-- metric:overview_hybrid_clamped_ff_total -->6505<!-- /metric:overview_hybrid_clamped_ff_total --> |
| SHA-256 / 32-byte endpoint | Strided | <!-- metric:overview_sha256_strided_script -->4698<!-- /metric:overview_sha256_strided_script --> | <!-- metric:overview_sha256_strided_mixed_witness -->2089<!-- /metric:overview_sha256_strided_mixed_witness --> | <!-- metric:overview_sha256_strided_mixed_total -->6787<!-- /metric:overview_sha256_strided_mixed_total --> | <!-- metric:overview_sha256_strided_zero_total -->6055<!-- /metric:overview_sha256_strided_zero_total --> | <!-- metric:overview_sha256_strided_ff_total -->7063<!-- /metric:overview_sha256_strided_ff_total --> |
| SHA-256 / 32-byte endpoint | Bitwise | <!-- metric:overview_sha256_bitwise_script -->4549<!-- /metric:overview_sha256_bitwise_script --> | <!-- metric:overview_sha256_bitwise_mixed_witness -->2343<!-- /metric:overview_sha256_bitwise_mixed_witness --> | <!-- metric:overview_sha256_bitwise_mixed_total -->6892<!-- /metric:overview_sha256_bitwise_mixed_total --> | <!-- metric:overview_sha256_bitwise_zero_total -->6235<!-- /metric:overview_sha256_bitwise_zero_total --> | <!-- metric:overview_sha256_bitwise_ff_total -->6991<!-- /metric:overview_sha256_bitwise_ff_total --> |
| SHA-256 / 32-byte endpoint | Clamped | <!-- metric:overview_sha256_clamped_script -->4947<!-- /metric:overview_sha256_clamped_script --> | <!-- metric:overview_sha256_clamped_mixed_witness -->2006<!-- /metric:overview_sha256_clamped_mixed_witness --> | <!-- metric:overview_sha256_clamped_mixed_total -->6953<!-- /metric:overview_sha256_clamped_mixed_total --> | <!-- metric:overview_sha256_clamped_zero_total -->6171<!-- /metric:overview_sha256_clamped_zero_total --> | <!-- metric:overview_sha256_clamped_ff_total -->7242<!-- /metric:overview_sha256_clamped_ff_total --> |

**Boundary:** policy-compiled locking fragments, with embedded commitments and
checksum/message cleanup, plus full serialized data-witness vectors. The common
terminal `OP_TRUE`, script-item framing, Taproot control block, and transaction
overhead are excluded. These sums are not complete-transaction weights or fees.
Seed: `[0x42; 32]`. All scripts are below 32 KiB and use `CompileOptions::ALL`.

All rows need **0 auxiliary hint items**. Clamped / strided / bitwise witnesses
contain **134 / 201 / 333 data items** together at entry, with measured combined
main-plus-alt-stack peaks **143 / 209 / 333**. Measurements are
`locally-reproduced`, `research-unlimited`: the tapscript metric helper disables
the stack check; separate strict-stack tests are not Bitcoin Core or policy
validation. The schemes also differ in digit-encoding acceptance and commitment
security; see the detailed comparisons below. Short-secret savings depend on
the message's zero digits, so no fixture establishes a universal winner.

This module contains a compatibility HASH160 API and an independent typed
`FastWinternitz<N, H = Hash160, P = Preimage16>` API. The typed implementation supports
HASH160, SHA-256, and SHA-256 chains with HASH160 commitments across every verification profile, with a consuming
one-time signing key. The hash and preimage-width choices are fixed when creating the key and
locking script; neither is selected by an untrusted witness.

This is classic unkeyed-chain Winternitz, not the addressed, keyed WOTS+
construction specified by RFC 8391. Changing the hash does not establish
WOTS+ security.

## Parameters

- Base: 16; each message byte becomes high then low nibble.
- Chain function: `Hash160` (default, 20-byte nodes/commitments), `Sha256`
  (32-byte nodes/commitments), or `Sha256Hash160` (32-byte nodes, 20-byte commitments);
  message chains have 15 links. SHA-2 means SHA-256 here, not SHA-512.
- Initial secret width: `Preimage16` (default, 16 bytes, revealed only by
  digit zero), or explicit `FullWidth` for native-width initial secrets.
- Fast signing seed: 32 bytes.
- Fast chain namespace: `H(domain || seed || message_bytes_be64)`, where
  the domains are `bitcoin-lab/winternitz-hash160/v1` and
  `bitcoin-lab/winternitz-sha256/v1`, with the hybrid domain described below; chain `i` starts at
  `H(namespace || i_be32)`. All profiles retain fixed-size chain arrays.
- Fast checksum: `sum(15 - message_digit)`, encoded in the minimum number of
  bits and split into mixed power-of-two digits of at most four bits. For
  `FastWots32`, the checksum radices are `[8, 8, 16]` and digits are
  least-significant first.
- Fast typed message sizes: 4, 16, 32, 64, and 80 bytes; arbitrary nonzero
  const-generic sizes are supported.
- Representative configuration: `FastWots32`, with 64 message digits, three
  checksum digits, and 67 chains.

## Optimization objectives

The current objective is reducing serialized locking-script bytes for a fixed
32-byte message, while measuring signature-witness bytes to expose total onchain
cost. The hybrid retains 20-byte HASH160 public commitments. Both contribute
equally to tapscript witness weight. Script-only size, stack peak, and executed
hashes are reported separately. A parameter sweep over
bases 16, 32, 64, 128, and 256 confirmed that base 16 is smallest in the
original HASH160 lookup matrix: reducing the endpoint count at a higher base costs more
hash/list opcodes than it saves.

The numeric size witness uses `[chain, digit]` pairs and orders the checksum pairs
so Script can use one short Horner pass. Its symmetric eight-value lookup
strictly rejects numeric digits outside `0..=15`. It intentionally omits a
separate chain-item length check. At digit 15 the direct endpoint equality
forces the selected hash width for the original Hash160/Sha256 profiles; below 15 at least one hash normalizes
the selected value before equality. FullWidth signer nodes are 20 or 32 bytes;
Preimage16 signer nodes are 16 bytes at digit zero and native width otherwise.
The accepted size-profile relation also includes arbitrary-length preimages
for digits below the chain maximum, and at every digit for Sha256Hash160
because its final commitment hash normalizes the input.
Omitting the width guard saves four bytes per chain with FullWidth or eleven
with Preimage16. It does not enforce canonical raw witness encoding.

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

The speed profile minimizes executed chain hash steps while keeping one copy of
each public endpoint in the locking fragment. For digit `d`, it executes
exactly `15 - d` hashes by sharing 8/4/2/1 conditional blocks. The final
conditional is also the tapscript-consensus `MINIMALIF` range check: inputs
outside `0..=15` leave a residual other than canonical false or true and fail.

The minimal profile instead builds an eight-value lookup list. It is smaller,
but executes 15 hashes when `d < 8` and seven otherwise. It checks the upper numeric bound before `OP_PICK`, whose negative-index
rejection enforces the lower bound. Narrow checksum chains use full tables. Both profiles validate that every
chain input has the expected width: the selected hash width for FullWidth;
16 bytes iff digit zero, otherwise the hash width, for Preimage16.

Host key generation streams the domain and chain index into the selected hash and keeps
each chain value in a fixed-size array. It performs no secret-vector clone,
per-chain heap allocation, or collision-list sort. `FastSigningKey` is neither
`Copy` nor `Clone`, and `sign` consumes it.

## Hash choice and preimage sizes

The default [Preimage16 mode](#default-16-byte-initial-preimages) shortens the initial
secret only. Intermediate outputs stay native width; the original hash profiles
also retain native-width endpoints. The hybrid hashes completed endpoints to 20 bytes; truncating
every host-side hash would disagree with native Script hashing.

```rust
use bitcoin_lab::signatures::winternitz::{FastWinternitz, Hash160, Sha256};

type Small = FastWinternitz<32, Hash160>; // Also FastWots32 / FastWinternitz<32>.
type Wide = FastWinternitz<32, Sha256>;
assert_eq!(Small::HASH_BYTES, 20);
assert_eq!(Wide::HASH_BYTES, 32);
let key = Wide::generate_signing_key();
let public_key = Wide::public_key(&key);
let signature = Wide::sign(key, &[0x42; 32]);
let verifier = Wide::checksig_verify_clamped_and_clear(&public_key);
let witness = signature.to_size_optimized_witness();
// Append the protocol terminal predicate before executing a complete leaf.
```

The hash and preimage-width parameters also appear on `FastSigningKey<N, H, P>`,
`FastPublicKey<N, H, P>`, and `FastSignature<N, H, P>`.
`FastChainValue<H>` is a native-width node; `FastCommitment<H>` is the
stored endpoint commitment, which is shorter for Sha256Hash160.
The `FastWots4/16/32/64/80` aliases use HASH160 with Preimage16.
**Migration:** defaults now derive different keys from the same seed and use
16-byte digit-zero openings. To restore previously created native-width keys,
use `FastWinternitz<N, H, FullWidth>` and matching `FastSigningKey`,
`FastPublicKey`, and `FastSignature` types with explicit `FullWidth`. The
FullWidth derivation and witness formats remain unchanged. Do not restore
old persisted keys using the new implicit default; persist the mode explicitly.
Persist the hash choice alongside keys and seeds: SHA-256 uses a separate
domain and its keys, endpoints, and signatures are not wire-compatible with
HASH160. Every choice still requires durable one-time-key management.
The legacy `Wots`/`CompactWots` API remains HASH160-only.

## Script metrics

The Fast rows in this section use explicit **FullWidth** for historical
comparison. The new default costs are in [Default 16-byte initial preimages](#default-16-byte-initial-preimages).

Locking sizes are `fragment-only`: chain checks, embedded public endpoints,
checksum verification, and the documented message/cleanup postcondition are
included. A terminal protocol predicate is excluded. Witness sizes are full
Bitcoin witness-vector serialization for a deterministic 32-byte zero message,
using Fast seed `[0x42; 32]` and legacy secret `[0x42; 20]`;
the maximum is the signer-produced maximum with 20-byte chain nodes and every
digit item one byte. It is not the size profile's maximum accepted adversarial
item length. The stack fixtures append a message consumer or `OP_TRUE` so
execution ends cleanly.

The following table uses **HASH160** throughout.

| 32-byte FullWidth configuration | Locking script | Unlocking witness (zero / upper bound) | Maximum stack items |
| --- | ---: | ---: | ---: |
| Legacy list-pick, recover message | <!-- metric:wots32_lock -->4908<!-- /metric:wots32_lock --> bytes | <!-- metric:wots32_witness -->1477<!-- /metric:wots32_witness --> / <!-- metric:wots32_witness_max -->1542<!-- /metric:wots32_witness_max --> bytes | <!-- metric:wots32_stack -->143<!-- /metric:wots32_stack --> |
| Legacy list-pick, clear message | <!-- metric:wots32_clear_lock -->4844<!-- /metric:wots32_clear_lock --> bytes | same as legacy recovery | <!-- metric:wots32_clear_stack -->143<!-- /metric:wots32_clear_stack --> |
| Fast bitwise, recover message | <!-- metric:fast_wots32_bitwise_lock -->4325<!-- /metric:fast_wots32_bitwise_lock --> bytes | <!-- metric:fast_wots32_bitwise_witness_zero -->1680<!-- /metric:fast_wots32_bitwise_witness_zero --> bytes | <!-- metric:fast_wots32_bitwise_stack -->334<!-- /metric:fast_wots32_bitwise_stack --> |
| Fast bitwise, clear message | <!-- metric:fast_wots32_bitwise_clear_lock -->4206<!-- /metric:fast_wots32_bitwise_clear_lock --> bytes | <!-- metric:fast_wots32_bitwise_terminal_witness_zero -->1938<!-- /metric:fast_wots32_bitwise_terminal_witness_zero --> bytes | <!-- metric:fast_wots32_bitwise_clear_stack -->333<!-- /metric:fast_wots32_bitwise_clear_stack --> |
| Fast clamped lookup, recover message | <!-- metric:fast_wots32_clamped_lock -->4465<!-- /metric:fast_wots32_clamped_lock --> bytes | 1,476 / 1,542 bytes | <!-- metric:fast_wots32_clamped_stack -->143<!-- /metric:fast_wots32_clamped_stack --> |
| Fast clamped lookup, clear message | <!-- metric:fast_wots32_clamped_clear_lock -->4403<!-- /metric:fast_wots32_clamped_clear_lock --> bytes | 1,476 / 1,542 bytes | <!-- metric:fast_wots32_clamped_clear_stack -->143<!-- /metric:fast_wots32_clamped_clear_stack --> |
| Fast size lookup, recover message | <!-- metric:fast_wots32_size_lock -->4599<!-- /metric:fast_wots32_size_lock --> bytes | same | <!-- metric:fast_wots32_size_stack -->143<!-- /metric:fast_wots32_size_stack --> |
| Fast size lookup, clear message | <!-- metric:fast_wots32_size_clear_lock -->4537<!-- /metric:fast_wots32_size_clear_lock --> bytes | same | <!-- metric:fast_wots32_size_clear_stack -->143<!-- /metric:fast_wots32_size_clear_stack --> |
| Fast exact-hash, recover message | <!-- metric:fast_wots32_exact_lock -->5267<!-- /metric:fast_wots32_exact_lock --> bytes | <!-- metric:fast_wots32_witness_zero -->1476<!-- /metric:fast_wots32_witness_zero --> bytes | <!-- metric:fast_wots32_exact_stack -->137<!-- /metric:fast_wots32_exact_stack --> |
| Fast eight-value lookup, recover message | <!-- metric:fast_wots32_minimal_lock -->4934<!-- /metric:fast_wots32_minimal_lock --> bytes | same | <!-- metric:fast_wots32_minimal_stack -->143<!-- /metric:fast_wots32_minimal_stack --> |
| Fast exact-hash, clear message | <!-- metric:fast_wots32_clear_lock -->5205<!-- /metric:fast_wots32_clear_lock --> bytes | same | <!-- metric:fast_wots32_clear_stack -->137<!-- /metric:fast_wots32_clear_stack --> |

For onchain cost, add the script and serialized signature witness: both are
witness-weight bytes in a tapscript spend. Script-item framing, the control
block, and the enclosing transaction are excluded equally here.

| Clamped profile | Script + zero-message witness (bytes) | Script + signer-node witness upper bound (bytes) |
| --- | ---: | ---: |
| Recovery | <!-- metric:fast_wots32_clamped_total_zero -->5941<!-- /metric:fast_wots32_clamped_total_zero --> | <!-- metric:fast_wots32_clamped_total_max -->6007<!-- /metric:fast_wots32_clamped_total_max --> |
| Terminal | <!-- metric:fast_wots32_clamped_clear_total_zero -->5879<!-- /metric:fast_wots32_clamped_clear_total_zero --> | <!-- metric:fast_wots32_clamped_clear_total_max -->5945<!-- /metric:fast_wots32_clamped_clear_total_max --> |

These minimize the measured zero-message totals and signer-node upper bounds
within the original HASH160 profiles above. The winner can depend on the
actual message: for an all-`ff` message the bitwise terminal profile totals
5,892 bytes, compared with 5,942 for clamped numeric. The bitwise profiles
also minimize the script alone.

| Profile | Static non-push opcodes |
| --- | ---: |
| Legacy list-pick, terminal | <!-- metric:wots32_clear_static_opcodes -->3166<!-- /metric:wots32_clear_static_opcodes --> |
| Fast clamped lookup, recovery | <!-- metric:fast_wots32_clamped_static_opcodes -->2923<!-- /metric:fast_wots32_clamped_static_opcodes --> |
| Fast clamped lookup, terminal | <!-- metric:fast_wots32_clamped_clear_static_opcodes -->2861<!-- /metric:fast_wots32_clamped_clear_static_opcodes --> |
| Fast exact-hash, recovery | <!-- metric:fast_wots32_exact_static_opcodes -->3325<!-- /metric:fast_wots32_exact_static_opcodes --> |
| Fast eight-value lookup, recovery | <!-- metric:fast_wots32_minimal_static_opcodes -->3258<!-- /metric:fast_wots32_minimal_static_opcodes --> |
| Fast exact-hash, terminal | <!-- metric:fast_wots32_clear_static_opcodes -->3263<!-- /metric:fast_wots32_clear_static_opcodes --> |
| Fast size lookup, recovery | <!-- metric:fast_wots32_size_static_opcodes -->3057<!-- /metric:fast_wots32_size_static_opcodes --> |
| Fast size lookup, terminal | <!-- metric:fast_wots32_size_clear_static_opcodes -->2995<!-- /metric:fast_wots32_size_clear_static_opcodes --> |
| Fast bitwise, recovery | <!-- metric:fast_wots32_bitwise_static_opcodes -->2716<!-- /metric:fast_wots32_bitwise_static_opcodes --> |
| Fast bitwise, terminal | <!-- metric:fast_wots32_bitwise_clear_static_opcodes -->2586<!-- /metric:fast_wots32_bitwise_clear_static_opcodes --> |

| Fast witness format | Serialized signer-node witness upper bound (bytes) |
| --- | ---: |
| Numeric | <!-- metric:fast_wots32_witness_max -->1542<!-- /metric:fast_wots32_witness_max --> |
| Bitwise | <!-- metric:fast_wots32_bitwise_witness_max -->1942<!-- /metric:fast_wots32_bitwise_witness_max --> |

Relative to the strict numeric size profiles, clamped verification reduces
the same witness's combined cost by 134 bytes: recovery 6,075 → 5,941 and
terminal 6,013 → 5,879 for the zero vector. Relative to the bitwise
zero-message recovery total (6,005), it saves 64 bytes. The signer-node
upper bounds improve from numeric 6,141/6,079 to 6,007/5,945.

The compatible exact-hash ladder and staged Horner checksum reduce recovery
from 5,342 to 5,267 script bytes and terminal verification from 5,408 to 5,205.
Direct checksum reduction also reduces the legacy terminal from 4,940 to 4,844.
First-bit initialization saves two bytes and one stack item in the bitwise
terminal, 4,208 → 4,206. Existing public keys and witness layouts are unchanged.

For the deterministic balanced message
`00112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0`:

| Profile | HASH160 calls |
| --- | ---: |
| Exact | <!-- metric:fast_wots32_exact_hashes -->498<!-- /metric:fast_wots32_exact_hashes --> |
| Lookup | <!-- metric:fast_wots32_minimal_hashes -->733<!-- /metric:fast_wots32_minimal_hashes --> |

These are algorithmic counts derived from the authenticated digits, not the
executor's currently unimplemented opcode counter. For uniformly distributed
message digits, the exact message-chain expectation is 7.5 hashes per digit,
versus 11 for the lookup profile.

Metrics use pinned `bitcoin-scriptexec` commit
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1` in tapscript context. The metric
helper disables the stack limit, so these rows are `research-unlimited` even
though separate strict-stack unit tests execute the same profiles below the
1,000-item ceiling. They are not Bitcoin Core consensus or policy validation.

## SHA-256 onchain comparison

Same deterministic seed, zero message, compilation policy, fragment boundary,
and stack wrappers as the HASH160 rows above. All sizes below are final
policy-produced sizes with `CompileOptions::ALL` (each script is below 32 KiB).
Witness upper bounds use 32-byte signer nodes with every digit/bit item one
byte; they do not bound the size profiles' accepted hostile preimages.

| SHA-256 profile | Script bytes | Witness bytes (zero / bound) | Stack peak | Static non-push opcodes | Script + witness (zero / bound) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Exact recovery | <!-- metric:sha256_wots32_exact_lock -->5610<!-- /metric:sha256_wots32_exact_lock --> | <!-- metric:sha256_wots32_exact_witness -->2280<!-- /metric:sha256_wots32_exact_witness --> / <!-- metric:sha256_wots32_exact_witness_max -->2346<!-- /metric:sha256_wots32_exact_witness_max --> | <!-- metric:sha256_wots32_exact_stack -->137<!-- /metric:sha256_wots32_exact_stack --> | <!-- metric:sha256_wots32_exact_static_opcodes -->2864<!-- /metric:sha256_wots32_exact_static_opcodes --> | <!-- metric:sha256_wots32_exact_total_zero -->7890<!-- /metric:sha256_wots32_exact_total_zero --> / <!-- metric:sha256_wots32_exact_total_max -->7956<!-- /metric:sha256_wots32_exact_total_max --> |
| Exact terminal | <!-- metric:sha256_wots32_clear_lock -->5548<!-- /metric:sha256_wots32_clear_lock --> | <!-- metric:sha256_wots32_clear_witness -->2280<!-- /metric:sha256_wots32_clear_witness --> / <!-- metric:sha256_wots32_clear_witness_max -->2346<!-- /metric:sha256_wots32_clear_witness_max --> | <!-- metric:sha256_wots32_clear_stack -->137<!-- /metric:sha256_wots32_clear_stack --> | <!-- metric:sha256_wots32_clear_static_opcodes -->2802<!-- /metric:sha256_wots32_clear_static_opcodes --> | <!-- metric:sha256_wots32_clear_total_zero -->7828<!-- /metric:sha256_wots32_clear_total_zero --> / <!-- metric:sha256_wots32_clear_total_max -->7894<!-- /metric:sha256_wots32_clear_total_max --> |
| Strict-chain lookup | <!-- metric:sha256_wots32_minimal_lock -->5478<!-- /metric:sha256_wots32_minimal_lock --> | <!-- metric:sha256_wots32_minimal_witness -->2280<!-- /metric:sha256_wots32_minimal_witness --> / <!-- metric:sha256_wots32_minimal_witness_max -->2346<!-- /metric:sha256_wots32_minimal_witness_max --> | <!-- metric:sha256_wots32_minimal_stack -->143<!-- /metric:sha256_wots32_minimal_stack --> | <!-- metric:sha256_wots32_minimal_static_opcodes -->2998<!-- /metric:sha256_wots32_minimal_static_opcodes --> | <!-- metric:sha256_wots32_minimal_total_zero -->7758<!-- /metric:sha256_wots32_minimal_total_zero --> / <!-- metric:sha256_wots32_minimal_total_max -->7824<!-- /metric:sha256_wots32_minimal_total_max --> |
| Strict numeric recovery | <!-- metric:sha256_wots32_size_lock -->5143<!-- /metric:sha256_wots32_size_lock --> | <!-- metric:sha256_wots32_size_witness -->2280<!-- /metric:sha256_wots32_size_witness --> / <!-- metric:sha256_wots32_size_witness_max -->2346<!-- /metric:sha256_wots32_size_witness_max --> | <!-- metric:sha256_wots32_size_stack -->143<!-- /metric:sha256_wots32_size_stack --> | <!-- metric:sha256_wots32_size_static_opcodes -->2797<!-- /metric:sha256_wots32_size_static_opcodes --> | <!-- metric:sha256_wots32_size_total_zero -->7423<!-- /metric:sha256_wots32_size_total_zero --> / <!-- metric:sha256_wots32_size_total_max -->7489<!-- /metric:sha256_wots32_size_total_max --> |
| Strict numeric terminal | <!-- metric:sha256_wots32_size_clear_lock -->5081<!-- /metric:sha256_wots32_size_clear_lock --> | <!-- metric:sha256_wots32_size_clear_witness -->2280<!-- /metric:sha256_wots32_size_clear_witness --> / <!-- metric:sha256_wots32_size_clear_witness_max -->2346<!-- /metric:sha256_wots32_size_clear_witness_max --> | <!-- metric:sha256_wots32_size_clear_stack -->143<!-- /metric:sha256_wots32_size_clear_stack --> | <!-- metric:sha256_wots32_size_clear_static_opcodes -->2735<!-- /metric:sha256_wots32_size_clear_static_opcodes --> | <!-- metric:sha256_wots32_size_clear_total_zero -->7361<!-- /metric:sha256_wots32_size_clear_total_zero --> / <!-- metric:sha256_wots32_size_clear_total_max -->7427<!-- /metric:sha256_wots32_size_clear_total_max --> |
| Clamped recovery | <!-- metric:sha256_wots32_clamped_lock -->5009<!-- /metric:sha256_wots32_clamped_lock --> | <!-- metric:sha256_wots32_clamped_witness -->2280<!-- /metric:sha256_wots32_clamped_witness --> / <!-- metric:sha256_wots32_clamped_witness_max -->2346<!-- /metric:sha256_wots32_clamped_witness_max --> | <!-- metric:sha256_wots32_clamped_stack -->143<!-- /metric:sha256_wots32_clamped_stack --> | <!-- metric:sha256_wots32_clamped_static_opcodes -->2663<!-- /metric:sha256_wots32_clamped_static_opcodes --> | <!-- metric:sha256_wots32_clamped_total_zero -->7289<!-- /metric:sha256_wots32_clamped_total_zero --> / <!-- metric:sha256_wots32_clamped_total_max -->7355<!-- /metric:sha256_wots32_clamped_total_max --> |
| Clamped terminal | <!-- metric:sha256_wots32_clamped_clear_lock -->4947<!-- /metric:sha256_wots32_clamped_clear_lock --> | <!-- metric:sha256_wots32_clamped_clear_witness -->2280<!-- /metric:sha256_wots32_clamped_clear_witness --> / <!-- metric:sha256_wots32_clamped_clear_witness_max -->2346<!-- /metric:sha256_wots32_clamped_clear_witness_max --> | <!-- metric:sha256_wots32_clamped_clear_stack -->143<!-- /metric:sha256_wots32_clamped_clear_stack --> | <!-- metric:sha256_wots32_clamped_clear_static_opcodes -->2601<!-- /metric:sha256_wots32_clamped_clear_static_opcodes --> | <!-- metric:sha256_wots32_clamped_clear_total_zero -->7227<!-- /metric:sha256_wots32_clamped_clear_total_zero --> / <!-- metric:sha256_wots32_clamped_clear_total_max -->7293<!-- /metric:sha256_wots32_clamped_clear_total_max --> |
| Bitwise recovery | <!-- metric:sha256_wots32_bitwise_lock -->4668<!-- /metric:sha256_wots32_bitwise_lock --> | <!-- metric:sha256_wots32_bitwise_witness -->2484<!-- /metric:sha256_wots32_bitwise_witness --> / <!-- metric:sha256_wots32_bitwise_witness_max -->2746<!-- /metric:sha256_wots32_bitwise_witness_max --> | <!-- metric:sha256_wots32_bitwise_stack -->334<!-- /metric:sha256_wots32_bitwise_stack --> | <!-- metric:sha256_wots32_bitwise_static_opcodes -->2255<!-- /metric:sha256_wots32_bitwise_static_opcodes --> | <!-- metric:sha256_wots32_bitwise_total_zero -->7152<!-- /metric:sha256_wots32_bitwise_total_zero --> / <!-- metric:sha256_wots32_bitwise_total_max -->7414<!-- /metric:sha256_wots32_bitwise_total_max --> |
| Bitwise terminal | <!-- metric:sha256_wots32_bitwise_clear_lock -->4549<!-- /metric:sha256_wots32_bitwise_clear_lock --> | <!-- metric:sha256_wots32_bitwise_clear_witness -->2742<!-- /metric:sha256_wots32_bitwise_clear_witness --> / <!-- metric:sha256_wots32_bitwise_clear_witness_max -->2746<!-- /metric:sha256_wots32_bitwise_clear_witness_max --> | <!-- metric:sha256_wots32_bitwise_clear_stack -->333<!-- /metric:sha256_wots32_bitwise_clear_stack --> | <!-- metric:sha256_wots32_bitwise_clear_static_opcodes -->2125<!-- /metric:sha256_wots32_bitwise_clear_static_opcodes --> | <!-- metric:sha256_wots32_bitwise_clear_total_zero -->7291<!-- /metric:sha256_wots32_bitwise_clear_total_zero --> / <!-- metric:sha256_wots32_bitwise_clear_total_max -->7295<!-- /metric:sha256_wots32_bitwise_clear_total_max --> |

All nine profiles in the original hash tables require **0 auxiliary hint items**. Complete witnesses have
**134 numeric data items** or **333 bitwise data items**, all coexisting at
script entry. The reported combined main-plus-alt-stack peaks include them;
compose with other state against the same 1,000-item limit. Metrics use the
stack-limit-disabled tapscript helper and remain **research-unlimited**.
Separate strict-stack tests cover both hashes; no Bitcoin Core consensus or
policy validation is claimed.

For a 32-byte message, 67 endpoints and 67 witness nodes each grow by 12 bytes:
804 extra endpoint bytes and 804 extra witness bytes. However, the centralized
compiler fuses adjacent `OP_SHA256 OP_SHA256` into `OP_HASH256`, preserving the
chain relation. This saves 461 script bytes in exact/bitwise profiles and 260
in lookup profiles, compared with the unfused SHA-256 byte estimate. The net
script-plus-witness increase over the matching HASH160 profile is **1,147**
or **1,348 bytes**, respectively. Static opcode counts decrease accordingly;
these are not measured executed-opcode counts, and a HASH256 still performs
two SHA-256 chain steps. No host speed claim is needed for this comparison.

HASH160 remains cheaper than SHA-256 for each matching profile in this
32-byte-message comparison. Within SHA-256, bitwise recovery has the lowest
zero-message recovery sum (7,152 bytes), while clamped recovery has the lower
signer-node bound (7,355). Clamped terminal has the lowest zero-message
terminal sum (7,227); its 7,293-byte signer-node bound is two bytes below bitwise terminal.
The optimum therefore depends on hash, message, output contract, and whether
raw digit aliases are acceptable. All totals exclude the same terminal
consumer, script/control-block framing, and transaction overhead; these are
not complete transaction weights.

Native hash semantics are recorded in [Bitcoin Core v29.0 interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp).
Pair fusion is in the pinned [rust-bitcoin-script optimizer](https://github.com/BitVM/rust-bitcoin-script/blob/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180/src/optimizer.rs).

<a id="optional-16-byte-initial-preimages"></a>

## Default 16-byte initial preimages

`FastWinternitz<N, H>` derives 16-byte initial secrets for every supported
hash profile; this is equivalent to explicit `Preimage16`. Choose
`FastWinternitz<N, H, FullWidth>` for native-width initial secrets. Only a
signature digit of zero reveals the initial secret. Later chain positions
retain 20 bytes (HASH160) or 32 bytes (both SHA-256 profiles). Public
commitments are 20 bytes for Hash160/Sha256Hash160 and 32 for Sha256.
The 32-byte master seed is unchanged.

```rust
use bitcoin_lab::signatures::winternitz::FastWinternitz;
type Wots = FastWinternitz<32>; // HASH160, Preimage16 by default.
assert_eq!(Wots::PREIMAGE_BYTES, 16);
assert_eq!(Wots::HASH_BYTES, 20);
let key = Wots::generate_signing_key();
let public_key = Wots::public_key(&key);
let signature = Wots::sign(key, &[0; 32]);
let witness = signature.to_size_optimized_witness();
let verifier = Wots::checksig_verify_clamped_and_clear(&public_key);
```

The mode also appears on `FastSigningKey`, `FastPublicKey`, and
`FastSignature`; persist it with the seed and hash choice. FullWidth's
`chain_values()` accessor still returns native hash arrays. Preimage16's
accessor returns `ShortChainValue<H>` values (`Secret([u8;16])` or `Hashed`),
all borrowable as byte slices. Changing the mode changes keys and witnesses.
Its namespace is `H(prefix || hash_domain || seed || message_bytes_be64)`,
where `prefix = bitcoin-lab/winternitz-preimage16/v1`. Derive chain `i` as
before and take its first 16 bytes as the initial secret. After that, apply
the untruncated native hash at every step.

Each zero digit saves **4 witness bytes for HASH160** or **16 for SHA-256**.
For the zero 32-byte message, 64 message and two checksum digits are zero,
so witness savings are **264 / 1,056 bytes**. The numeric size, clamped, and
bitwise profiles add no script bytes. Strict exact and strict lookup profiles
validate 16 bytes iff the digit is zero and the native width otherwise; their
per-chain size guard compiles to 11 bytes instead of four. The measured
whole-script costs below include this tradeoff. Short preimages therefore
need not reduce cost in every profile/message combination.

Same seed `[0x42;32]`, zero message, `fragment-only` locking boundary and
complete serialized data witness as the earlier tables. Compilation uses
`CompileOptions::ALL` below 32 KiB. Witness upper bounds allow full-width nodes
at every chain and are unchanged; they do not bound hostile accepted encodings.

| Preimage16 profile | Script bytes | Witness bytes (zero / bound) | Combined stack peak | Static non-push opcodes | Script + witness (zero / bound) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hash160 clamped terminal | <!-- metric:preimage16_hash160_clamped_clear_lock -->4403<!-- /metric:preimage16_hash160_clamped_clear_lock --> | <!-- metric:preimage16_hash160_clamped_clear_witness -->1212<!-- /metric:preimage16_hash160_clamped_clear_witness --> / <!-- metric:preimage16_hash160_clamped_clear_witness_max -->1542<!-- /metric:preimage16_hash160_clamped_clear_witness_max --> | <!-- metric:preimage16_hash160_clamped_clear_stack -->143<!-- /metric:preimage16_hash160_clamped_clear_stack --> | <!-- metric:preimage16_hash160_clamped_clear_static_opcodes -->2861<!-- /metric:preimage16_hash160_clamped_clear_static_opcodes --> | <!-- metric:preimage16_hash160_clamped_clear_total_zero -->5615<!-- /metric:preimage16_hash160_clamped_clear_total_zero --> / <!-- metric:preimage16_hash160_clamped_clear_total_max -->5945<!-- /metric:preimage16_hash160_clamped_clear_total_max --> |
| Hash160 bitwise recovery | <!-- metric:preimage16_hash160_bitwise_lock -->4325<!-- /metric:preimage16_hash160_bitwise_lock --> | <!-- metric:preimage16_hash160_bitwise_witness -->1416<!-- /metric:preimage16_hash160_bitwise_witness --> / <!-- metric:preimage16_hash160_bitwise_witness_max -->1942<!-- /metric:preimage16_hash160_bitwise_witness_max --> | <!-- metric:preimage16_hash160_bitwise_stack -->334<!-- /metric:preimage16_hash160_bitwise_stack --> | <!-- metric:preimage16_hash160_bitwise_static_opcodes -->2716<!-- /metric:preimage16_hash160_bitwise_static_opcodes --> | <!-- metric:preimage16_hash160_bitwise_total_zero -->5741<!-- /metric:preimage16_hash160_bitwise_total_zero --> / <!-- metric:preimage16_hash160_bitwise_total_max -->6267<!-- /metric:preimage16_hash160_bitwise_total_max --> |
| Hash160 strict exact terminal | <!-- metric:preimage16_hash160_exact_clear_lock -->5674<!-- /metric:preimage16_hash160_exact_clear_lock --> | <!-- metric:preimage16_hash160_exact_clear_witness -->1212<!-- /metric:preimage16_hash160_exact_clear_witness --> / <!-- metric:preimage16_hash160_exact_clear_witness_max -->1542<!-- /metric:preimage16_hash160_exact_clear_witness_max --> | <!-- metric:preimage16_hash160_exact_clear_stack -->137<!-- /metric:preimage16_hash160_exact_clear_stack --> | <!-- metric:preimage16_hash160_exact_clear_static_opcodes -->3665<!-- /metric:preimage16_hash160_exact_clear_static_opcodes --> | <!-- metric:preimage16_hash160_exact_clear_total_zero -->6886<!-- /metric:preimage16_hash160_exact_clear_total_zero --> / <!-- metric:preimage16_hash160_exact_clear_total_max -->7216<!-- /metric:preimage16_hash160_exact_clear_total_max --> |
| Sha256 clamped terminal | <!-- metric:preimage16_sha256_clamped_clear_lock -->4947<!-- /metric:preimage16_sha256_clamped_clear_lock --> | <!-- metric:preimage16_sha256_clamped_clear_witness -->1224<!-- /metric:preimage16_sha256_clamped_clear_witness --> / <!-- metric:preimage16_sha256_clamped_clear_witness_max -->2346<!-- /metric:preimage16_sha256_clamped_clear_witness_max --> | <!-- metric:preimage16_sha256_clamped_clear_stack -->143<!-- /metric:preimage16_sha256_clamped_clear_stack --> | <!-- metric:preimage16_sha256_clamped_clear_static_opcodes -->2601<!-- /metric:preimage16_sha256_clamped_clear_static_opcodes --> | <!-- metric:preimage16_sha256_clamped_clear_total_zero -->6171<!-- /metric:preimage16_sha256_clamped_clear_total_zero --> / <!-- metric:preimage16_sha256_clamped_clear_total_max -->7293<!-- /metric:preimage16_sha256_clamped_clear_total_max --> |
| Sha256 bitwise recovery | <!-- metric:preimage16_sha256_bitwise_lock -->4668<!-- /metric:preimage16_sha256_bitwise_lock --> | <!-- metric:preimage16_sha256_bitwise_witness -->1428<!-- /metric:preimage16_sha256_bitwise_witness --> / <!-- metric:preimage16_sha256_bitwise_witness_max -->2746<!-- /metric:preimage16_sha256_bitwise_witness_max --> | <!-- metric:preimage16_sha256_bitwise_stack -->334<!-- /metric:preimage16_sha256_bitwise_stack --> | <!-- metric:preimage16_sha256_bitwise_static_opcodes -->2255<!-- /metric:preimage16_sha256_bitwise_static_opcodes --> | <!-- metric:preimage16_sha256_bitwise_total_zero -->6096<!-- /metric:preimage16_sha256_bitwise_total_zero --> / <!-- metric:preimage16_sha256_bitwise_total_max -->7414<!-- /metric:preimage16_sha256_bitwise_total_max --> |
| Sha256 strict exact terminal | <!-- metric:preimage16_sha256_exact_clear_lock -->6017<!-- /metric:preimage16_sha256_exact_clear_lock --> | <!-- metric:preimage16_sha256_exact_clear_witness -->1224<!-- /metric:preimage16_sha256_exact_clear_witness --> / <!-- metric:preimage16_sha256_exact_clear_witness_max -->2346<!-- /metric:preimage16_sha256_exact_clear_witness_max --> | <!-- metric:preimage16_sha256_exact_clear_stack -->137<!-- /metric:preimage16_sha256_exact_clear_stack --> | <!-- metric:preimage16_sha256_exact_clear_static_opcodes -->3204<!-- /metric:preimage16_sha256_exact_clear_static_opcodes --> | <!-- metric:preimage16_sha256_exact_clear_total_zero -->7241<!-- /metric:preimage16_sha256_exact_clear_total_zero --> / <!-- metric:preimage16_sha256_exact_clear_total_max -->8363<!-- /metric:preimage16_sha256_exact_clear_total_max --> |

Every invocation needs **0 auxiliary hint items**. All **134 numeric** or
**333 bitwise** data items coexist at entry and are included in the combined
main/alt stack peaks. Adding protocol state must respect the same 1,000-item
limit. These metrics are `locally-reproduced`, `research-unlimited` because
the tapscript metric helper disables the stack check. Independent strict-stack
tests pass; there is no Bitcoin Core consensus or policy validation.

A 16-byte initial secret has at most **128-bit single-target classical
exhaustive-search resistance**, before multi-target effects. This reduces the
initial-secret search space compared with the full-width modes; it is not a
security-free change or an end-to-end 128-bit Winternitz proof. SHA-256's
generic hash collision bound stays 128 bits; HASH160's stays 80 bits. Initial
secret entropy, hash collision resistance, and concrete one-time signature
security are different quantities. [NIST's hash-security definitions](https://csrc.nist.gov/projects/hash-functions#security-strengths)
separate collision, preimage, and second-preimage resistance. The construction
remains unkeyed Winternitz, not RFC 8391 WOTS+.

## Smaller scripts: SHA-256 chains with HASH160 commitments

`FastWinternitz<N, Sha256Hash160, P>` keeps SHA-256 inside each chain and
commits to its completed endpoint with HASH160. Thus intermediate nodes are
32 bytes (or initial 16-byte secrets under Preimage16), but every public
commitment is 20 bytes. Native SHA256 pairs fuse to HASH256. This combines
short commitments with fewer serialized chain hash opcodes. It has a separate
`bitcoin-lab/winternitz-sha256-hash160/v1` derivation domain, so callers must
derive matching keys and signatures. The existing hash profiles remain available.

```rust
use bitcoin_lab::signatures::winternitz::{FastWinternitz, Sha256Hash160, Preimage16};
type Wots = FastWinternitz<32, Sha256Hash160, Preimage16>;
let key = Wots::generate_signing_key();
let pk = Wots::public_key(&key);
let sig = Wots::sign(key, &[0; 32]);
assert_eq!(Wots::HASH_BYTES, 32);
assert_eq!(Wots::COMMITMENT_BYTES, 20);
// Smallest measured locking fragment:
let small_script = Wots::checksig_verify_bitwise_size_optimized_and_clear(&pk);
let bitwise_witness = sig.to_bitwise_terminal_witness();
// Lower combined cost for this zero-message fixture:
let small_total = Wots::checksig_verify_strided_and_clear(&pk);
let strided_witness = sig.to_strided_witness();
// Both fragments require the surrounding protocol's terminal predicate.
```

The strided witness stores `[q, node, b]` for each chain, where `q = digit/2`
and canonical `b = 1 - (digit % 2)`. It hashes once iff `b`, then selects from
every second chain node. SHA256 pairs become HASH256. The same authenticated
`d = 2*min(q, chain_max/2) + 1-b` enters the weighted checksum, accumulated
directly without recovering every message digit. Negative quotients and oversized ScriptNum encodings fail; above-range quotients alias the last two digits, depending
on the bit. `MINIMALIF` rejects noncanonical bits. This is an explicit clamped
terminal profile, not the strict numeric relation.

The following costs use the same 32-byte zero message and seed `[0x42;32]`,
final compilation policy, fragment-only scripts, and serialized witness
boundary as the earlier tables. No terminal predicate or transaction framing
is included. All these scripts are below 32 KiB and receive the full optimizer.
The upper bound permits full-width nodes and one-byte numeric/bit items; it
is not a bound on hostile accepted raw encodings.

| Hybrid mode / terminal profile | Script bytes | Witness zero / bound | Stack peak | Static opcodes | Total zero / bound | Entry items | Hint items |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| FullWidth clamped | <!-- metric:hybrid_full_clamped_lock -->4210<!-- /metric:hybrid_full_clamped_lock --> | <!-- metric:hybrid_full_clamped_witness -->2280<!-- /metric:hybrid_full_clamped_witness --> / <!-- metric:hybrid_full_clamped_witness_max -->2346<!-- /metric:hybrid_full_clamped_witness_max --> | <!-- metric:hybrid_full_clamped_stack -->143<!-- /metric:hybrid_full_clamped_stack --> | <!-- metric:hybrid_full_clamped_static_opcodes -->2668<!-- /metric:hybrid_full_clamped_static_opcodes --> | <!-- metric:hybrid_full_clamped_total_zero -->6490<!-- /metric:hybrid_full_clamped_total_zero --> / <!-- metric:hybrid_full_clamped_total_max -->6556<!-- /metric:hybrid_full_clamped_total_max --> | <!-- metric:hybrid_full_clamped_items -->134<!-- /metric:hybrid_full_clamped_items --> | <!-- metric:hybrid_full_clamped_hints -->0<!-- /metric:hybrid_full_clamped_hints --> |
| FullWidth bitwise | <!-- metric:hybrid_full_bitwise_lock -->3812<!-- /metric:hybrid_full_bitwise_lock --> | <!-- metric:hybrid_full_bitwise_witness -->2742<!-- /metric:hybrid_full_bitwise_witness --> / <!-- metric:hybrid_full_bitwise_witness_max -->2746<!-- /metric:hybrid_full_bitwise_witness_max --> | <!-- metric:hybrid_full_bitwise_stack -->333<!-- /metric:hybrid_full_bitwise_stack --> | <!-- metric:hybrid_full_bitwise_static_opcodes -->2192<!-- /metric:hybrid_full_bitwise_static_opcodes --> | <!-- metric:hybrid_full_bitwise_total_zero -->6554<!-- /metric:hybrid_full_bitwise_total_zero --> / <!-- metric:hybrid_full_bitwise_total_max -->6558<!-- /metric:hybrid_full_bitwise_total_max --> | <!-- metric:hybrid_full_bitwise_items -->333<!-- /metric:hybrid_full_bitwise_items --> | <!-- metric:hybrid_full_bitwise_hints -->0<!-- /metric:hybrid_full_bitwise_hints --> |
| FullWidth strided | <!-- metric:hybrid_full_strided_lock -->3961<!-- /metric:hybrid_full_strided_lock --> | <!-- metric:hybrid_full_strided_witness -->2413<!-- /metric:hybrid_full_strided_witness --> / <!-- metric:hybrid_full_strided_witness_max -->2480<!-- /metric:hybrid_full_strided_witness_max --> | <!-- metric:hybrid_full_strided_stack -->209<!-- /metric:hybrid_full_strided_stack --> | <!-- metric:hybrid_full_strided_static_opcodes -->2480<!-- /metric:hybrid_full_strided_static_opcodes --> | <!-- metric:hybrid_full_strided_total_zero -->6374<!-- /metric:hybrid_full_strided_total_zero --> / <!-- metric:hybrid_full_strided_total_max -->6441<!-- /metric:hybrid_full_strided_total_max --> | <!-- metric:hybrid_full_strided_items -->201<!-- /metric:hybrid_full_strided_items --> | <!-- metric:hybrid_full_strided_hints -->0<!-- /metric:hybrid_full_strided_hints --> |
| Preimage16 clamped | <!-- metric:hybrid_short_clamped_lock -->4210<!-- /metric:hybrid_short_clamped_lock --> | <!-- metric:hybrid_short_clamped_witness -->1224<!-- /metric:hybrid_short_clamped_witness --> / <!-- metric:hybrid_short_clamped_witness_max -->2346<!-- /metric:hybrid_short_clamped_witness_max --> | <!-- metric:hybrid_short_clamped_stack -->143<!-- /metric:hybrid_short_clamped_stack --> | <!-- metric:hybrid_short_clamped_static_opcodes -->2668<!-- /metric:hybrid_short_clamped_static_opcodes --> | <!-- metric:hybrid_short_clamped_total_zero -->5434<!-- /metric:hybrid_short_clamped_total_zero --> / <!-- metric:hybrid_short_clamped_total_max -->6556<!-- /metric:hybrid_short_clamped_total_max --> | <!-- metric:hybrid_short_clamped_items -->134<!-- /metric:hybrid_short_clamped_items --> | <!-- metric:hybrid_short_clamped_hints -->0<!-- /metric:hybrid_short_clamped_hints --> |
| Preimage16 bitwise | <!-- metric:hybrid_short_bitwise_lock -->3812<!-- /metric:hybrid_short_bitwise_lock --> | <!-- metric:hybrid_short_bitwise_witness -->1686<!-- /metric:hybrid_short_bitwise_witness --> / <!-- metric:hybrid_short_bitwise_witness_max -->2746<!-- /metric:hybrid_short_bitwise_witness_max --> | <!-- metric:hybrid_short_bitwise_stack -->333<!-- /metric:hybrid_short_bitwise_stack --> | <!-- metric:hybrid_short_bitwise_static_opcodes -->2192<!-- /metric:hybrid_short_bitwise_static_opcodes --> | <!-- metric:hybrid_short_bitwise_total_zero -->5498<!-- /metric:hybrid_short_bitwise_total_zero --> / <!-- metric:hybrid_short_bitwise_total_max -->6558<!-- /metric:hybrid_short_bitwise_total_max --> | <!-- metric:hybrid_short_bitwise_items -->333<!-- /metric:hybrid_short_bitwise_items --> | <!-- metric:hybrid_short_bitwise_hints -->0<!-- /metric:hybrid_short_bitwise_hints --> |
| Preimage16 strided | <!-- metric:hybrid_short_strided_lock -->3961<!-- /metric:hybrid_short_strided_lock --> | <!-- metric:hybrid_short_strided_witness -->1357<!-- /metric:hybrid_short_strided_witness --> / <!-- metric:hybrid_short_strided_witness_max -->2480<!-- /metric:hybrid_short_strided_witness_max --> | <!-- metric:hybrid_short_strided_stack -->209<!-- /metric:hybrid_short_strided_stack --> | <!-- metric:hybrid_short_strided_static_opcodes -->2480<!-- /metric:hybrid_short_strided_static_opcodes --> | <!-- metric:hybrid_short_strided_total_zero -->5318<!-- /metric:hybrid_short_strided_total_zero --> / <!-- metric:hybrid_short_strided_total_max -->6441<!-- /metric:hybrid_short_strided_total_max --> | <!-- metric:hybrid_short_strided_items -->201<!-- /metric:hybrid_short_strided_items --> | <!-- metric:hybrid_short_strided_hints -->0<!-- /metric:hybrid_short_strided_hints --> |

All entry items coexist and are included in the combined main-plus-alt-stack
peak; compose with other protocol state against the same 1,000-item ceiling.
Strided uses 201 items for Wots32, versus 134 numeric or 333 bitwise, and no
profile adds auxiliary hints. Measurements are `locally-reproduced` and
`research-unlimited`: the metric helper disables the stack check in tapscript.
Separate strict-stack roundtrip and adversarial tests pass. There is no Core
consensus/policy validation or complete transaction measurement.

The hybrid has **160-bit commitments**, retaining HASH160's generic 80-bit
collision bound, not SHA-256's 128-bit bound. Preimage16 still caps initial
secret exhaustive search at 128 single-target classical bits before
multi-target effects. A new commitment hash also changes the raw relation:
size/bitwise/strided profiles admit arbitrary raw node lengths even at the
maximum digit, because HASH160 normalizes the computed endpoint. Strict
exact/lookup profiles still enforce the selected initial/intermediate widths.
The chain suffix and checksum remain bound, but this is not a WOTS+ security
proof. The hybrid reduces script size; its larger nonzero signature nodes can
increase total witness cost, so choose by the actual message and boundary.

Numeric verification also improves without changing keys or witnesses:
checksum digits of at most three bits now use full tables, whose smaller
control overhead beats half tables. Four-bit chains retain half tables.
Strict lookup relies on OP_PICK to reject negative indices while retaining an
explicit upper bound. Exhaustive tests include deliberately matching unrelated
stack values to ensure no selector escapes its own table.

## Security

Every key is strictly one-time. Signing twice with the same seed and message
length can expose chain nodes that enable a new valid digit vector despite the
checksum. The consuming Rust API reduces accidental reuse but cannot protect
against restoring a seed, copying it before construction, crash rollback, or
concurrent signers; durable state is a protocol obligation.

HASH160 gives 160-bit outputs; SHA-256 gives 256-bit outputs. Their idealized
single-target classical preimage bounds are at most 160/256 bits, and birthday
collision bounds are at most 80/128 bits, respectively. These hash-level bounds
are not end-to-end signature security claims: multi-target attacks, chain
length, message choice, and the custom unkeyed construction require analysis.
SHA-256 offers a wider hash security margin at higher onchain byte cost. The custom chain-start
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
so the chain value is on top. FullWidth checks its native 20/32-byte size
before consuming the digit; Preimage16 checks its size against the digit-zero
condition. Shortening the initial secret does not add witness items. A zero digit is an empty item; positive digits use canonical
one-byte ScriptNum items. Size witness order is message `[chain_i, digit_i]` pairs
followed by checksum pairs in reverse chain-index order; callers must use
`to_size_optimized_witness` with a numeric size verifier. Bitwise recovery
chunks are `[bit_1, bit_2, ..., chain]`; terminal chunks interleave the chain
before `bit_1` so each selected conditional exposes the chain node. Callers
must use the matching bitwise witness serializer. The clamped profiles use
`to_size_optimized_witness` without any serialization changes. All profiles
require **0 auxiliary hint items**: the 134 numeric, 201 strided, or 333 bitwise items are
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
  and peak at 143 combined items for the metric vector.
- `FastWots32::checksig_verify_bitwise_size_optimized`: consumes 333 witness
  items and leaves the same 64 authenticated nibbles with the smallest measured
  recovery fragment.
- `FastWots32::checksig_verify_bitwise_size_optimized_and_clear`: consumes its
  terminal-specific 333-item witness and leaves an empty stack with the
  smallest measured terminal fragment.
- `FastWots32::checksig_verify_strided_and_clear`: consumes 201 items,
  peaks at 209 combined items, and leaves an empty stack.
- `FastWots32::checksig_verify_and_clear`: consumes the signature, reduces
  staged authenticated digits through the checksum, and leaves an empty stack.
  The caller must append a terminal predicate.

All internal altstack state is balanced. Extra witness items remain below the
fixed input and are rejected by tapscript cleanstack only when the fragment is
composed into a complete leaf.

## Test coverage and limitations

Tests cover all verifier profiles and terminal paths, every documented
stack postcondition, separately generated Python vectors for every hash choice, wrong chain
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

The hash-choice tests cover every verifier with strict stack enforcement,
message/checksum boundaries, wrong hash witnesses, altered chain nodes and
checksum binding, malformed numbers, and compile-time key-type
separation. Run `python3 tools/winternitz_hash_vectors.py` to reproduce the
independent Python stdlib endpoint/signature digests for all three hash profiles; Rust
compares those fixed vectors in `hash_choice_tests.rs`.

## Lossless 20-byte messages with a constant-sum encoding

`ConstantSumWinternitz20<H = Hash160, P = Preimage16>` is a separate terminal
construction for exactly 20 unchanged message bytes. It reduces the measured
locking fragment plus serialized signature data. The host treats the message as a
big-endian rank and reversibly encodes it into 41 digits: 32 radix-16 digits,
four radix-18 digits, and five radix-20 digits, with digit sum 321. There are
no separate checksum chains, no padding search, and no message truncation.
The digits are enumerative code coordinates, not the original byte nibbles.

The number of bounded vectors with that sum is
`1470691080098966924606702294670956744709470421906`, exceeding `2^160`.
`encode_message` selects the first `2^160` vectors in lexicographic order;
`decode_message` checks digit count, ranges, sum, and rank below `2^160`.
Both use exact integer suffix counts. Script verifies the terminal relation
and does not implement this host decoder or its final rank bound. Even the
bounded verifier consequently accepts a larger antichain than the host
encoder uses. This is appropriate only when the surrounding protocol needs
verification and consumption, rather than recovered bytes or proof of a
canonical onchain byte encoding.

```rust
use bitcoin_lab::signatures::winternitz::ConstantSumWinternitz20;
type Wots = ConstantSumWinternitz20;
let message = [0x42; 20];
let key = Wots::generate_signing_key();
let public_key = Wots::public_key(&key);
let signature = Wots::sign(key, &message);
assert_eq!(Wots::decode_message(signature.digits()).unwrap(), message);
let script = Wots::checksig_verify_and_clear(&public_key);
let witness = signature.to_witness();
assert_eq!(witness.len(), 82);
// Append the surrounding protocol's terminal predicate.
```

The hash choices are `Hash160`, `Sha256`, and `Sha256Hash160`; start modes
are `Preimage16` and `FullWidth`. Every choice has matching typed keys,
commitments, and signatures. The namespace binds the constant-sum domain,
hash domain, preimage domain, radix vector, sum, and seed. Persist the complete
configuration and never reuse the seed after signing. Existing Fast keys and
witnesses cannot be substituted for this construction.

### Terminal relation and the omitted upper bounds

The smallest verifier omits individual upper-digit guards. For HASH160 it
uses numeric witnesses `[node_i, digit_i]`; an above-range `OP_PICK` index can
read a matching value from preceding witness or protocol state. Such a
coordinate is not independently range-checked or locally authenticated. Its
raw nonnegative numeric value is nevertheless included unchanged in the
fixed sum. SHA-256 variants use `[digit_i / 2, node_i, 1 - digit_i % 2]` and
include the equivalent raw digit `2*q + 1 - b`; `MINIMALIF` enforces the bit.
Negative lookup indices and oversized ScriptNums fail.

The security argument is a **local inference**, under honestly generated
independent chain keys, a canonical signer vector, one-time use, and the
ordinary chain inversion/collision assumptions. Every honest digit is below
its chain radix. An overflowing alternative digit is therefore strictly
larger than the signed one, even if its lookup escapes. Any distinct vector
with the same exact sum must also decrease some coordinate. That decreased
coordinate is in range, so its lookup remains inside its own chain table and
requires an earlier chain node. The sum uses non-wrapping ScriptNum arithmetic.
This argument depends on the complete fixed-sum composition; these chain
fragments must not be reused as standalone digit authenticators.
The unbounded relation is broader than the boxed code: someone holding all
signing secrets can construct an accepted out-of-radix same-sum vector, which
the bounded method rejects. That is not a forgery from a canonical signature;
it demonstrates that canonical onchain encoding is not the claimed relation.

`checksig_verify_bounded_and_clear` adds explicit radix rejection before each
chain. It still omits the host rank bound and raw node-width checks. Both
terminal methods intentionally accept the size-profile preimage relation:
only signer-produced starts are guaranteed to be 16 bytes. HASH160/SHA-256
maximum digits compare with native endpoints; hybrid maximum digits also
execute the final commitment hash. Neither method supplies canonical raw
witness serialization or a general WOTS+ security proof.

The general constant-sum method is established research: Zhang, Cui, and Yu,
[ePrint 2023/850](https://eprint.iacr.org/2023/850), received 2023-06-06
(`constant-sum-wots-2023`). Its WOTS+ analysis does not prove this custom
unkeyed Script implementation or the omitted-upper-guard argument above.

### Measured 20-byte costs and execution boundary

The default results use seed `[0x42;32]`, the final compilation policy, and
fragment-only locking scripts containing all commitments, chain checks, sum
verification, and cleanup. Signature witnesses include the item count and
all item-length prefixes. The final predicate, script-item framing, control
block, and transaction overhead are excluded on both sides. The zero fixture
is `[0;20]`, all-`ff` is `[0xff;20]`, and varied byte `i` is `(37*i) mod 256`.

All rows below use `Preimage16`. The bounded row adds explicit digit-range
rejection; both constant-sum HASH160 rows use the same signer witness.

The [first table](#winternitz-one-time-signatures) lists these 20-byte
script and witness measurements, including both best-cost profiles.

<details>
<summary>Boundary fixtures used by regression checks</summary>

These fixtures check edge cases and are excluded from the comparison table.

- Constant-sum HASH160: zero <!-- metric:w20_sum_hash160_witness_zero -->839<!-- /metric:w20_sum_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_hash160_witness_ff -->934<!-- /metric:w20_sum_hash160_witness_ff --> bytes.
- Constant-sum HASH160, bounded: zero <!-- metric:w20_sum_bounded_hash160_witness_zero -->839<!-- /metric:w20_sum_bounded_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_bounded_hash160_witness_ff -->934<!-- /metric:w20_sum_bounded_hash160_witness_ff --> bytes.
- Base-16 HASH160 clamped: zero <!-- metric:w20_base16_hash160_witness_zero -->785<!-- /metric:w20_base16_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_base16_hash160_witness_ff -->975<!-- /metric:w20_base16_hash160_witness_ff --> bytes.
- Constant-sum hybrid: zero <!-- metric:w20_sum_hybrid_witness_zero -->1142<!-- /metric:w20_sum_hybrid_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_hybrid_witness_ff -->1454<!-- /metric:w20_sum_hybrid_witness_ff --> bytes.
- Constant-sum SHA-256: zero <!-- metric:w20_sum_sha256_witness_zero -->1142<!-- /metric:w20_sum_sha256_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_sha256_witness_ff -->1454<!-- /metric:w20_sum_sha256_witness_ff --> bytes.

</details>

| Terminal profile | Combined main/alt-stack peak | Static non-push opcodes | Complete entry data items | Auxiliary hint items |
| --- | ---: | ---: | ---: | ---: |
| Base-16 HASH160 clamped | <!-- metric:w20_base16_hash160_stack -->95<!-- /metric:w20_base16_hash160_stack --> | <!-- metric:w20_base16_hash160_opcodes -->1829<!-- /metric:w20_base16_hash160_opcodes --> | <!-- metric:w20_base16_hash160_items -->86<!-- /metric:w20_base16_hash160_items --> | <!-- metric:w20_base16_hash160_hints -->0<!-- /metric:w20_base16_hash160_hints --> |
| Constant-sum HASH160 | <!-- metric:w20_sum_hash160_stack -->93<!-- /metric:w20_sum_hash160_stack --> | <!-- metric:w20_sum_hash160_opcodes -->1774<!-- /metric:w20_sum_hash160_opcodes --> | <!-- metric:w20_sum_hash160_items -->82<!-- /metric:w20_sum_hash160_items --> | <!-- metric:w20_sum_hash160_hints -->0<!-- /metric:w20_sum_hash160_hints --> |
| Constant-sum HASH160, bounded | <!-- metric:w20_sum_bounded_hash160_stack -->93<!-- /metric:w20_sum_bounded_hash160_stack --> | <!-- metric:w20_sum_bounded_hash160_opcodes -->1897<!-- /metric:w20_sum_bounded_hash160_opcodes --> | <!-- metric:w20_sum_bounded_hash160_items -->82<!-- /metric:w20_sum_bounded_hash160_items --> | <!-- metric:w20_sum_bounded_hash160_hints -->0<!-- /metric:w20_sum_bounded_hash160_hints --> |
| Constant-sum SHA-256 | <!-- metric:w20_sum_sha256_stack -->133<!-- /metric:w20_sum_sha256_stack --> | <!-- metric:w20_sum_sha256_opcodes -->1475<!-- /metric:w20_sum_sha256_opcodes --> | <!-- metric:w20_sum_sha256_items -->123<!-- /metric:w20_sum_sha256_items --> | <!-- metric:w20_sum_sha256_hints -->0<!-- /metric:w20_sum_sha256_hints --> |
| Constant-sum hybrid | <!-- metric:w20_sum_hybrid_stack -->133<!-- /metric:w20_sum_hybrid_stack --> | <!-- metric:w20_sum_hybrid_opcodes -->1516<!-- /metric:w20_sum_hybrid_opcodes --> | <!-- metric:w20_sum_hybrid_items -->123<!-- /metric:w20_sum_hybrid_items --> | <!-- metric:w20_sum_hybrid_hints -->0<!-- /metric:w20_sum_hybrid_hints --> |

The 2,680-byte default fragment plus the 839-byte zero-message witness totals
3,519 bytes. Independent exact counting over all `2^160` messages gives a
mean witness of approximately 931.841783370768 bytes and a mean total of
3,611.841783370768 bytes. The maximum signer witness is exactly 944 bytes;
it bounds honest signatures, not accepted hostile raw encodings.

The existing `FastWinternitz<20, Hash160, Preimage16>` clamped terminal uses
2,819 script bytes and a 990-byte signer-node witness bound, totaling 3,809
bytes. The new 3,624-byte maximum total is 185 bytes smaller. Its script alone
saves 139 bytes. Independent exact counting over all `2^160` messages gives
the baseline mean witness approximately 976.262466089252 bytes and mean total
3,795.262466089252 bytes. The exact uniform-message expectation improves by
approximately 183.420682718484 bytes, or 4.83%. Both means are rounded decimal
displays of exact counts over the same input distribution; neither is sampled.

The hybrid has the smallest locking fragment among these retained profiles,
2,381 bytes, but its 32-byte nonzero openings increase the maximum combined
cost to 3,898 bytes. HASH160 minimizes the measured mean and maximum combined
costs. Explicit HASH160 upper-bound rejection costs 173 additional script
bytes, yielding a 3,797-byte maximum total with the same signer witness.

All 82 default data items coexist at entry; the measured combined peak is 93,
including the lookup table and sum accumulator. The baseline has 86 entry
items and peaks at 95. Both need **zero auxiliary hint items per invocation**.
SHA-256 variants use 123 entry data items, also with zero hints; their separate
measurements must be used when budgeting stack space. Unrelated live state
counts against the same 1,000-item combined stack limit. Both terminal methods
preserve unrelated main/alt-stack state and leave no result; the caller must
append its predicate.

Metrics are `locally-reproduced` and `research-unlimited`: the tapscript metric
helper disables the stack check and appends `OP_TRUE` for execution. Separate
strict-stack tests remain `unclassified` deployment evidence. No Bitcoin Core
consensus, relay-policy, or complete-transaction validation is claimed.
The pinned local executor can panic on an `OP_PICK` index outside the entire
stack. Adversarial lookup-escape tests therefore place traps inside the
complete stack; they do not establish correct local handling of every index.
Bitcoin consensus rejects a genuinely out-of-stack index. This local executor
limitation is recorded in the [negative result](../../../knowledge/negative-results/index.md#nr-041-20-byte-winternitz-search-and-overflow-relation-boundaries).

`python3 tools/winternitz20_vectors.py` independently reproduces the encoder,
host vectors, exact witness mean, and exact maximum. Rust tests compare its
fixed outputs, exercise message roundtrips and invalid ranks, and check chain
mutations, sum binding, overflow traps, malformed numbers, and preserved stack
state. See the [constant-sum primitive page](../../../knowledge/primitives/winternitz-constant-sum20.md),
the [signature comparison](../../../knowledge/comparisons/signatures.md), and
[OP-009](../../../knowledge/open-problems.md#op-009--one-time-authentication-security-profiles).
