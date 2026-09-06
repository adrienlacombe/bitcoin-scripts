# Winternitz one-time signatures

Choose the construction by what Script must do with the authenticated data.
[Base-16](base16/README.md) signs the actual message nibbles and can return
them to a Script consumer. [Constant-sum](constant_sum/README.md) reversibly
encodes 20 bytes and currently only verifies and consumes the signature.
**BitVM3 can handle constant-sum encoding**; it does not require the publication
script to reconstruct the original proof bytes. Integrations that do require
Script to recover or consume those bytes must include that conversion cost.

## Total onchain cost for 20-byte terminal verification

All rows use 16-byte initial secrets, seed `[0x42;32]`, and the same
fragment-plus-serialized-signature boundary. “Varied” byte `i` is
`(37*i) mod 256`; “maximum” is the attained signer-witness maximum.
Rows are ordered by maximum combined cost.

| Terminal profile | Script bytes | Varied witness | Maximum signer witness | Script + maximum witness |
| --- | ---: | ---: | ---: | ---: |
| Constant-sum HASH160 | <!-- metric:w20_sum_hash160_script -->2680<!-- /metric:w20_sum_hash160_script --> | <!-- metric:w20_sum_hash160_witness_varied -->924<!-- /metric:w20_sum_hash160_witness_varied --> | <!-- metric:w20_sum_hash160_witness_max -->944<!-- /metric:w20_sum_hash160_witness_max --> | <!-- metric:w20_sum_hash160_total_max -->3624<!-- /metric:w20_sum_hash160_total_max --> |
| Constant-sum HASH160, bounded | <!-- metric:w20_sum_bounded_hash160_script -->2853<!-- /metric:w20_sum_bounded_hash160_script --> | <!-- metric:w20_sum_bounded_hash160_witness_varied -->924<!-- /metric:w20_sum_bounded_hash160_witness_varied --> | <!-- metric:w20_sum_bounded_hash160_witness_max -->944<!-- /metric:w20_sum_bounded_hash160_witness_max --> | <!-- metric:w20_sum_bounded_hash160_total_max -->3797<!-- /metric:w20_sum_bounded_hash160_total_max --> |
| Base-16 HASH160 clamped | <!-- metric:w20_base16_hash160_script -->2819<!-- /metric:w20_base16_hash160_script --> | <!-- metric:w20_base16_hash160_witness_varied -->960<!-- /metric:w20_base16_hash160_witness_varied --> | <!-- metric:w20_base16_hash160_witness_max -->990<!-- /metric:w20_base16_hash160_witness_max --> | <!-- metric:w20_base16_hash160_total_max -->3809<!-- /metric:w20_base16_hash160_total_max --> |
| Constant-sum hybrid | <!-- metric:w20_sum_hybrid_script -->2381<!-- /metric:w20_sum_hybrid_script --> | <!-- metric:w20_sum_hybrid_witness_varied -->1430<!-- /metric:w20_sum_hybrid_witness_varied --> | <!-- metric:w20_sum_hybrid_witness_max -->1517<!-- /metric:w20_sum_hybrid_witness_max --> | <!-- metric:w20_sum_hybrid_total_max -->3898<!-- /metric:w20_sum_hybrid_total_max --> |
| Constant-sum SHA-256 | <!-- metric:w20_sum_sha256_script -->2832<!-- /metric:w20_sum_sha256_script --> | <!-- metric:w20_sum_sha256_witness_varied -->1430<!-- /metric:w20_sum_sha256_witness_varied --> | <!-- metric:w20_sum_sha256_witness_max -->1517<!-- /metric:w20_sum_sha256_witness_max --> | <!-- metric:w20_sum_sha256_total_max -->4349<!-- /metric:w20_sum_sha256_total_max --> |

HASH160 constant-sum has the lowest tested combined maximum, **3,624 bytes**.
The hybrid has the smallest script, **2,381 bytes**, but larger openings
increase its total to **3,898 bytes**. Exact uniform-message means are
**3,611.84 bytes** for constant-sum HASH160 and **3,795.26 bytes** for the
base-16 baseline. These measure signature publication/consumption; they do
not include a separate Script decoder or the rest of a BitVM3 transaction.

The fragments include embedded commitments, chain verification, checksum
or sum checks, and cleanup. The terminal predicate, script-item framing,
Taproot control block, and transaction overhead are excluded equally. Both
script and signature data contribute witness bytes; these totals are not
complete transaction weights. All scripts use the centralized compilation
policy. Detailed fixtures, static opcode counts, and reproduction commands
are in the construction READMEs.

## High-level tradeoffs

- **Direct base-16:** ordinary nibble encoding plus a checksum. Recovery
  methods return authenticated nibbles; terminal methods consume them.
  Lookup, clamped, bitwise, and strided profiles trade script size against
  witness size, execution, stack use, and range-checking behavior. Compare
  methods with the same output contract.
- **Constant-sum:** lossless mixed-radix encoding removes checksum chains,
  but its digits are not the original nibbles. The current terminal API
  omits onchain decoding and the encoder-image check. Its smallest mode
  also omits individual upper bounds and relies on a complete fixed-sum
  argument for an honest canonical signer. A malicious publisher can
  create accepted encodings that host decoding rejects; the bounded mode
  checks digit ranges but still omits the encoder-image check.
- **Hash and initial-secret width:** HASH160 makes nodes and commitments
  small; hybrid SHA-256/HASH160 shortens commitments while keeping
  32-byte chain nodes. Pure SHA-256 has larger commitments. Initial
  secrets are 16 bytes by default, but later nodes keep the native width.
  See [shared security and representations](shared/README.md).
- **Original API:** [legacy](legacy/README.md) retains the older HASH160
  signing, converter, and verifier implementation and its wire vectors.

## Structure and public API

```text
winternitz/
  README.md             tradeoffs and total onchain cost
  mod.rs                construction modules and existing public type exports
  base16/               typed FastWinternitz; direct message digits + checksum
    README.md           exact profiles, witnesses, contracts, and measurements
    mod.rs, strided.rs  implementation
    tests/              Rust tests and independent Python vectors
  constant_sum/         experimental terminal-only 20-byte encoding
    README.md           encoding, accepted relation, and BitVM3 integration
    mod.rs, chain.rs    implementation
    tests/              Rust tests, overflow cases, and exact Python costs
  legacy/               original HASH160 API and converters
    README.md
    api.rs, signing.rs, verification.rs, utils.rs
    tests/              Rust tests and original JSON vectors
  shared/               hash functions and initial-secret representations
    README.md
    chain_hash.rs, preimage.rs
```

Existing high-level types such as `FastWinternitz`, `ConstantSumWinternitz20`,
`Wots32`, `Hash160`, and `Preimage16` remain available from
`signatures::winternitz`. Low-level legacy modules now live under
`signatures::winternitz::legacy`. Implementation tests live with their
construction; the repository-wide metric harness remains in
[`tests/primitive_metrics.rs`](../../../tests/primitive_metrics.rs).

## Security, stack, and evidence boundary

All keys are strictly one-time. Consuming a Rust key does not prevent seed
restoration or reuse by concurrent signers. HASH160 and hybrid commitments
have an 80-bit generic collision bound; pure SHA-256 has a 128-bit bound.
Sixteen-byte starts cap initial-secret search at 128 bits before multi-target
losses. These are custom unkeyed chains, not WOTS+ security claims.

All table rows have **zero auxiliary hints**, and all signature items coexist
at entry. HASH160 constant-sum uses 82 data items and peaks at 93 combined
main/alt-stack items; base-16 uses 86/95; SHA-256 constant-sum uses 123/133.
Surrounding state counts toward the same 1,000-item limit.

Metrics are `locally-reproduced`, `research-unlimited`: the tapscript metric
helper disables stack-limit enforcement. Separate strict local tests do not
establish Bitcoin Core consensus or policy acceptance. An out-of-stack
`OP_PICK` panic in the local executor remains documented in the constant-sum
README. See the [cost model](../../../knowledge/cost-model.md) and
[signature comparison](../../../knowledge/comparisons/signatures.md).
