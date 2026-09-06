# Shared hash and initial-secret types

These types describe the hash chain and its initial secret. They are shared
by [base16](../base16/README.md) and [constant_sum](../constant_sum/README.md);
this directory does not implement a standalone signature verifier.

## Parameters

| Type | Chain outputs | Endpoint commitments | Script operation |
| --- | ---: | ---: | --- |
| `Hash160` | 20 bytes | 20 bytes | `OP_HASH160` |
| `Sha256` | 32 bytes | 32 bytes | `OP_SHA256` |
| `Sha256Hash160` | 32 bytes | 20 bytes | SHA-256 chain, final `OP_HASH160` commitment |

`Preimage16` is the default initial-secret representation, with exactly
16-byte signer starts. Later nodes remain native-width, so a signature gets
shorter only where a digit reveals its chain start. `FullWidth` uses the
native hash width for every node. The `PreimageSize<H>` type binds starts
and witness values to the chosen hash; `ChainHash` binds hash, commitment,
and Script operations. These traits are sealed to the supported choices.

## Code and domains

[chain_hash.rs](chain_hash.rs) defines `ChainHash`, hashes, commitment
operations, and hash-specific domain constants. [preimage.rs](preimage.rs)
defines `PreimageSize`, `ShortChainValue`, and the initial-secret domain.
Each construction binds its own message geometry and namespace; see its
README and signer. Hash choice and width are fixed in keys and scripts,
never selected by an untrusted witness.

## Security

A 16-byte initial secret caps generic single-target search at 128 bits
before multi-target losses. It does not make HASH160 collision-resistant
to 128 bits: HASH160 and hybrid commitments retain an 80-bit generic
collision bound, whereas SHA-256 has a 128-bit generic collision bound.
These are hash bounds, not complete security proofs for custom unkeyed WOTS.
One-time use and durable seed management remain essential.

Raw node-width acceptance is a verifier property. Strict base-16 methods
validate the chosen width; size-oriented and constant-sum methods have a
broader raw-preimage relation. Host types do not validate hostile witnesses.

## Validation and composition

Hash/width correctness, domain-separated vectors, all verifier modes, and
malformed witnesses are tested in each construction’s `tests/` directory.
These types alone add no stack or hint contract: complete item counts,
peaks, metrics, execution classes, and terminal predicates belong to the
selected verifier. See the [overview](../README.md) for total onchain cost.
