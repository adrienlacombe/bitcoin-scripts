# Primary-source registry

The machine-readable registry is [`sources.json`](sources.json). Catalog records
refer to source IDs rather than embedding mutable URLs repeatedly.

Source classes include:

- Bitcoin consensus and script-version specifications;
- Bitcoin Core and execution tooling;
- local upstream implementation repositories and pinned dependency revisions;
- cryptographic standards and original papers;
- protocol papers and active upstream implementations.

A rolling branch is discovery evidence, not immutable reproduction provenance.
Before promoting a reported result, record the exact commit or document version
used by the reproduction.


The Fast Winternitz hash-choice comparison inspects Bitcoin Core **v29.0**
native SHA256/HASH160/HASH256 semantics (`bitcoin-core-v29-hashes`). Its local
compiled measurements use `bitcoin-script-locked` at
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, including SHA256-pair fusion.
That Core source inspection is not a Core execution or policy reproduction.

The default Preimage16 discussion uses `nist-hash-security-strengths` for the
distinction between collision, preimage, and second-preimage resistance. The
128-bit initial-secret exhaustive-search ceiling is a local inference from
the 16-byte secret space, before multi-target effects; the NIST table is not
a security proof for the custom Winternitz construction.

The 20-byte constant-sum Winternitz construction cites
`constant-sum-wots-2023` for the established encoding approach. Its mixed
radix selection, Bitcoin Script byte measurements, and whole-vector argument
for omitting individual upper bounds are local results. The paper is not a
security proof for this unkeyed native-hash implementation. The reversible
encoder has an independent Python reproduction in
[`src/signatures/winternitz/constant_sum/tests/vectors.py`](../../src/signatures/winternitz/constant_sum/tests/vectors.py).

Bitcoin Core v29.0 rejects `OP_PICK` indices outside the entire stack in
[`interpreter.cpp`, lines 759–769](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp#L759-L769).
That source inspection is distinct from the local executor's known panic on
some out-of-stack positive indices; no Core execution is claimed here.

The fixed-composition construction uses `nist-dlmf-multiset-permutations`,
NIST DLMF §26.16 version 1.2.7 (2026-06-15), for exact multiset capacity.
Its key-pool verifier, parameter search and Script measurements are local results;
neither that counting reference nor the constant-sum WOTS+ paper proves this
custom unkeyed signature. Independent host vectors are in
[`constant_composition/tests/vectors.py`](../../src/signatures/winternitz/constant_composition/tests/vectors.py).
