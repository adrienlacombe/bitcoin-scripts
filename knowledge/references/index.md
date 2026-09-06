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
