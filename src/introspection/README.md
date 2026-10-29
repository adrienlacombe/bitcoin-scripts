# Legacy transaction introspection

This module contains host-side research helpers for transaction-dependent
legacy Script behavior. They are not tapscript fragments and must not be
executed with the repository's default tapscript-only assumptions.

## Binohash core

`binohash::find_and_delete` removes selected serialized signature pushes only
when they occur at Script opcode boundaries. `binohash::binohash_digest` then
passes the mutated `scriptCode` to rust-bitcoin's legacy sighash implementation.
This reproduces the deterministic mutation boundary used by a Binohash-style
subset grind. A separate [funded Core fixture](../../research/binohash-legacy-core/README.md)
constructs fixed ECDSA signatures and executes two complete P2SH spends. The
proof-of-work search and digest extraction into Script remain outside this
helper.

The focused tests cover opcode-boundary deletion, subset-dependent digests,
the legacy `SIGHASH_SINGLE` bug constant, invalid selections, and invalid input
indices. The host helper alone remains `unclassified`; the separate funded
configuration is `differentially-validated` against Core v30.3 and
`consensus-validated`, but fails default relay policy.

The [nine-byte SINGLE anchor](../../research/binohash-single-anchor/README.md)
is another raw legacy P2SH fixture. A recovered public key verifies an
embedded minimum-size ECDSA signature only when input index 1 exceeds the
one-output count. Pinned Core accepts that spend and rejects adding an output
or moving the anchor to input index 0. Its checked complete-transaction
boundary is:

| P2SH scriptPubKey | RedeemScript in scriptSig | Complete spend | Easy scriptSig | Anchor scriptSig | Witness items | Hint items |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| <!-- metric:binohash_anchor_lock -->23<!-- /metric:binohash_anchor_lock --> bytes | <!-- metric:binohash_anchor_redeem -->45<!-- /metric:binohash_anchor_redeem --> bytes | <!-- metric:binohash_anchor_weight -->732<!-- /metric:binohash_anchor_weight --> WU | <!-- metric:binohash_anchor_easy_sig -->2<!-- /metric:binohash_anchor_easy_sig --> bytes | <!-- metric:binohash_anchor_main_sig -->46<!-- /metric:binohash_anchor_main_sig --> bytes | 0 | 0 |

Combined stack peak and executed opcode count were not measured. The valid
spend is consensus-valid but fails default relay policy under
`CONST_SCRIPTCODE`.
