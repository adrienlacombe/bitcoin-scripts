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

The [raw sighash-byte census](../../research/binohash-sighash-flags/README.md)
independently signs all 256 flag values in P2SH spends. Its canonical `01`
sample has this complete-transaction boundary:

| P2SH scriptPubKey | RedeemScript in scriptSig | Complete spend | scriptSig | Witness items | Hint items |
| ---: | ---: | ---: | ---: | ---: | ---: |
| <!-- metric:binohash_flag_lock -->23<!-- /metric:binohash_flag_lock --> bytes | <!-- metric:binohash_flag_redeem -->35<!-- /metric:binohash_flag_redeem --> bytes | <!-- metric:binohash_flag_weight -->808<!-- /metric:binohash_flag_weight --> WU | <!-- metric:binohash_flag_scriptsig -->108<!-- /metric:binohash_flag_scriptsig --> bytes | 0 | 0 |

The sample uses a plain `OP_CHECKSIG`, without Binohash subset selection or
grinding. Stack peak and executed opcode count remain unmeasured.
