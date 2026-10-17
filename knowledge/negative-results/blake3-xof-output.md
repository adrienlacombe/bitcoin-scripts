# BLAKE3 XOF output boundary (corrected)

**Status (2026-10-11): corrected for 64-byte output.** The short direct-u4
profile now returns the first 64 bytes of the XOF stream. This closes
[OP-024](../open-problems.md#op-024--blake3-xof-output-frontier).

The original record said that a 64-byte output needs "the additional
root-output compression". That is incorrect. A BLAKE3 compression produces 16
output words. Words 0 to 7 are `v[i] ^ v[i+8]`, the ordinary 32-byte digest.
Words 8 to 15 are `v[i+8] ^ cv[i]`, where `cv` is the root's input chaining
value. The XOF stream starts with this complete 64-byte output at counter 0.
Only bytes 64 and later need another root compression with an incremented
counter. The generator already computed `v[8..16]` and then dropped it.

In the single-block short profile, `cv` is the IV, the key, or the context key.
All of these are constants when the script is generated. The second half
therefore costs 64 constant-row XOR lookups on copies of `v[8..16]`.

| 32-byte message `00 01 ... 1f` | Compute bytes | Static non-push opcodes | Strict peak |
| --- | ---: | ---: | ---: |
| 32-byte digest, 2026-10-11 backend | 59,534 | 41,135 | 527 |
| 64-byte XOF prefix, 2026-10-11 backend | 60,131 | 41,442 | 527 |
| 32-byte digest, 2026-10-16 stack-modelled generator | 43,930 | 28,854 | 499 |
| 64-byte XOF prefix, 2026-10-16 stack-modelled generator | 44,500 | 29,134 | 499 |

Both rows use 64 checked data items, zero hints, and a peak that includes the
output verifier. The 64-byte output is 128 u4 items. Every length from 0 to 32
in all three modes matches the `blake3` crate under strict-stack execution, as
do the official 64-byte extended vectors up to 8 bytes. Evidence is
`differentially-validated`; deployment is `unclassified`.

Remaining boundaries: XOF output beyond 64 bytes is not implemented. The
multi-block limb API also lacks the 64-byte XOF prefix. There, `cv` is the
runtime chaining value from the previous block, so the generator must keep a
copy of it for the second output half.

The [XOF probe](../../examples/blake3_xof_boundary.rs) now prints both script
sizes.
