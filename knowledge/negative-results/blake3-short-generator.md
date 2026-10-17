# BLAKE3 short-generator variants (2026-10-16)

The stack-modelled short-input generator
([`short.rs`](../../src/hashes/blake3/short.rs)) was ported onto upstream
`374d076` and then refined. This page records every measured step, including
the variants that did not pay. All rows are the unkeyed 32-byte digest of the
`fragment-with-memory` compute fragment with 64 checked u4 data items and zero
hints; the peak includes the output verifier.

Byte counts are deterministic generator measurements and are
`locally-reproduced`. The retained construction is `differentially-validated`
against the `blake3` crate (see the
[primitive page](../primitives/blake3-short-u4.md)). Rejected variants passed
the generator's own sample-message checks against host arithmetic but were
not executed against the `blake3` crate. Deployment is `unclassified`.

## Retained steps

| Step | Bytes | Peak | Change |
| --- | ---: | ---: | ---: |
| Upstream tracked-stack backend (`374d076`) | 59,534 | 527 | |
| Earlier agentic run, on older upstream `5860061`, its own harness | 44,401 | 581 | |
| Port onto `374d076`, upstream witness layout | 44,305 | 581 | -15,229 |
| XOR rows packed as superstring pieces at the old table positions | 44,205 | 499 | -100 |
| Rows relabelled by `y ^ 11`, best of the 16 relabellings | 44,167 | 499 | -38 |
| Column/diagonal G order from a coordinate search | 43,993 | 499 | -174 |
| 16 cyclic XOR nibble orders added to the 4 depth-sorted ones | 43,930 | 499 | -63 |

A second coordinate search over the G order after the last step found no
further improvement.

## Rejected variants

| Variant | Bytes | Peak | Against |
| --- | ---: | ---: | --- |
| Fully packed 295-item table: carries at 0/16/32, lut at 33, shift table at 135 | 44,646 | 492 | 44,305 (+341) |
| Natural instead of permuted 32-byte witness layout | 44,302 | 581 | 44,305 (-3) |
| Push the initial state instead of folding it into lookup offsets | 44,079 | 499 | 43,930 (+149) |
| No `KAPPA` bias on message low nibbles | 44,076 | 499 | 43,930 (+146) |
| Both of the previous two | 44,249 | 499 | 43,930 (+319) |
| Greedy nibble-by-nibble XOR order as an extra candidate | 43,930 | 499 | 43,930 (0) |
| One-operation lookahead when choosing an XOR order | 43,928 | 499 | 43,930 (-2) |
| Second shift table biased by `MU` for the round-6 diagonal 7-bit rotations | 43,914 | 515 | 43,930 (-16) |
| Best other relabelling (`y ^ 5`) after the G-order search | 43,926 | 499 | 43,930 (-4) |

- **Fully packed table.** Moving the shift table to entry 135 makes the index
  adjustment of every steady-state shift lookup exceed 127, so each pushes two
  data bytes instead of one. The 448 extra bytes outweigh the 92-byte setup
  and 44-byte output-phase savings. The retained layout keeps the shift, lut,
  carry and modulo tables at their positions and packs only the XOR rows,
  which saves 82 table items without that penalty.
- **Materialized state and unbiased message.** Neither variant was shorter in
  any of the 96 unkeyed length and output-width configurations, so the
  generator no longer tries them.
- **Natural witness layout.** The 3-byte gain does not justify a witness
  layout change for existing callers.
- **Greedy and lookahead XOR orders.** The greedy order was never better than
  the existing candidates. One-operation lookahead saved 2 bytes for about
  three times the generation time.
- **Biased round-6 shift table.** It makes the final `b` words addition-biased,
  so 32 output XORs need no bias adjustment, but its 16 table items, their
  setup and cleanup, and one-byte-longer adjustments in those rotations leave
  16 bytes of gain for 16 more peak items. Not adopted.

## Where the bytes remain

An instrumented run of the 43,993-byte step attributed about 19.7 kB to
operand fetches and 3.3 kB to index adjustments; the rest is per-nibble
lookup and arithmetic opcodes, 362 bytes of table setup and about 1.1 kB of
output phase and cleanup. Most fetches are 3-byte `OP_ROLL`s of state nibbles
at depths 25 to 127 and 2-byte `OP_PICK`s of fresh operands; message nibbles
below the tables cost 4 bytes. Few rolls sit just above the 16-item
one-byte-push boundary, so local reordering has little left to gain. The
largest adjustments are the one-byte-data shift lookups of the 7-bit
rotations and the `KAPPA` carry bias on the first nibble of additions without
a message word. These attributions are `locally-reproduced` for that build;
they are not lower bounds. See
[OP-013](../open-problems.md#op-013--blake3-circuit-superoptimization-frontier).
