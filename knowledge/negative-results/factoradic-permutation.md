# NR-075: Packed permutation ranks lose combined bytes

The hint-free ScriptNum factoradic decoder has a clear witness/item advantage,
but no total-byte advantage over a separately encoded Lehmer-digit witness in
the measured configurations.

| Width | Packed script + data witness | Digit script + data witness | Packed / digit peak | Packed / digit executed non-push ops |
| --- | ---: | ---: | ---: | ---: |
| 4 | 102 + 3 = 105 | 57 + 7 = 64 | 8 / 10 | 70 / 37 |
| 8 | 312 + 5 = 317 | 129 + 15 = 144 | 12 / 18 | 178 / 85 |
| 12 | 633 + 6 = 639 | 201 + 23 = 224 | 16 / 26 | 302 / 133 |

Equal `complete-leaf:` boundaries include canonical/range checks, public pool
setup and removal, descending-permutation output comparisons, and clean truthy
success. Both exclude input pushes and transaction framing. All witness items
are present at entry; packed uses 1 data item, digits use 3/7/11, and both use
**0 hints**. Data-witness byte serialization includes count and length prefixes.
Both are optimized under the repository policy.

Evidence: `locally-reproduced`. Execution: `unclassified`, local tapscript,
strict combined stack enforcement, global minimal-data disabled. See the
[README](../../src/arithmetic/permutation/README.md) for resolved dependency
commits and deterministic commands. Static and executed opcodes are separate.

The experiment is retained because its lower stack peak may matter in a future
consumer with tightly constrained live state. The present rows neither establish
that consumer nor prove an optimum or impossibility for another decoder.
The existing fixed-composition signature encoder has different semantics and
performs its rank mapping off chain; these small-alphabet numbers cannot be
extrapolated to its 49-key multiset domain. [OP-032](../open-problems.md#op-032--permutation-decoding-consumer-frontier)
requires a falsifiable composed comparison.
