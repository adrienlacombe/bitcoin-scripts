# Canonical reflection-constrained u4 witnesses

Question: can a constrained vector enter Script as only its first half and
reconstruct the omitted half, while improving locking/data-witness bytes and
entry item count over a full-vector symmetry verifier? The hypothesis is that
canonical validation of half the inputs plus fixed-index copies costs less than
validating a full vector and separately comparing mirrored pairs.

The [implementation](../../src/arithmetic/u4/README.md#canonical-reflection-witnesses)
provides equal reflection (palindromes) and complement reflection (mirrored
symbols sum to 15). Its public width is 1..996; complement reflection is even-only.
Inputs are hostile raw ScriptNums; all must be canonical nibbles before copying.
The omitted half has no independent witness choices or hints. Both encodings
return the same vector, with the last coordinate on top, preserve caller state,
and require a consumer and terminal predicate.

Equal width 32 measures 309 script bytes + 32 serialized data-witness bytes,
16 data items, 0 hints, a 33-item combined peak and 192 executed non-push
opcodes. Full-vector verification measures 588 + 63 bytes, 32 data items, 0
hints, a 36-item peak and 368 executed opcodes. Complement width 32 is 357 + 32
versus 620 + 63, with the same item counts/peaks and 224 versus 384 opcodes.
Odd equal width 33 is also measured. All share `complete-leaf:` canonical/range
checks, symmetry enforcement or expansion, exact output comparisons and clean
truthy success. Input pushes, transaction framing and unrelated state are
excluded; data serialization includes counts and length prefixes. Fixtures use
`h[i]=(7*i+3)%16`, not an all-nonzero maximum-size vector.

The result improves measured bytes and entry items **within this restricted
domain**. It does not compress arbitrary state, authenticate data, prove any
polynomial irreducible, or interpret u4 automatically as a field. Equal reflection
can describe palindromic coefficient vectors, as in the primary reference;
that interpretation supplies no cryptographic security for this adapter.

Evidence: `locally-reproduced`. Execution: `unclassified`; local tapscript,
strict combined stack checks, global minimal-data disabled and explicit fragment
canonicality. The metric test prints compiler/interpreter identities from its
embedded lockfile. Its final optimized leaves remain distinct from Core or
relay-policy validation. The README reports P2SH and static-opcode limitations.

Correctness tests independently define every output coordinate, exhaust one/two
symbol halves, mutate raw witness encodings without relying on output equality,
reject broken pairs and odd complement widths, and exercise the common maximum
width. Exact stack frontiers include preserved **runtime** main/alt items; a
constant altstack marker can optimize away and is not valid occupancy evidence.

[NR-076](../negative-results/index.md#nr-076-odd-nibble-complement-reflection-has-no-center)
records the non-composable odd complement domain. [OP-033](../open-problems.md#op-033--reflection-witness-consumer-frontier)
requires a measured real consumer before a protocol-level claim.

Provenance: [Gao, arXiv:2109.09006v1](https://arxiv.org/abs/2109.09006v1),
2021-09-18, for the palindromic coefficient definition. Stack scheduling,
canonical witness enforcement, complement rule and Script costs are local results.
