# BLAKE3 keyed-mode boundary (retracted)

**Status (2026-10-11): retracted.** Keyed mode is implemented for the short
direct-u4 profile and closes
[OP-028](../open-problems.md#op-028--blake3-keyed-mode-frontier).

The original record said that the local BLAKE3 generators expose no key input
or `KEYED_HASH` flag. It said that support would need new pricing for the
key's eight words, the flags, the witness shape, and stack routing. The first
part was a correct description of the API. The second part overstated the
cost. BLAKE3 keyed mode changes only the root compression's input chaining
value, from the IV to the key words, and adds flag `KEYED_HASH` (16). With a
key fixed when the script is generated, the key words fold into the same
constant-addressed first-round lookups as the IV. The witness shape, hint
count, and stack schedule do not change.

Measured on the 32-byte message `00 01 ... 1f` with the official test-vector
key: keyed hashing is 59,532 compute bytes versus 59,534 unkeyed, with 41,135
static non-push opcodes in both. The size depends on the key: the probe's
all-`0x42` key gives 59,557 bytes. Constant nibbles 0 and 15 skip a lookup,
and ScriptNum offset widths change with the key. Both have a 527-item strict composition peak,
64 checked data items, and zero hints. All 27 official mode vectors up to 8
bytes, plus every length up to 32 against the `blake3` crate, match under
strict-stack execution. Evidence is `differentially-validated`; deployment is
`unclassified`. See [the primitive page](../primitives/blake3-short-u4.md).

Remeasured on 2026-10-16 with the stack-modelled short generator: keyed
hashing is 43,915 bytes with the official key and 43,904 bytes with the
all-`0x42` key, versus 43,930 unkeyed, all at a 499-item strict peak.

A key supplied in the witness is still not implemented. It would use the
existing runtime chaining-value path, the one the generic backend uses for
non-first blocks, plus 64 range-checked key nibbles. A key fixed when the
script is generated is public to anyone who sees the revealed leaf.

The [keyed probe](../../examples/blake3_keyed_boundary.rs) now prints the
implemented keyed digest size beside the unkeyed size.
