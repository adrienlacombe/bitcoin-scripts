# Checked u4 most-significant-bit projection

`arithmetic::u4::msb::u4_nibbles_to_msb` range-checks each numeric nibble and
replaces it with the bit `nibble >= 8`. Each nibble uses one
`OP_DUP 0 16 OP_WITHIN OP_VERIFY` range check, then `8 OP_GREATERTHANOREQUAL`
consumes the original. It uses no lookup table.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top; every nibble must be in `0..=15`.
- **Output:** `preserved | msb[0] | ... | msb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by boundary, malformed-input, and strict
  stack-frontier tests plus a metric fixture.
- **Representative result:** 286 locking-script bytes, 65 serialized witness
  bytes, 35 combined stack items, 190 static non-push opcodes, and zero hint
  items for 32 checked nibbles. All 32 data items coexist at entry. This is not an executed-opcode or deployment claim.
- **Execution class:** `unclassified`; the local strict executor uses
  tapscript context and the combined stack limit, not Bitcoin Core consensus
  or relay-policy validation.

The standalone schedule peaks at `n + 3` items: the nibble, its copy, and
the two `OP_WITHIN` bounds. It accepts `1..=997`; callers must reduce the width for unrelated live main- or alt-stack
state. Numeric range checking does not establish canonical or byte-unique
ScriptNum encodings, and this projection is not a complete locking script:
callers still need a terminal predicate and any required clean-stack binding.

## Schedule comparison

All rows are `n = 32`, measured on the same fragment-only boundary with the
same 32-item witness (65 bytes) and zero hints:

| Schedule | Script bytes | Strict peak |
| --- | ---: | ---: |
| Former 16-entry lookup table | 440 | 50 |
| Two compare-and-`VERIFY` checks, then `DUP 8 GTE TOALT DROP` | 446 | 34 |
| Same checks, consuming the nibble without `DUP`/`DROP` | 382 | 34 |
| `DUP 0 16 WITHIN VERIFY 8 GTE TOALT` (retained) | 286 | 35 |

The retained schedule uses 160 fewer bytes than the former threshold, and 154
fewer than the lookup with 15 fewer peak items. The 382-byte variant is the
byte minimum found that keeps the `n + 2` peak, for callers short of one stack
item. The pinned optimizer did not apply either rewrite to the former
schedule. Rows two and three come from a one-off measurement with
`execute_script_with_inputs_strict` and are not kept as a fixture, so they are
`inspected` evidence. The retained row is `locally-reproduced` by the metric
test.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-msb`.
