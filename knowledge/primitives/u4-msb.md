# Checked u4 most-significant-bit projection

`arithmetic::u4::msb::u4_nibbles_to_msb` range-checks each numeric nibble and
replaces it with the bit `nibble >= 8`. Nibbles are range-checked in groups
of up to three: copy the group, fold it with `OP_MAX` and require the maximum
below 16, then copy it again, fold it with `OP_MIN` and require the minimum to
be non-negative. While at least 16 batch items remain on the main stack, the
lower bound is `OP_PICK OP_DROP`: any index in `0..=15` reaches a batch item
and a negative index fails. Then `8 OP_GREATERTHANOREQUAL` consumes each
nibble. A small dynamic program chooses the group widths. It uses no lookup
table.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top; every nibble must be in `0..=15`.
- **Output:** `preserved | msb[0] | ... | msb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by boundary, malformed-input, and strict
  stack-frontier tests plus a metric fixture.
- **Representative result:** 250 locking-script bytes, 65 serialized witness
  bytes, 35 combined stack items, 202 static non-push opcodes, and zero hint
  items for 32 checked nibbles. All 32 data items coexist at entry. This is not an executed-opcode or deployment claim.
- **Execution class:** `unclassified`; the local strict executor uses
  tapscript context and the combined stack limit, not Bitcoin Core consensus
  or relay-policy validation.

Batches of up to 995 nibbles use three-nibble groups and peak at `n + 3`
items (the batch plus a group's copies); batches of 996 to 998 use two-nibble
groups and peak at `n + 2`. It accepts `1..=998`; callers must reduce the
width for unrelated live main- or alt-stack state. Numeric range checking does not establish canonical or byte-unique
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
| `DUP 0 16 WITHIN VERIFY 8 GTE TOALT` per nibble | 286 | 35 |
| Two-nibble groups (`2DUP MAX`, `2DUP MIN`) | 277 | 34 |
| Three-nibble groups (`3DUP MAX MAX`, `3DUP MIN MIN`) (retained) | 250 | 35 |

The retained schedule uses 196 fewer bytes than the former threshold, and 190
fewer than the lookup with 15 fewer peak items. It has 202 static non-push
opcodes, 12 more than the per-nibble `OP_WITHIN` schedule. The two-nibble
variant is the smallest found that keeps the `n + 2` peak, for callers short of
one stack item; the implementation uses it only above 995 nibbles. The pinned
optimizer did not apply any of these rewrites to the former schedule. Rows
two, three, four and five come from one-off measurements with
`execute_script_with_inputs_strict` and are not kept as a fixture, so they are
`inspected` evidence. The retained row is `locally-reproduced` by the metric
test.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-msb`.
