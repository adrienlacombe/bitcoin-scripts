# Fixed-width u4 lexicographic comparison

`arithmetic::u4::compare::lexicographic_le` compares two equal-width,
big-endian u4 vectors and returns whether `left <= right`. It range-checks all
hostile input nibbles before looking at the first differing position, consumes
both vectors, and leaves one truthy/falsy result. The primitive is useful for
Taproot node ordering and other fixed-width byte-domain commitments.

## Contract

For `n > 0`:

```text
left[0] ... left[n-1] right[0] ... right[n-1] -> result
```

Each input is one numeric nibble in `0..=15`, ordered most-significant first.
The result is true for equality and for the first differing nibble being lower
on the left. The implementation uses no witness hints; the `2*n` data items
all coexist at script entry.

The range check establishes numeric nibble validity. It does not establish a
unique raw ScriptNum byte encoding under consensus; callers that need byte
canonicality must use a separately specified policy or encoding boundary.

`lexicographic_le_constant(constant)` keeps the left vector as hostile witness
data and embeds the right vector at generation time. The constant must be a
nonempty slice of numeric u4 nibbles; invalid generation-time values panic.
This removes the right vector from the witness while retaining the same
range-checking and first-difference logic.

## Measurement

The representative `n=128` fragment includes all numeric range checks, the
first-difference state machine, operand cleanup, and a complete 256-item empty
nibble witness. It excludes any surrounding hash, terminal predicate, or
transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Two 128-nibble vectors | 7,500 bytes | 259 bytes | 256 | 0 (none) | 259 | 4,354 |
| One 128-nibble vector plus embedded right vector | 7,628 bytes | 257 bytes | 128 | 0 (none) | 259 | 4,354 |

The strict local executor enforces the combined 1,000-item stack limit for the
measurement. Deployment remains `unclassified`: the fragment is below the
10,000-byte script-size ceiling but has more than 201 non-push opcodes and has
not been differentially validated against Bitcoin Core.

For the all-`0x0f` representative, the fixed-right form uses 257 serialized
witness bytes for one vector versus 513 bytes for two vectors, removing 128
entry items and 256 witness bytes for 128 additional locking bytes. The
embedded vector is still pushed before the comparison, so the attained strict
peak remains 259 items.

## Validation

The focused test exhaustively checks all `256 × 256` two-nibble byte pairs,
rejects an out-of-range nibble, and rejects zero-width generation. Run:

```sh
cargo test --locked arithmetic::u4::compare::tests::compares_against_embedded_constant --lib
cargo test --locked arithmetic::u4::compare::tests::preserves_surrounding_main_and_alt_stack_items --lib
cargo test --locked arithmetic::u4::compare::tests::rejects_out_of_range_constant --lib
cargo test --locked --test primitive_metrics u4_lexicographic_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```
