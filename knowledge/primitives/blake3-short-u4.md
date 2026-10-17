# BLAKE3 sparse direct-u4 short-input construction

## Question and comparison objective

For a BLAKE3 message length fixed at generation time and no longer than 32
bytes, minimize the locking-script fragment while keeping the combined
main/altstack peak at or below 1,000 items. Compare against the previously
checked 32-byte direct-u4 and 4-bit-limb generators on the same
`fragment-with-memory` boundary.

## Result

The 32-byte direct-u4 compute fragment is 43,930 bytes, contains 28,854 static
non-push opcodes, and peaks at 499 combined stack items including the output
verifier. It includes the exact-count check, numeric input validation, 362
bytes of lookup-table setup, compression, 183 bytes of cleanup, and digest
restoration. It excludes input serialization and the terminal digest
predicate. The script exceeds the 32 KiB optimizer cutoff, so the size is
unoptimized by the repository policy; the generator emits it directly.

The previous frontier, upstream `374d076`, measured 59,534 bytes, 41,135
static non-push opcodes and 527 items. The new fragment saves 15,604 bytes
(26.2%), 12,281 static non-push opcodes and 28 stack items. Every length from
1 to 32 bytes measures between 39,294 bytes (1 byte, previously 56,124) and
43,930 bytes; lengths 29, 30, and 31 measure 43,688, 43,768, and 43,849. The
modelled peak grows from 435 items at 1 byte to 499 at 32 bytes.

The deterministic `00 01 ... 1f` helper composition adds 64 bytes of input
pushes and 128 bytes of digest comparison, for 44,122 bytes total. Its canonical
64-item witness encoding serializes to 111 bytes; the maximum over valid
numeric nibbles is 129 bytes. There are zero hint items.

The 32-byte, 4-bit selected-limb fragment is 61,204 bytes with a 527-item peak,
so the direct profile saves 17,274 compute bytes and halves the host-push
fixture from 128 to 64 bytes.

For protocols that need only a 128-bit BLAKE3 prefix, the same schedule can
stop after output word three. The `blake3_short_compute_script_truncated_128`
profile measures 43,466 bytes and 28,614 static non-push opcodes for 32-byte
input, saving 464 bytes at the same 499-item strict composition peak. It
consumes the same 64 checked input items, so the representative witness is 111
bytes (129 bytes at the valid maximum), with zero auxiliary hint items. The
output is 32 u4 items in standard BLAKE3 little-endian byte order;
`blake3_verify_output_prefix_script` supplies the matching terminal comparison
fragment.

The fragment requires an otherwise empty main stack. Its altstack use is
balanced, so caller state parked on the altstack adds to the peak item for
item; by the exact stack model, up to 501 such items fit beside the 32-byte
fragment. That composition was not executed.

### Modes and 64-byte XOF output

`blake3_short_mode_compute_script` adds `keyed_hash`, `derive_key`, and the
first 64 bytes of the XOF stream to the same input profile. A mode changes only
the root compression's input chaining value (IV, key, or context key) and one
flag. The key and context are fixed when the script is generated. BLAKE3
requires derive-key contexts to be hardcoded, so the context phase runs on the
host and only the material phase is in Script. For 32-byte input, keyed output
is 43,915 bytes and derive-key output is 43,928 bytes, at the same 499-item
strict composition peak. The small differences come from the different
constants folded into lookup addresses. Each mode uses the same 64 checked
input items and zero hint items.

The 64-byte XOF prefix is the complete root compression output. Its second
half is `v[i+8] ^ cv[i]`, where `cv` is a generation-time constant in this
single-block profile. It needs no extra compression. It measures 44,500 bytes
(570 bytes more than the 32-byte digest) and 29,134 static non-push opcodes,
at the same 499-item peak including the 64-byte verifier. Keyed 64-byte output
measures 44,483 bytes. The output is 128 u4 items, with the first byte deepest.
Output beyond 64 bytes needs another root compression with an incremented
counter. That is not implemented.

A key fixed when the script is generated is visible to anyone who sees the
revealed leaf. Keyed mode is therefore a domain-separation or public-key MAC
tool, not a way to hide a secret key in Script.

## Construction

The construction comes from an agentic Claude Opus 5.5 run against an older
upstream revision (44,401 bytes and a 581-item peak there, as measured by
that run's harness). It was
generalized to every short length, mode and output width, and refined with a
packed XOR table, a searched G-call order and more XOR nibble orders.

- A generator ([`short.rs`](../../src/hashes/blake3/short.rs)) models the main
  and alt stacks exactly and emits opcodes directly. Constant initial-state,
  key, flag, length and padding words exist only in the generator. While
  generating, every lookup is checked to reach its intended entry, every word
  operation is checked against host arithmetic on a sample message, and the
  output is checked against a host compression.
- Check the exact item count with `OP_DEPTH`. Range-check each witness
  nibble with `DUP 0 16 WITHIN VERIFY` the first time it is fetched, before it
  is added or used as an index.
- Store addition outputs as `n + MU`: the value is directly the `OP_PICK`
  depth of a 16-entry lut that holds the depth of XOR row `n`. A dynamic XOR
  is then `PICK`, `ADD` of the other plain nibble, and `PICK`. XOR outputs and
  message nibbles are plain.
- Store carries as `q + KAPPA`, so an addition nibble sum is directly the
  depth of its 48-entry modulo entry, and `DUP PICK TUCK SUB PICK` leaves the
  result nibble and the next carry with no index arithmetic. The low nibble
  of each message word is biased by `KAPPA` once at entry, so message
  additions need no carry adjustment on their first nibble.
- A 7-bit rotation XORs each nibble, adds its top bit to the previous nibble's
  left shift with `TUCK 8 GREATERTHANOREQUAL ADD SWAP`, and looks up its own
  left shift in a 16-entry table. Rotations by 8, 12 and 16 are relabelling.
- Outside the steady state (round zero, constant operands, the output phase)
  add the exact residual offset before a lookup. Fold constant nibbles into
  these offsets; a dynamic nibble XORed with a constant indexes that
  constant's XOR row directly, and constants 0 and 15 use a copy or `15-x`.
- Pack the 16 fixed-orientation XOR rows as three pieces (86, 16 and 78
  items) of their 171-item shortest common superstring, fitted around the
  shift, lut, carry and modulo tables. Those keep their positions, so each
  steady-state shift adjustment pushes as one data byte. The table memory is
  302 items, built by a greedy encoder that copies earlier entries where that
  is shorter than a literal.
- Choose by trial at generation time: the operand fetch order of each
  addition nibble, the order of each XOR among up to 20 candidate nibble
  orders,
  the starting nibble of each 7-bit rotation, and one of two output
  strategies (outputs kept on the main stack while copying, or sent straight
  to the altstack while consuming at last use). The final XOR query consumes
  its table entry when that shortens cleanup.
- Use a fixed column and diagonal G-call order per round, selected by a
  coordinate search over the 24 orders of each phase. It is at least 168
  bytes shorter than the natural order in every one of the 288 length, mode
  and output configurations.

The 32-byte witness keeps the existing physical word and digit permutation
for compatibility; the generator accepts any fixed layout, and the natural
order measured 3 bytes shorter.

## Validation and evidence

`test_short_modes_match_reference_all_lengths_and_outputs` checks every length
from 0 to 32 in every mode at 16-, 32-, and 64-byte output against the
independent Rust `blake3` crate. Each of the 297 scripts runs on a fixed
pattern, four seeded random messages and an all-`0xff` message.
`test_short_modes_match_official_extended_vectors` checks all 27 official
hash, keyed-hash, and derive-key vectors with input length 0 to 8 against their
64-byte extended outputs, and `test_derive_key_contexts_match_reference`
covers empty, short, and 150-byte (three-block) contexts.
`test_short_direct_nibbles_all_lengths` and
`test_short_truncated_128_all_lengths` check the unkeyed digest and prefix at
every length. All of these use strict-stack execution with the 1,000-item
limit.

`test_short_rejects_malformed_witness_items_at_every_position` replaces each
witness item, in five length/mode/output configurations, with 16, -1, -15,
256, `n + 256`, a five-byte number and, for nonzero `n`, `-n`. Every case
rejects with and
without the interpreter's minimal-number rule. Missing and extra items at
either end and a wrong digest reject. Non-minimal encodings of an in-range
nibble reject under the minimal-number rule; without it, which is the
consensus behaviour in tapscript, they produce the same digest as the
canonical nibble. Mode scripts also reject another mode's digest.

`test_short_modelled_peak_matches_execution` checks that the generator's
stack model equals the executed peak, and `test_short_32_table_lifecycle_bytes`
pins the setup and cleanup byte counts. Unit tests check every table entry
after the pushes, every sum, carry, shift and XOR entry, and that the packed
pieces cover each XOR row once. A regression test checks the 32-byte digest
script as a fixed point of the BLAKE3 peephole pass; every length, mode and
output width was checked once during this change.

These results are `differentially-validated` locally. Deployment is
`unclassified`: no pinned Bitcoin Core consensus run or relay-policy
acceptance was performed. Numeric nibble bounds do not by themselves define a
protocol's raw-byte canonicality rule, and callers must bind both the generated
length choice and returned digest.

Rejected eager message expansion, active-quartet routing, alternate radices,
byte hybrids, expanded low-XOR planes, and fused add/rotate layouts are recorded
in the negative-results index. Generator variants that did not pay, including
a fully packed table and a biased output shift table, are in the
[generator negative results](../negative-results/blake3-short-generator.md).
The remaining circuit-superoptimization frontier is tracked by OP-013.

See the [implementation README](../../src/hashes/blake3/README.md), the generic
[selected-limb profile](blake3-limb29.md), and catalog record
`hash/blake3-short-u4`.
