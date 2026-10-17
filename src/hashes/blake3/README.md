# BLAKE3

BLAKE3 hashing in tapscript. The selected-limb profile and the experimental
Ed25519 transcripts use tracked-stack u4/bigint machinery; their compute
scripts are run through the pinned `bitcoin-script-stack` peephole optimizer
plus two locally proved stack-identity rewrites to a fixed point. The short
direct-u4 profile uses a separate stack-modelled generator
([`short.rs`](short.rs)) that emits its script directly; the same peephole
pass is a checked fixed point of its output.

Two input profiles are public:

- `blake3_short_compute_script` is the script-minimized profile for a
  witness-backed message of `0..=32` bytes. It consumes exactly two numeric u4
  items per byte and synthesizes all padding internally.
- `blake3_compute_script_with_limb` supports `0..=1024` bytes with two
  selected-limb 256-bit groups per block. Limb width is `4..=31`; the
  compatibility wrapper uses 29-bit limbs.
- `blake3_short_compute_script_truncated_128` is the short-input direct-u4
  profile when only the first 128 output bits are needed.

- `blake3_short_mode_compute_script` generalizes the short profile to all
  three BLAKE3 modes (`Hash`, `KeyedHash`, `DeriveKey`) and 16-, 32-, or
  64-byte outputs.

The limb-API profile implements unkeyed BLAKE3 with the standard 32-byte
output. The short profile also supports keyed hashing, derive-key, and the
first 64 bytes of the XOF stream. The multi-chunk tree API and XOF output
beyond 64 bytes are not implemented; see the
[tree boundary](../../../knowledge/negative-results/blake3-tree-composition.md).

The experimental `ed25519_challenge` module also exposes custom-signature
transcript shapes. These are not stable hash APIs and do not implement RFC
8032 Ed25519:

These experimental generators now use only the repository's centralized
compilation policy. In particular, wrappers larger than 32 KiB receive
`CompileOptions::NONE` and do not run a second fixed-point optimizer pass after
`compile_with_policy()`.
They build on the tracked-stack compression of the selected-limb profile
(64-byte blocks, preserved caller prefixes), not on the short-input generator
described below, and their scripts are unchanged by it.

| Experimental transcript | Script bytes | Data items | Hint items | Peak/bound |
| --- | ---: | ---: | ---: | ---: |
| `BLAKE3(R32 || A32 || M32)` | 125,687 | 192 checked u4 | 0 | <=655 |
| `BLAKE3(D32 || A32 || R32 || M32)`, fixed `D32,A32` | 65,208 | 128 checked u4 | 0 | <=591 |
| low 128 bits of fixed-`D32,A32` form | 64,760 | 128 checked u4 | 0 | <=591 |
| low 128 bits, caller-certified u4 input | 63,764 | 128 certified u4 | 0 | <=591 |
| caller-certified input with 337 H16 items preserved | 65,123 | 128 certified u4 + 337 preserved | 0 | 928 combined |
| fixed-`M32` binder + specialized low-128 hash at the H16 frontier | 64,118 | 128 certified u4 + 337 preserved at entry; 64 u4 + 337 after binding | 0 | 864 combined |
| fixed-`M32` hash copied from later-certified packed R | 67,806 | 297 preserved items, including 8 packed R words | 0 | 824 combined |
| fixed-`M32` hash from canonical-u5 R | 67,137 | 391 preserved items, including 51 R digits | 0 | 918 combined |

The second form precomputes the non-root chaining value for the fixed first
block and runs only the final `CHUNK_END|ROOT` compression in Script. A
deterministic host-only test matches the ordinary unkeyed BLAKE3 digest of the
complete 128-byte transcript. Runtime `R` digits must be bound to the same
canonical point encoding used by the curve
equation, and runtime `M32` digits to the intended message source. Both forms
use exactly zero auxiliary witness-hint items.

`key_specialized_compute_script_preserving_truncated_128` omits the four
unused root-output words for a 128-bit challenge schedule. It saves 448 script
bytes and returns 32 rather than 64 u4 items. It is truncation of ordinary
BLAKE3 output, not a different compression function. The generated Script was
not executed, so this row has the same `inspected`/`unclassified` boundary.
The caller-certified variant saves another 996 bytes by relying on a preceding
carrier decoder to prove every transcript item is in `0..16`; using it on raw
witness items would be unsound.

The 337-item preserving instantiation is the exact H16 slope-chain hash
frontier: 288 future packet items, a 41-item current state, and eight packed
`Rtilde` words remain live below the 128 transcript nibbles. The previously
reported 63,766-byte generator was not executable with a prefix:
the packed-XOR backend's `OP_DEPTH` addressing requires its 330 lookup-table
items at the bottom of the main stack. Correctly parking and restoring the 337
preserved items around table construction and cleanup makes the variable-`M32`
hash 65,123 bytes. A strict focused execution reaches 928 combined items.

For the linked constant `M32`, a 128-byte binder instead verifies and consumes
the 64 hostile message nibbles. The specialized compressor folds those eight
fixed words into its addition-table addresses, so its hash frontier is only
337 preserved items plus 64 `R32` nibbles. Binder plus hash is 64,118 bytes
(128 + 63,990) and reaches 864 combined items in a strict focused execution.
The fixture
matches the standard `blake3` crate's low 128 output bits, preserves exact
prefix/`R` order, and rejects malformed, reordered, or extra input. It uses
zero hint items. Applying the policy-only hash delta to the generation-only
H16 component account projects a 3,828,057-byte leaf with
792 entry items (88 hints and 704 trace-data items, all coexisting) and a
strict peak-equivalent schedule of 999. The multi-megabyte leaf itself has not
been executed.

The separate G29 q-free H16 schedule has no transcript carriers. At its hash
boundary, 256 challenge-trace items and the 41-item current state remain. The
67,806-byte helper deep-copies the eight packed R words at word-zero depth 289,
derives their 64 u4 items, hashes the fixed message, and preserves all 297
original items. A focused strict execution peaks at 824, matches host BLAKE3,
preserves the prefix byte-for-byte, and rejects extra input. Packed-word
canonicality is intentionally supplied later by the final derived slope
transition over those untouched originals; omitting that later certification
would be unsound. This boundary has exactly zero hint items. It is composed in
the policy-corrected additive 3,896,335-byte q-free projection, whose 712 entry
data items also contain zero hints and whose analytical arithmetic frontier is
912. The multi-megabyte leaf was not executed.

The G32 hybrid-u5 helper receives 391 preserved items: the 51 canonical
radix-32 `Rtilde` digits, the remaining fifteen challenge packets, and the
92-item current state. Its 2,931-byte converter copies and packs R into 64 u4
items while checking every digit and rejecting the 19-value noncanonical gap;
the fixed-message BLAKE3 body is 64,206 bytes. The 67,137-byte pair contains
45,452 static non-push opcodes, preserves all original items byte-for-byte,
returns 32 digest nibbles, uses exactly zero hint items, and strict-peaks at
918. A focused fixture matches host BLAKE3 and
rejects an out-of-range digit, the first gap encoding, and extra input. The
original 51 R digits remain available for the terminal slope relation.
Together with the fifteen-item first-kernel pool and partial-word decoding,
it gives a 2,834,653-byte
generation-only G32 leaf. That leaf has
803 coexisting entry-data items, zero hints across all 47 transitions, and an
analytical combined-stack maximum of 995. Its multi-megabyte Script
has not been executed, and fixed `M32` is not transaction authorization.

`key_specialized_compute_script_preserving` exposes the same one-compression
construction while preserving a caller-selected main-stack prefix. Preserved
prefixes must use the same table-below-prefix staging described above; older
size projections that counted only a deeper exact-depth constant are invalid.
A separate inspected carrier model stores the 64 runtime transcript bytes in
existing signed-23-bit quotient items, leaving the G29 entry at 764 items; that
composed metric has intentionally not been run.

## Short-input specialization

The short profile is generated by [`short.rs`](short.rs). The construction
comes from an agentic Claude Opus 5.5 run and was generalized here to every
length from 1 to 32 bytes, all three modes and 16-, 32- and 64-byte output.
The generator models the main and alt stacks exactly and emits opcodes
directly. Its value representations make most lookup indexes free:

- Addition outputs (`A` nibbles) are stored as `n + MU`. That value is
  directly the `OP_PICK` depth of a 16-entry lut whose entries hold the depth
  of XOR row `n`, so an XOR is `PICK`, `ADD` of the other plain nibble, and
  `PICK`.
- XOR outputs and message nibbles are plain. Carries are stored as
  `q + KAPPA`, so the sum of two or three operand nibbles and a carry is
  directly the depth of its modulo entry. `DUP PICK TUCK SUB PICK` then leaves
  the result nibble and the next carry. The low nibble of every message word
  is biased by `KAPPA` once, so a message addition needs no carry adjustment
  on its first nibble.
- A 7-bit rotation XORs each nibble, adds its top bit (`8 GREATERTHANOREQUAL`)
  to the previous nibble's left shift, and looks up its own left shift in a
  16-entry table.

Wherever the stack is not in that steady state (round zero, constant operands
and the output phase), the generator adds the exact residual offset before
the lookup. Initial-state, key and padding words are constants at generation
time and are folded into these offsets; a dynamic nibble XORed with a constant
indexes that constant's XOR row directly. Absent message words are omitted.
While generating, every lookup is checked to reach the intended entry, every
word operation is checked against host arithmetic for a sample message, and
the output is checked against a host compression.

The lookup memory is 302 items: the shift table, the lut, three carry entries,
the 48-entry modulo table, and the 16 XOR rows packed as three pieces of their
171-item shortest common superstring (180 items including the two splits).
The shift, lut, carry and modulo positions keep every steady-state shift
adjustment below 128, so it pushes as one data byte. A greedy encoder pushes
the tables, copying earlier entries where that is shorter than a literal.

Some choices are made at generation time by trial: the operand order of each
addition nibble by modelled fetch cost, the nibble order of each XOR among up
to 20 candidate orders, the starting nibble of each 7-bit rotation, and one of
two output strategies. The column and diagonal G-call order of each round is
fixed; a coordinate search over the 24 orders of each phase selected it, and
it is at least 168 bytes shorter than the natural order for every length,
mode and output width. The final XOR query
consumes its table entry when that shortens the cleanup.

These are generator transformations: they do not change BLAKE3's seven-round
compression function or remove validation from witness-backed digits.
Measured alternatives that did not pay are recorded in the
[generator negative results](../../../knowledge/negative-results/blake3-short-generator.md).

## Script metrics

The compute metrics are `fragment-with-memory`. They include input range
validation and any representation conversion, lookup-table setup, hashing,
table cleanup, and digest restoration. Metrics exclude input pushes or witness
serialization and digest comparison.

For the short profile, the generator reports the byte ranges it emits for
table setup and cleanup, and `test_short_32_table_lifecycle_bytes` pins them
at 32 bytes. Setup is 362 bytes. Cleanup drops the tables and any leftover
state below the outputs: 183 bytes for the 32-byte digest and 199 bytes for
the 128-bit prefix.

The selected-limb profile's tables use 353 bytes of setup and 166 bytes of
cleanup. Those costs are measured as independent fragments. Compiling unused
setup immediately followed by cleanup allows optimizer cancellation;
subtracting the standalone setup size from that result is not a cleanup cost.
The lifecycle regression test declares the table input layout and compiles
the actual cleanup method independently.

| Configuration | Compute script |
| --- | ---: |
| Empty message, 29-bit API | <!-- metric:blake3_empty_limb29 -->64<!-- /metric:blake3_empty_limb29 --> bytes |
| 1 byte, direct checked u4 | <!-- metric:blake3_short_1 -->39294<!-- /metric:blake3_short_1 --> bytes |
| 32 bytes, direct checked u4 | <!-- metric:blake3_short_32 -->43930<!-- /metric:blake3_short_32 --> bytes |
| 32 bytes, direct checked u4, low 128 bits | <!-- metric:blake3_short_truncated_128_32 -->43466<!-- /metric:blake3_short_truncated_128_32 --> bytes |
| 32 bytes, selected 4-bit limbs | <!-- metric:blake3_32_limb4 -->61204<!-- /metric:blake3_32_limb4 --> bytes |
| 64 bytes, 4-bit limbs | <!-- metric:blake3_64_limb4 -->64095<!-- /metric:blake3_64_limb4 --> bytes |
| 64 bytes, 29-bit limbs | <!-- metric:blake3_64_limb29 -->72293<!-- /metric:blake3_64_limb29 --> bytes |

Every nontrivial row in this table exceeds the repository optimizer's 32 KiB
input cutoff, so the policy applies no upstream rewrite passes. The limb rows
receive the BLAKE3-specific fixed-point pass; the short rows are emitted
directly by their generator.

For the deterministic 32-byte message `00 01 ... 1f`, direct host-side message
pushes are <!-- metric:blake3_push_short_32 -->64<!-- /metric:blake3_push_short_32 -->
bytes. The push, compute fragment, and 128-byte digest comparison compose to
<!-- metric:blake3_complete_short_32 -->44122<!-- /metric:blake3_complete_short_32 -->
bytes. Encoding the same nibbles as canonical witness items takes
<!-- metric:blake3_witness_short_32 -->111<!-- /metric:blake3_witness_short_32 -->
serialized bytes; the valid 64-item maximum is
<!-- metric:blake3_witness_short_32_max -->129<!-- /metric:blake3_witness_short_32_max -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_short_32 -->28854<!-- /metric:blake3_opcodes_short_32 -->
static non-push opcodes, and the executable composition peaks at
<!-- metric:blake3_stack_short_32 -->499<!-- /metric:blake3_stack_short_32 -->
combined main/altstack items.

The corresponding 32-byte selected-limb helper composition peaks at
<!-- metric:blake3_stack_32_limb4 -->527<!-- /metric:blake3_stack_32_limb4 -->
items. Against the 61,204-byte 4-bit selected-limb fragment, direct u4 saves
17,274 compute bytes and uses 64 rather than 128 host-push bytes.

Before the stack-modelled generator (upstream `374d076`), the same metrics
were 59,534 compute bytes, 41,135 static non-push opcodes and a 527-item peak
at 32 bytes, and 56,124 bytes at 1 byte. Every message length from 1 to 32
now measures between 39,294 and 43,930 bytes. The generator's stack model
gives a peak between 435 items at 1 byte and 499 at 32 bytes; the model
matches strict execution in every configuration that
`test_short_modelled_peak_matches_execution` runs.

The fragment requires an otherwise empty main stack, and its peak includes
the 64 input items. Its altstack use is balanced, so caller state parked on
the altstack adds to the peak item for item. By the exact model, at most 501
such items can coexist with the 32-byte fragment; that composition was not
executed.

`blake3_short_compute_script_truncated_128` runs the same checked short-input
compression but materializes only the first four output words. It is useful for
protocols that commit to a 128-bit BLAKE3 prefix; the output uses the standard
little-endian byte order and contains 32 u4 items. The 32-byte profile's
truncated compute fragment is
<!-- metric:blake3_short_truncated_128_32_compute -->43466<!-- /metric:blake3_short_truncated_128_32_compute --> bytes, with
<!-- metric:blake3_short_truncated_128_32_opcodes -->28614<!-- /metric:blake3_short_truncated_128_32_opcodes --> static non-push opcodes and a strict
composition peak of
<!-- metric:blake3_short_truncated_128_32_stack -->499<!-- /metric:blake3_short_truncated_128_32_stack --> items including the prefix verifier. It saves
464 compute bytes versus the full 32-byte output at the same
64-item checked input boundary. The empty-message specialization rejects
extra stack input and returns the first 16 bytes of the standard empty digest.

### Modes and 64-byte XOF output

A BLAKE3 mode changes only the root compression's input chaining value and
one flag. Unkeyed hashing starts from the IV. `keyed_hash` starts from the key
words with `KEYED_HASH`. `derive_key` starts from the context key with
`DERIVE_KEY_MATERIAL`. The key and context are fixed when the script is
generated. BLAKE3 requires the derive-key context to be a hardcoded string.
`Blake3Mode::derive_key` therefore computes the context phase on the host,
for a context of at most 1,024 bytes. The generator folds the chaining value
into the same constant-addressed first-round lookups that it uses for the IV.
No mode adds witness items, hint items, or compressions.

The first 64 bytes of the XOF stream are the complete root compression
output. Bytes 0 to 31 are `v[i] ^ v[i + 8]`, the ordinary digest. Bytes 32 to
63 are `v[i + 8] ^ cv[i]`. In this single-block profile, `cv` is the
generation-time chaining value. The 64-byte output therefore needs no
additional compression: it adds 64 constant-row XOR lookups, 570 bytes at 32
bytes. The generator copies each `v[i + 8]` nibble until its last use, which
consumes it. The output is 128 u4 items, with the first byte deepest. XOF output beyond 64 bytes needs another root compression with an
incremented counter. That is not implemented.

For the 32-byte message `00 01 ... 1f`, with zero hint items and 64 checked
u4 data items all present at entry:

| 32-byte message | Compute script | Static non-push opcodes | Strict peak with verifier |
| --- | ---: | ---: | ---: |
| Unkeyed, 32-byte output | `blake3_short_32` above | `blake3_opcodes_short_32` above | `blake3_stack_short_32` above |
| Keyed, 32-byte output | <!-- metric:blake3_short_keyed_32 -->43915<!-- /metric:blake3_short_keyed_32 --> bytes | <!-- metric:blake3_short_keyed_32_opcodes -->28855<!-- /metric:blake3_short_keyed_32_opcodes --> | <!-- metric:blake3_short_keyed_32_stack -->499<!-- /metric:blake3_short_keyed_32_stack --> |
| Derive-key, 32-byte output | <!-- metric:blake3_short_derive_key_32 -->43928<!-- /metric:blake3_short_derive_key_32 --> bytes | <!-- metric:blake3_short_derive_key_32_opcodes -->28856<!-- /metric:blake3_short_derive_key_32_opcodes --> | <!-- metric:blake3_short_derive_key_32_stack -->499<!-- /metric:blake3_short_derive_key_32_stack --> |
| Unkeyed, 64-byte XOF | <!-- metric:blake3_short_xof64_32 -->44500<!-- /metric:blake3_short_xof64_32 --> bytes | <!-- metric:blake3_short_xof64_32_opcodes -->29134<!-- /metric:blake3_short_xof64_32_opcodes --> | <!-- metric:blake3_short_xof64_32_stack -->499<!-- /metric:blake3_short_xof64_32_stack --> |
| Keyed, 64-byte XOF | <!-- metric:blake3_short_keyed_xof64_32 -->44483<!-- /metric:blake3_short_keyed_xof64_32 --> bytes | <!-- metric:blake3_short_keyed_xof64_32_opcodes -->29135<!-- /metric:blake3_short_keyed_xof64_32_opcodes --> | <!-- metric:blake3_short_keyed_xof64_32_stack -->499<!-- /metric:blake3_short_keyed_xof64_32_stack --> |

Key-dependent byte differences come from the constant-folded lookup offsets
and ScriptNum widths. The key is embedded in the script, so treat a
revealed keyed leaf as disclosing its key. Use keyed mode for domain
separation, or for MAC checks only when the key may be public at spend
time.

`test_short_modes_match_official_extended_vectors` checks all 27 official
mode vectors with input length 0 to 8 against their 64-byte extended outputs.
`test_short_modes_match_reference_all_lengths_and_outputs` checks every
length from 0 to 32, every mode, and 16-, 32-, and 64-byte outputs against the
independent `blake3` crate, each on a fixed pattern, four seeded random
messages and an all-`0xff` message. Both tests use strict-stack tapscript
execution with witness inputs.
`test_short_rejects_malformed_witness_items_at_every_position` replaces every
witness position in five length/mode/output configurations with 16, -1, -15,
256, `n + 256`, a five-byte number and, for nonzero `n`, `-n`; all reject,
with and without the interpreter's minimal-number rule. Missing and extra
items at either end, a wrong digest, and another mode's digest reject.
Non-minimal encodings of an in-range nibble (`[n, 0x00]`, and `[0x00]` or
`[0x80]` for zero) reject under the minimal-number rule. Consensus alone does
not require minimal numbers in tapscript; without that rule the same test
shows that these encodings produce the same digest as the canonical nibble.
Evidence is `differentially-validated` against the `blake3` crate for the
fragment boundary. Deployment is `unclassified`: no Bitcoin Core comparison
was made.

For the deterministic 64-byte message `00 01 ... 3f`, host-side 29-bit message
packing is <!-- metric:blake3_push_64_limb29 -->87<!-- /metric:blake3_push_64_limb29 -->
bytes and digest comparison is
<!-- metric:blake3_verify_output -->128<!-- /metric:blake3_verify_output -->
bytes. Their executable composition with the 64-byte compute fragment is
<!-- metric:blake3_complete_64_limb29 -->72508<!-- /metric:blake3_complete_64_limb29 -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_64_limb29 -->47567<!-- /metric:blake3_opcodes_64_limb29 -->
static non-push opcodes; the composition peaks at
<!-- metric:blake3_stack_64_limb29 -->591<!-- /metric:blake3_stack_64_limb29 -->
items.

The helper compositions embed messages and expected digests in the script;
they are deterministic regression fixtures rather than proof-boundary cost
claims. The local strict-stack test executes every direct-input length from 0
through 32 and enforces the 1,000-item limit. This is not a Bitcoin Core
consensus or policy reproduction. The selected-limb profile keeps its
`research-unlimited` label; the short profile is `unclassified`.

The separate `test_maximum_alstack_element_calculation` is a resource-boundary
probe for limb widths 4 and 29 and message lengths 0, 64, 128, ..., 1,024 bytes.
It supplies canonical zero-message limbs and padding as witness data, moves
padding to the altstack, then computes the hash. All data coexist at entry;
there are exactly zero auxiliary hint items in every configuration. It leaves
the padding and 64 digest nibbles observable, and checks the digest against
host BLAKE3. It intentionally has no complete-leaf terminal predicate or
cleanup: `error = None` denotes normal fragment completion, while `success`
is false because the output stack contains 64 items.

For `n` nonempty 64-byte blocks, the message has `n*L` items, where `L = 128`
for 4-bit limbs and `L = 18` for 29-bit limbs. Predicted padding capacity is
`p = 409 - (n-1)*L`. Whenever `p >= 0`, the test executes both `p` and `p+1`
padding items: complete entry counts are `n*L+p` and `n*L+p+1`, and serialized
data-witness sizes are `3+n*L+2*p` and two bytes more, respectively. For the
empty message, capacities 936/937 use 936/937 entry items and 1,875/1,877
witness bytes. These witness sizes exclude the script and control block.
For negative capacity (4-bit limbs, 5 through 16 blocks), zero padding is
tested, with `128*n` entry items and `3+128*n` witness bytes.

Every supported capacity must peak at exactly 1,000 combined main/alt items;
one more padding item must fail with `StackSize`. Unsupported message shapes
must also fail with `StackSize`, including oversized entry witnesses. The
test prints each final script size, data/hint count, witness size and combined
peak with `--nocapture`; nonempty scripts exceed the cutoff and are explicitly
unoptimized. This is `locally-reproduced` stack-limited tapscript evidence,
deployment `unclassified`, not complete-leaf consensus/policy validation.
The [old test's optimization failure](../../../knowledge/negative-results/compiler-validation-runtime.md#constant-cleanup-erases-the-resource-being-tested)
explains why embedding constants and dropping every result did not measure
this boundary reliably.

The [56 recorded resource probes](../../../tests/data/blake3-resource-boundaries.json)
pass under the pinned compiler and match the compiler candidate's measurements
exactly. The report records per-probe bytes, witness and hint counts, combined
peaks and source hashes; it does not upgrade the separate primitive profiles'
deployment classes.

## Direct u4 witness layout

`blake3_short_compute_script(n)` requires exactly `2*n` numeric items and
rejects extra main-stack state. Each byte is represented by its high nibble and
then low nibble. Within each four-byte BLAKE3 word, bytes are supplied in reverse
order. For lengths below 32 bytes, words remain in semantic order.

For exactly 32 bytes, let `w0..w7` be the consecutive four-byte words. Their
physical push order is `w1,w4,w3,w7,w6,w2,w0,w5`. Within each word, number the
otherwise canonical nibble items `d0..d7`; their physical order is
`d7,d0,d5,d6,d1,d2,d3,d4`. The previous backend chose these permutations to
shorten its stack routing. The current generator accepts any fixed layout;
with the natural order it measured 3 bytes shorter, so the permutation is
kept for compatibility with existing witnesses.
`blake3_short_message_witness` emits minimally encoded witness items, and
`blake3_push_short_message_script` emits the same layout as script constants;
either helper should be preferred over hand encoding.

`OP_DEPTH` first checks the exact item count. Every supplied item is then
checked as a ScriptNum in `[0, 16)` the first time it is fetched, before it is
added to anything or can address lookup memory. This establishes numeric
bounds, not a protocol-level byte serialization rule: without the
minimal-number policy rule, a non-minimal encoding of an in-range nibble is
accepted as that nibble. Callers that commit to raw encodings must enforce
their own canonicality boundary. The message length is fixed when the script is
generated and must be bound by the surrounding protocol when it is selected
dynamically.

The selected-limb profile range-validates every witness limb that overlaps the
declared message. When the final block has at most 32 message bytes, its second
256-bit group is wholly padding: that profile drops the group without
validation and synthesizes zeros, so callers must not treat ignored values as
bound data. The direct profile has no ignored padding input.

## Security and compatibility

The 256-bit BLAKE3 output has generic 128-bit collision resistance and 256-bit
preimage/second-preimage resistance. Only the single-chunk-tree range supported
by this implementation is in scope.

Generated scripts are far beyond ordinary standard output templates. Treat
them as tapscript research fragments. A complete caller must compare the digest
and leave a clean truthy result; P2SH, P2WSH, and bare deployment are generally
unsuitable.
