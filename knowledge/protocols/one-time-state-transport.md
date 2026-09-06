# One-time authenticated state transport

BitVM-style protocols may authenticate intermediate state with one-time hash
constructions so a later script can recover and check individual digits.

## Dependency map

```text
State value
├── digitization (bit, nibble, byte, limb, or field coefficient)
├── message/domain encoding
├── one-time key generation and public commitment
├── witness signature/opening
├── Script verification and recovered value layout
└── enforced key lifecycle across transaction graph
```

Lamport 2-bit, HORS-like subsets, and base-16 Winternitz solve different parts
of this problem. The HORS module does not derive indices from a message. The
Lamport helper authenticates only two bits. Winternitz provides typed message
APIs but requires strict one-time key management and can make state transport
witness-heavy.

The following Fast costs use the default HASH160 chain and `FullWidth`
initial secrets.

The Fast Winternitz path makes the transport boundary more explicit. Numeric
profiles use 134 digit/chain items; the 4,325-byte bitwise recovery profile uses
333 items, peaks at 334, and returns the same 64 high/low nibbles. Its canonical
bits and the exact verifier depend on tapscript `MINIMALIF`. The 4,206-byte
terminal profile peaks at 333 items and clears the message when transport is
unnecessary. The
consuming Rust key prevents ordinary same-process reuse only. Transaction-graph
state, crash rollback, restored seeds, distributed signers, and raw ScriptNum
canonicality remain protocol obligations. Size profiles relax raw chain-item
length; protocols requiring exactly 20-byte signature nodes should use the
4,934-byte strict-chain profile. Fast and legacy witnesses are not
wire-compatible.

The residual-digit exact verifier and staged checksum reduce strict exact
recovery to 5,267 bytes and exact terminal verification to 5,205 bytes without
changing Fast witness encoding. These improvements do not supply durable
reuse prevention. There are zero auxiliary hint items; all 134 numeric or 333 bitwise data items and
any other protocol state contribute to the entry and combined stack limits.
Full tables for narrow checksum digits now reduce HASH160 clamped/strict
numeric fragments by six bytes; strict lookup also removes a redundant
lower-bound check and saves 73 bytes. Its upper bound and `OP_PICK` rejection
of negative indices prevent selectors from reading preceding protocol state.

For total on-chain bytes, the explicit clamped lookup profile uses the same
134-item numeric witness and reduces the zero-message recovery/terminal sums
to 5,941/5,879 bytes. It authenticates the upper-clamped digit, including the
checksum, so protocols that require rejection of above-range raw digit
encodings must choose a strict profile. Lowest locking-script size alone does
not determine transport cost: serialized signature data must also be counted.

Protocol evaluation must count public commitment placement, witness
serialization, recovered-state cleanup, and the transaction graph that prevents
key reuse.

Hash selection is also part of the protocol: `FastWinternitz<N, Sha256>` uses
32-byte chain nodes instead of HASH160's 20-byte nodes, and separate key
derivation domains. Persist the hash choice and construct matching public
commitments before signing. The 32-byte zero-message clamped terminal total
increases from 5,879 to 7,227 bytes; entry item count (134), auxiliary hint
count (0), and combined peak (143) stay the same. SHA-256 pair fusion changes
the profile ranking: bitwise recovery totals 7,152 bytes versus clamped's
7,289, at the cost of 333 entry items and peak 334. These are fragment-plus-data
measurements under `research-unlimited` tapscript execution, not complete
state-transport transaction weights. A wider hash does not replace a concrete
multi-target security argument or durable one-time-key management.


The independent start-mode choice is `FastWinternitz<N, H, Preimage16>`.
Persist it together with the hash and message length: it has separate key
namespace derivation, so existing commitments cannot be reused by changing a
runtime witness encoding. Only zero-valued digits reveal 16-byte initial
secrets; subsequent nodes retain the native width and public commitments
retain the selected commitment width.
The explicit `FullWidth` mode retains existing keys and witness encodings.

With 66 zero digits, the same Wots32 fixture reduces the measured clamped
terminal sum to 5,615 bytes for HASH160 or 6,171 for SHA-256. These results are
`locally-reproduced` and `research-unlimited` under the tapscript metric helper
with the stack limit disabled; they are not complete transaction weights or
Core consensus/policy validation. Witness items and auxiliary hints stay at 134
and zero, with the same measured 143-item clamped peak; bitwise still uses 333 entry
data items and zero hints. All items coexist at entry. Strict raw-width
profiles pay extra script bytes to select 16 or the native width from the
authenticated digit. A protocol should evaluate its actual message/checksum
distribution and the full transport transaction before choosing a profile.

`FastWinternitz<N, Sha256Hash160>` provides a third hash choice: 32-byte
SHA-256 nodes and 20-byte HASH160 endpoint commitments, with a fresh derivation
domain. The 32-byte-message bitwise terminal fragment shrinks to 3,812 bytes,
394 below HASH160 bitwise. It still needs 333 data items and peaks at 333.
For the same zero-message fixture, its Preimage16 witness is 1,686 bytes and
the fragment-plus-data total is 5,498; FullWidth totals 6,554. This changes
the commitment format, so persist the choice and regenerate keys when
switching from either existing hash choice.

The `checksig_verify_strided_and_clear` terminal profile and
`to_strided_witness()` serializer use three items per chain: a quotient, a
node, and a canonical low bit. The quotient is upper-clamped before both
table selection and checksum accumulation. For `Sha256Hash160`, the fragment
is 3,961 bytes and consumes 201 data items with a 209-item combined peak.
Its Preimage16 zero-message witness is 1,357 bytes, giving a 5,318-byte sum;
FullWidth uses 2,413 witness bytes and totals 6,374. Bitwise remains the
smaller locking fragment; strided has the smaller zero-message total among
these measured terminal profiles. Both consume the message, so a protocol
that needs recovered state must select a recovery profile instead.

The hybrid and strided measurements are `locally-reproduced` and
`research-unlimited` under the stack-limit-disabled tapscript metric helper.
Each invocation needs zero auxiliary hints. All 333 or 201 data items coexist
at entry, and peaks include checksum state and temporary tables; unrelated
live state must fit under the same 1,000-item limit. A caller-supplied final
predicate and transaction framing are excluded. Separate strict-stack tests
do not constitute Core consensus or policy validation.

A 16-byte initial secret caps generic single-target classical start search at
128 bits. The selected commitments retain their hash-output collision bounds,
which are a different security property; they do not restore the larger
FullWidth secret-search space. In particular, the hybrid's 20-byte HASH160
commitments retain an approximately 80-bit generic collision bound despite
32-byte internal nodes. Its size profiles also accept arbitrary raw node
widths at the maximum digit, because a final commitment hash always executes;
strict exact and lookup keep the raw-width checks. Concrete multi-target/chain analysis and
durable one-time-key state remain protocol obligations under
[OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).
