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
5,007-byte strict-chain profile. Fast and legacy witnesses are not
wire-compatible.

The residual-digit exact verifier and staged checksum reduce strict exact
recovery to 5,267 bytes and exact terminal verification to 5,205 bytes without
changing Fast witness encoding. These improvements do not supply durable
reuse prevention. There are zero auxiliary hint items; all 134 numeric or 333 bitwise data items and
any other protocol state contribute to the entry and combined stack limits.

For total on-chain bytes, the explicit clamped lookup profile uses the same
134-item numeric witness and reduces the zero-message recovery/terminal sums
to 5,947/5,885 bytes. It authenticates the upper-clamped digit, including the
checksum, so protocols that require rejection of above-range raw digit
encodings must choose a strict profile. Lowest locking-script size alone does
not determine transport cost: serialized signature data must also be counted.

Protocol evaluation must count public commitment placement, witness
serialization, recovered-state cleanup, and the transaction graph that prevents
key reuse.
