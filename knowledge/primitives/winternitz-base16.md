# Base-16 Winternitz signatures

Implements HASH160 Winternitz chains with standard and compact signatures,
typed message sizes, and list-pick, brute-force, or binary-search verifiers.

- **Position:** current local general-purpose one-time message authentication
  construction and a state-commitment transport mechanism.
- **Evidence:** locally reproduced with committed self-generated regression
  vectors across all typed message lengths. Those vectors do not constitute an
  independent differential implementation.
- **Representative result:** Wots32 list-pick uses 4,908 script bytes and a
  1,477-byte serialized witness. The Fast bitwise profile reduces the like-for-
  like recovery fragment to 4,325 bytes, or 4,206 bytes when the message is
  cleared, with a documented witness-size/stack tradeoff and relaxed raw
  chain-item length relation.
- **Terminal result:** direct reduction of authenticated digits replaces
  recovery followed by dropping, reducing the legacy terminal fragment from
  4,940 to 4,844 bytes while preserving the existing signature format. With
  an appended `OP_TRUE`, the zero-message fixture measures 3,166 static
  non-push fragment opcodes and a 143-item combined stack peak. Its 134 data
  items and zero auxiliary hints coexist at entry. This is
  `locally-reproduced` in tapscript through the metric helper with stack checks
  disabled, hence `research-unlimited`, without Bitcoin Core validation.
- **Tradeoff:** compact witnesses increase verification work; verifier choice
  changes script, witness, and stack costs.
- **Security:** keys are strictly one-time and chain security is bounded by
  HASH160 and multi-target effects.
- **Audit notes:** the default list-pick verifier clamps values above the base
  maximum before recovering them, so it authenticates the clamped digit but
  does not enforce raw numeric canonicality. Legacy key generation also clones
  the secret per chain and allocates/sorts all intermediate hashes solely to
  warn about cycles. The random-key wrapper hex-encodes a 20-byte RNG output
  into a 40-byte secret. These are compatibility behaviors, not properties of
  the new Fast API.

See the [implementation README](../../src/signatures/winternitz/legacy/README.md),
[Fast implementation](winternitz-fast-base16.md),
[signature comparison](../comparisons/signatures.md), and catalog record
`signature/winternitz-base16`.


The legacy API remains fixed to HASH160 and 20-byte chain values. Hash selection
is available in the independent [Fast implementation](winternitz-fast-base16.md)
as `FastWinternitz<N, Hash160>`, `FastWinternitz<N, Sha256>`, or
`FastWinternitz<N, Sha256Hash160>`. The hybrid retains 20-byte HASH160
commitments with 32-byte SHA-256 chain nodes; its bitwise terminal fragment
is 3,812 bytes. Fast also
supports `FastWinternitz<N, H, Preimage16>`: the initial secret is 16 bytes,
while every hash output keeps the native 20- or 32-byte width and commitments
retain their selected width.
Only zero-valued signature digits reveal the shorter item. Fast defaults now use `Preimage16`; explicit `FullWidth` and the legacy API
retain their existing encodings. Changing
hash or start mode requires new keys and witnesses; see the Fast page for the
size savings, strict-width validation overhead, and reduced secret-search
margin.
